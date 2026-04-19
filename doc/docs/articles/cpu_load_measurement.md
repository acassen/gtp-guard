---
title: "Per-Core CPU Load Measurement"
---

*Alexandre Cassen*, <<acassen@gmail.com>> - April 2026

---

## Overview

gtp-guard needs accurate per-core CPU load to drive scheduling decisions, for instance to pick the right CPU for a new flow without overloading a core already busy with forwarding. The data-plane runs XDP and AF_XDP, which process packets in softirq context through NAPI polling, and this work is partly outside the view of the standard scheduler. This document covers the design choices behind `lib/cpu.c` and explains why the implementation uses a hardware performance counter rather than the more common `/proc` interfaces.

## Why Classic Approaches Fall Short

The following table summarises how each candidate method handles the two softirq execution paths that XDP uses.

| Method | Inline softirq (NAPI) | Granularity | Notes |
|---|---|---|---|
| `/proc/stat` | Captured (dedicated softirq column) | jiffy (~1–4 ms) | Coarse; quantization noise degrades tight scheduling |
| `/proc/schedstat` | **Missed** — scheduler doesn't see inline softirq | nanosecond | Not suitable for XDP workloads |
| `PERF_COUNT_SW_TASK_CLOCK` | **Missed** — not a task context | nanosecond | Only counts task time |
| `PERF_COUNT_HW_REF_CPU_CYCLES` | **Captured** — hardware counts all unhalted cycles | nanosecond | Correct for XDP |

XDP processing runs in two modes. In the first, packets are handled directly in the driver's interrupt handler as inline NAPI, which runs outside any task context and is therefore invisible to the scheduler. In the second, when the softirq budget is exceeded, the kernel hands off to `ksoftirqd/N`, which is a regular kernel thread and does appear to the scheduler. Any task-based or scheduler-based metric misses the inline case entirely, whereas the hardware reference cycle counter does not.

### The `/proc/stat` granularity problem

The kernel accounts CPU time in jiffies. With HZ set to 250 or 1000 on most distributions, each tick is 4 ms or 1 ms respectively. A core that runs XDP for 300 µs and then goes idle gets charged either zero or one jiffy depending on where that window falls within the tick boundary, which is pure quantization noise. For a scheduler making placement decisions at tens-of-milliseconds intervals, this noise matters: a lightly loaded core can appear idle, and a briefly active core can appear fully busy. The `softirq` column does capture NAPI work, but the granularity problem alone disqualifies `/proc/stat` for tight per-core scheduling.

### The `/proc/schedstat` blind spot

`/proc/schedstat` looks more suitable at first: it is nanosecond-resolution and scheduler-maintained, which avoids the jiffy quantization problem entirely. But it has a fundamental blind spot with inline softirq that makes it unsuitable for XDP workloads.

When a NIC interrupt arrives and the CPU wakes from `HLT`, NAPI polling runs directly in the interrupt handler context. At that moment the idle task is still `current` because no context switch has occurred. The scheduler's `run_ns` counter only increments while a task is on-CPU, so inline NAPI, which preempts whatever was running without going through the scheduler, is completely invisible to `/proc/schedstat`. At high packet rates, a large fraction of the XDP forwarding budget runs in this preempted-idle context, so `/proc/schedstat` reports a heavily loaded forwarding core as nearly idle. `ksoftirqd/N` is a kernel thread and does appear in schedstat, but it only runs when the inline softirq budget is exceeded, making it the overflow path rather than the common fast path.

## Hardware Reference Cycle Counter

The `PERF_COUNT_HW_REF_CPU_CYCLES` counter increments whenever the CPU core is not halted, regardless of execution context. It counts across user tasks, kernel threads, `ksoftirqd`, hardirq handlers, and inline NAPI/softirq alike. It stops only during `HLT`/`MWAIT`, which is true idle time. `perf_event_open(2)` is called with `pid=-1` to select system-wide mode and `cpu=N` to pin the counter to a specific core, so every execution context on that core is captured:

```c
struct perf_event_attr attr = {
    .type        = PERF_TYPE_HARDWARE,
    .config      = PERF_COUNT_HW_REF_CPU_CYCLES,
    .exclude_idle = 0,       /* count halted→unhalted transitions too */
    .read_format = PERF_FORMAT_TOTAL_TIME_ENABLED,
};
fd[n] = perf_event_open(&attr, -1, n, -1, 0);
```

The resulting value answers a precise question: what fraction of wall time was this core not halted? It carries no knowledge of which process or context drove the activity, which is exactly the right input for a placement algorithm deciding whether a core has spare capacity.

## Two Measurement Modes

The library exposes two initialisation functions that differ only in how they compute the denominator of the load ratio. Both use the same hardware counter and the same `cpu_load_update()` function. The mode is selected once at startup and encoded in the `base_freq_hz` field of the context structure.

### Calibrated mode

In calibrated mode, `cpu_load_init()` sets `PERF_FORMAT_TOTAL_TIME_ENABLED` in the perf read format. Each `read()` on the perf file descriptor then returns both the accumulated reference cycle count and `time_enabled`, the number of nanoseconds the counter was active as tracked by the kernel using each CPU's own local timekeeping. On multi-socket NUMA systems this is inherently per-socket, with no cross-socket TSC skew. The load formula is:

```
load[n] = Δref_cycles / (Δtime_enabled_ns × base_freq_hz / 1e9)
```

`base_freq_hz` is calibrated once at startup by measuring TSC ticks against `CLOCK_MONOTONIC` over a 20 ms `nanosleep`. This cost is paid only inside `cpu_load_init()` and never touches the update hot path.

### TSC mode

In TSC mode, `cpu_load_init_tsc()` uses the `rdtsc` instruction as the denominator. On modern x86, `PERF_COUNT_HW_REF_CPU_CYCLES` and the TSC share the same crystal oscillator and run at the same base frequency, so the ratio is dimensionless and needs no frequency conversion:

```
load[n] = Δref_cycles / Δtsc
```

The invariant TSC synchronises across all cores at boot via the QPI/UPI inter-socket link. The residual cross-socket skew stays in the nanosecond range, well under 0.001% error for the tens-of-milliseconds intervals a scheduling algorithm uses. Because no calibration sleep is needed and no per-CPU `time_enabled` field is read, this variant initialises instantly and is the recommended default.

### Mode comparison

| | `cpu_load_init_tsc()` | `cpu_load_init()` |
|---|---|---|
| Init cost | Instant | 20 ms calibration sleep |
| Denominator | Δtsc (global, x86 `rdtsc`) | Δtime_enabled (per-CPU kernel clock) |
| NUMA accuracy | Invariant TSC (negligible skew) | Fully per-CPU, zero cross-socket |
| Formula | Δcycles / Δtsc | Δcycles / (Δtime_ns × base_freq) |
| TSC mode sentinel | `base_freq_hz == 0` | `base_freq_hz != 0` |

`cpu_load_update()` handles both modes transparently through a branch on the `base_freq_hz == 0` sentinel that `calloc` sets naturally when TSC mode is selected.

## Data Structures

The context is split into two structures. `cpu_perf` holds the per-core state: the perf file descriptor, the previous cycle and time samples for delta computation, and the most recently computed load value. `cpu_load` is the top-level context that owns the array of per-core structures and the shared fields for whichever measurement mode was selected.

```c
struct cpu_perf {
    int      fd;            /* perf_event fd, -1 if unavailable */
    uint64_t prev_cycles;   /* last sampled ref cycle count */
    uint64_t prev_time_ns;  /* kernel per-CPU wall ns at last sample */
    float    load;          /* [0.0, 1.0]: fraction of unhalted wall time */
};

struct cpu_load {
    struct cpu_perf *cpus;
    int              nr_cpus;
    uint64_t         base_freq_hz;  /* 0 = TSC mode */
    uint64_t         prev_tsc;      /* TSC mode: TSC at last update */
};
```

Offline CPUs, where `perf_event_open` fails at initialisation, have their `fd` set to -1 and are silently skipped on each update. Callers detect them because `cpu_load_get()` returns `-1.0f` for any CPU with an invalid fd.

## API

```c
int   cpu_load_init(struct cpu_load **ctx);        /* calibrated mode */
int   cpu_load_init_tsc(struct cpu_load **ctx);    /* TSC mode */
void  cpu_load_update(struct cpu_load *ctx);       /* sample all CPUs */
float cpu_load_get(struct cpu_load *ctx, int cpu); /* [0.0,1.0] or -1 */
int   cpu_load_nr(struct cpu_load *ctx);
void  cpu_load_destroy(struct cpu_load *ctx);
```

## Usage

The typical pattern is a periodic timer callback that calls `cpu_load_update()` to sample all cores, then reads per-core values for scheduling decisions. The example below uses gtp-guard's timer framework, where `TIMER_HZ` is 1,000,000 microseconds, so dividing by 5 gives a 200 ms interval.

```c
#include "thread.h"
#include "timer.h"
#include "cpu.h"

#define CPU_LOAD_INTERVAL (TIMER_HZ / 5)   /* 200 ms */

static void
cpu_load_timer(struct thread *t)
{
    struct cpu_load *cl = THREAD_ARG(t);
    int i;

    cpu_load_update(cl);

    for (i = 0; i < cpu_load_nr(cl); i++) {
        float load = cpu_load_get(cl, i);
        if (load < 0.0f)
            continue;   /* offline CPU */
        /* use load in scheduling decisions */
    }

    thread_add_timer(master, cpu_load_timer, cl, CPU_LOAD_INTERVAL);
}

/* At startup, after thread_make_master(): */
struct cpu_load *cl;

if (cpu_load_init_tsc(&cl) < 0)
    /* handle error */

thread_add_timer(master, cpu_load_timer, cl, CPU_LOAD_INTERVAL);
```
