---
title: "5G UPF: Smart Session Placement"
subtitle: Multi-Metric CPU Scheduling with Constraint-Based Gating
---
*Alexandre Cassen*, <<acassen@gmail.com>>

---

The [companion article](https://gtp-guard.org/articles/5g-upf-from-flow-steering-to-session-affinity/)
described how range partitioning, flow steering policy, and CPU scheduling groups form an
end-to-end pipeline in GTP-Guard. When a PFCP session is established, a scheduling algorithm
elects a CPU, and that election determines the TEID range, the IP sub-prefix, and the NIC
queue assignment for the entire session lifetime. The previous article introduced connection-
and resource-based algorithms (wlc, sed, lc, ll, lbw, lpps) that each operate on a single
metric.

This article goes further. It introduces trend-based algorithms that look at load trajectory
rather than a point-in-time snapshot, a Weighted Score Composite that blends multiple metrics
into a single normalized score, and a Constraint-Based Scheduler that enforces hard limits
before delegating to any other algorithm. Together they give operators fine-grained control
over session placement quality and SLA differentiation.


## Single-Metric Scheduling could not be enough

Every scheduling algorithm from the previous article operates on one metric dimension.
Connection-based algorithms (lc, wlc, sed, nq) look at `pfcp_sessions`. Load-based
algorithms (ll) look at CPU utilization. Traffic-based algorithms (lbw, lpps) look at
bandwidth or packet rate.

In a real data-plane workload these dimensions are correlated but not interchangeable. A CPU
can sit at low utilization while saturating its NIC queue bandwidth. It can hold many sessions
that are mostly idle. It can show moderate load right now while absorbing a burst that will
saturate it in five seconds.

Single-metric scheduling forces the operator to pick one dimension and hope the others
follow. For a uniform workload with similar session profiles, this is fine. For a
multi-service UPF handling video, VoLTE, IoT, and web browsing simultaneously, it leaves
blind spots.


## Smoothing the Signal

Before combining metrics or detecting trends, each input must be smoothed. Raw instantaneous
values are noisy. The per-CPU metrics polling runs every 200ms, and ethtool stats arrive
every 3 seconds. A single sampling interval can capture a burst that vanishes by the next
tick.

GTP-Guard maintains EWMA (Exponentially Weighted Moving Average) smoothed values alongside
the raw counters for all key metrics:

```c
float   load_ewma;
double  rx_bw_bps_ewma;
double  tx_bw_bps_ewma;
double  total_bw_bps_ewma;
double  rx_pps_ewma;
double  tx_pps_ewma;
```

These are updated at the polling tick using the formula:

```
smoothed = alpha * current + (1 - alpha) * previous_smoothed
```

!!! note "Quickly on EWMA"
    An Exponentially Weighted Moving Average reacts to sustained changes while
    ignoring short-lived spikes, which is exactly what a scheduler needs when load,
    bandwidth, and packet rate all jitter from tick to tick. Each new sample
    contributes a fraction `alpha` of its value, and the remaining `1 - alpha` carries
    the previous smoothed value forward. Expanding the recursion, older samples decay
    geometrically as `(1 - alpha)^n`, so their influence fades but never disappears
    abruptly. A small alpha (for example 0.1) gives long memory and heavy damping,
    while a larger alpha (0.5 or more) tracks the raw signal more closely. Compared
    with a plain moving window, EWMA keeps a constant memory footprint of one float
    per metric and avoids the sharp edge effect that appears when a sample leaves the
    window. For detailed informations on EWMA, see the
    [NIST/SEMATECH e-Handbook section on EWMA control charts](https://www.itl.nist.gov/div898/handbook/pmc/section3/pmc324.htm).

The default alpha is 0.2. With the 3-second ethtool interval for traffic metrics, this
converges after roughly 15 seconds (five ticks). The `show cpu-sched` output displays both
raw and smoothed values so operators can observe the smoothing in real time:

```
CPU Scheduling Group: dp-plane (algorithm: wsc)
  CPU   Weight   Sessions   Load   Load~   BW(Mbps)   BW~(Mbps)       PPS      PPS~
    4      100         42   0.23    0.21      850.2       812.4    125430    121200
    5      100         38   0.31    0.22      790.1       801.3    118200    119500
    6      100         55   0.18    0.20     1200.5      1050.8    189400    175300
    7      100         29   0.45    0.38      420.0       455.2     62100     68900
```

The `~` columns show the EWMA-smoothed values. CPU 5 has a raw load of 0.31 (a transient
spike) but its smoothed load is 0.22, much closer to its sustained state. CPU 6 shows a raw
bandwidth of 1200 Mbps but the smoothed value is 1050 Mbps, filtering out a recent burst.


## Trend-Based Algorithms

### gauge_history: capturing trajectory

Every metric except session count maintains a ring buffer of historical samples in
`gtp_percpu_metrics`. The load history is sampled every 200ms and stores up to 256 samples,
covering roughly 51 seconds. The bandwidth and packet rate histories are sampled every 3
seconds and store up to 256 samples, covering roughly 12 minutes.

This history data enables two trend-based scheduling algorithms.

### ls (Least-Slope)

The ls algorithm computes a linear slope over a configurable window of recent load samples.
The CPU with the lowest slope (most negative or least positive) wins. A CPU trending down is
preferred over one trending up, even if its current absolute load is higher.

```
slope = (newest_sample - oldest_sample) / window_samples
```

The window parameter controls reactivity:

| Window | Time coverage | Behavior |
|--------|---------------|----------|
| 5-10 samples | 1-2 seconds | Reacts quickly to short bursts |
| 25 samples | 5 seconds | Balanced (default) |
| 100-256 samples | 20-51 seconds | Captures longer-term trends, ignores transients |

Configuration:

```
cpu-sched-group dp-adaptive
 cpumask 0-7
 algorithm ls
 window 50
!
```

With a window of 50 (10 seconds), ls ignores sub-second jitter and catches sustained ramps.
Consider two CPUs: CPU 4 is at 45% load but trending upward (slope +0.03), while CPU 5 is at
55% load but trending downward (slope -0.02). A point-in-time algorithm picks CPU 4 because
it has lower load. The ls algorithm picks CPU 5 because it is cooling down while CPU 4 is
heating up.

The `show cpu-sched` output keeps the same layout as every other algorithm. The slope is
computed internally from the load history ring buffer and drives the election, but it is
not printed as a dedicated column. Operators read the trend indirectly by comparing `Load`
(raw) with `Load~` (EWMA-smoothed):

```
CPU Scheduling Group: dp-adaptive (algorithm: ls)
  CPU   Weight   Sessions   Load   Load~   BW(Mbps)   BW~(Mbps)       PPS      PPS~
    4      100         42   0.45    0.42      850.2       835.1    125430    123800
    5      100         38   0.55    0.57      790.1       795.6    118200    119100
```

CPU 4 shows a raw load (0.45) higher than its smoothed value (0.42), so the sustained trend
is upward. CPU 5 shows the opposite pattern with 0.55 raw versus 0.57 smoothed, so the
sustained state is cooling. The ls algorithm picks CPU 5 even though its absolute load is
higher at the sampling instant.

### ewma (EWMA Least-Load)

The ewma algorithm uses the pre-computed `load_ewma` to elect the CPU with the lowest
smoothed load. It is structurally identical to ll (least-load) but operates on the smoothed
value instead of the raw one.

The smoothing factor alpha is configurable per scheduling group:

```
cpu-sched-group dp-smooth
 cpumask 0-7
 algorithm ewma
 ewma-alpha 0.1
!
```

A lower alpha (0.05-0.1) gives heavier smoothing and longer memory, dampening most spikes.
A higher alpha (0.5-0.8) follows load closely with mild smoothing. The default of 0.2
provides a good balance for typical mobile data-plane workloads.


## Weighted Score Composite (WSC)

WSC addresses the core limitation of single-metric algorithms by computing a composite score
from four EWMA-smoothed metrics, weighted by the operator.

### The four metrics

| Index | Metric | Source |
|-------|--------|--------|
| load | CPU utilization | `load_ewma` |
| sessions | Session count | `pfcp_sessions` |
| bw | Total bandwidth | `total_bw_bps_ewma` |
| pps | Packet rate | `rx_pps_ewma + tx_pps_ewma` |

### Scoring

WSC runs two passes over the cpumask.

The first pass collects metric values for each CPU and tracks the group-wide maximum for each
metric. These maxima serve as normalization denominators.

The second pass computes a normalized composite score for each CPU:

```
score(cpu) = sum over k: weight[k] * (value[k] / max[k])
```

Dividing by the group-wide max normalizes each metric to [0.0, 1.0], making them comparable
regardless of unit or scale. The CPU with the lowest score wins.

Normalization is relative to the current group state, not to any absolute capacity. WSC
adapts automatically as load increases. It does not need to know the NIC line rate or CPU
frequency.

### Operator-tunable weights

The `metric-weight` command sets the importance of each metric. Weights do not need to sum to
1.0. Setting `load 2.0` and `bw 1.0` makes load twice as important as bandwidth.

**Bandwidth-dominated workload.** The operator knows the bottleneck is NIC throughput (video
streaming, large file transfers):

```
cpu-sched-group upf-bw-heavy
 cpumask 0-7
 algorithm wsc
 metric-weight load 1.0
 metric-weight bw 3.0
 metric-weight pps 1.0
 metric-weight sessions 0.0
!
```

Bandwidth gets 3x weight. Sessions are disabled (weight 0.0) because each session carries
high traffic volume, making session count a poor proxy for actual load.

**Session-heavy IoT deployment.** Many low-throughput bearers where the bottleneck is
state-table pressure:

```
cpu-sched-group iot-pool
 cpumask 0-7
 algorithm wsc
 metric-weight sessions 2.0
 metric-weight load 1.0
 metric-weight bw 0.5
 metric-weight pps 0.5
!
```

Sessions get 2x weight because each device generates negligible traffic but consumes memory
and hash-table entries.

**Balanced default.** When no single bottleneck dominates:

```
cpu-sched-group upf-balanced
 cpumask 0-7
 algorithm wsc
!
```

All four metric weights default to 1.0, giving equal importance to every dimension.


## Constraint-Based Scheduling (CBS)

WSC blends metrics into a single score and always picks the least-loaded CPU. But it cannot
express hard limits. If every CPU in the group exceeds 85% load, WSC still picks the
least-bad one without signaling that a critical threshold has been crossed. It also cannot
express trend-based policies because the composite score flattens all dimensions into a
single number.

CBS solves this by separating the decision into two phases.

### Phase 1: constraint filter

The algorithm evaluates every CPU against operator-defined constraints. A constraint is
defined by three parameters: a metric (load, sessions, bw, pps), a mode (instant, ewma,
slope), and a threshold. If a CPU's metric value exceeds the threshold, the CPU is excluded
from the candidate set.

The three modes leverage different data sources:

| Mode | Source | Use case |
|------|--------|----------|
| instant | Raw current value | Hard real-time limits |
| ewma | EWMA-smoothed value | Filtering transient spikes |
| slope | Trend from gauge_history | Detecting ramp-ups before saturation |

The slope mode is the most interesting. Instead of asking "is this CPU busy?", it asks "is
this CPU becoming busy?" A CPU at 55% load with a slope of +0.05 is a worse placement target
than one at 65% with a flat or declining trend. The slope is computed from the gauge_history
ring buffer over a configurable window.

### Phase 2: fallback delegation

After filtering, the survivor set becomes the candidate cpumask. Any existing scheduling
algorithm can serve as the fallback (wlc, wsc, ll, ewma, or any other). CBS temporarily
restricts the group's cpumask to the survivors, calls the fallback algorithm, and restores
the original cpumask. The fallback sees a reduced CPU set and operates normally on it.

If no CPU passes all constraints (complete overload), CBS falls back to the full cpumask.
Refusing placement entirely would cause session establishment failures, which is worse than
placing on a busy CPU. The operator can detect this condition through debug logging.

### Configuration

```
constraint <load|sessions|bw|pps> <instant|ewma|slope> <threshold>
fallback-algorithm <algo>
```

The parser enforces mode compatibility: sessions only supports instant mode because session
count changes discretely and has no EWMA or history ring.

### Scenario 1: Capacity protection

The simplest CBS use case. Exclude overloaded CPUs, let LC distribute sessions among the
healthy ones.

```
cpu-sched-group protected
 cpumask 0-7
 algorithm cbs
 constraint load ewma 0.8
 fallback-algorithm lc
!
```

The EWMA constraint at 0.8 leaves 20% headroom for burst absorption. EWMA mode avoids false
exclusions on transient spikes so that a CPU that briefly touches 95% on a burst but sustains
60% stays eligible.

At election time, suppose the 8 CPUs have smoothed loads of 0.45, 0.62, 0.71, 0.83, 0.55,
0.91, 0.38, 0.77. The constraint excludes CPUs 3 (0.83) and 5 (0.91). LC picks from the
remaining 6 CPUs based on session count.

### Scenario 2: Trend-aware gating

Detect CPUs absorbing a traffic surge before their absolute load crosses a threshold.

```
cpu-sched-group trend-aware
 cpumask 0-7
 algorithm cbs
 constraint load slope 0.03
 constraint bw ewma 5000000000
 fallback-algorithm wsc
 metric-weight load 2.0
 metric-weight bw 1.0
 metric-weight pps 0.5
 metric-weight sessions 0.0
 window 50
!
```

The load slope constraint uses a window of 50 samples (10 seconds at 200ms per load sample).
A threshold of 0.03 means "exclude any CPU whose load is increasing by more than 3% per
sample over the window." This catches CPUs actively absorbing a burst, even if their
absolute load is still moderate. A CPU sitting at 50% load but rising steeply is a worse
placement target than one at 65% with a flat trend.

The bandwidth EWMA constraint at 5 Gbps protects against NIC queue saturation. The WSC
fallback, with load weighted 2x and sessions disabled, then picks the best candidate among
the survivors.

### Scenario 3: Mixed SLA tiers

Isolate premium subscribers from best-effort traffic at the CPU level.

```
cpu-sched-group premium
 cpumask 0-7
 algorithm cbs
 constraint load ewma 0.7
 constraint bw ewma 3000000000
 fallback-algorithm wsc
 metric-weight load 2.0
 metric-weight sessions 1.0
 metric-weight bw 1.0
 metric-weight pps 0.5
!

cpu-sched-group best-effort
 cpumask 8-15
 algorithm wsc
!
```

The premium group runs CBS with two constraints. The load EWMA threshold is tighter (0.7
versus 0.8 in scenario 1) because premium traffic needs more headroom for latency-sensitive
processing. The bandwidth EWMA constraint at 3 Gbps adds protection against NIC queue
saturation before the load metric catches up.

The best-effort group runs plain WSC on a separate CPU set (8-15). No constraints, no hard
limits. Since best-effort traffic tolerates higher latency, the WSC scoring alone provides
adequate balancing.

Binding these to APNs creates full SLA differentiation:

```
access-point-name enterprise
 cpu-sched premium
!
access-point-name consumer
 cpu-sched best-effort
!
```

Enterprise subscribers land on CPUs 0-7 with tight capacity protection. Consumer subscribers
land on CPUs 8-15 with best-effort balancing. The two traffic classes are fully isolated at
the CPU level.

### Scenario 4: IoT session gating

For NB-IoT or LTE-M deployments where the dominant bottleneck is session count rather than
throughput.

```
cpu-sched-group iot
 cpumask 0-7
 algorithm cbs
 constraint sessions instant 50000
 fallback-algorithm ewma
 ewma-alpha 0.15
!
```

IoT devices typically establish a PFCP session, send a few hundred bytes of telemetry, then
go idle for hours. Each session consumes memory and state-table entries but generates
negligible traffic. The constraint at 50000 sessions in instant mode prevents any single CPU
from accumulating enough state to cause hash collisions or memory pressure. On 8 CPUs, this
allows up to 400000 total sessions.

The EWMA fallback with a low alpha (0.15) gives heavier smoothing. This matters for IoT
workloads because the traffic pattern is bursty at the device level (a device wakes up,
transmits, sleeps) but smooth in aggregate when thousands of devices are staggered.

### Scenario 5: CDN cache miss storm

Detect bandwidth ramp-ups caused by cache invalidation events at a mobile CDN edge.

```
cpu-sched-group cdn-edge
 cpumask 0-15
 algorithm cbs
 constraint bw slope 200000000
 constraint bw ewma 6000000000
 constraint load ewma 0.85
 fallback-algorithm wsc
 metric-weight bw 3.0
 metric-weight load 1.0
 metric-weight pps 0.5
 metric-weight sessions 0.0
 window 10
!
```

The bandwidth slope constraint is the core of this configuration. With a window of 10
ethtool samples (30 seconds), a threshold of 200 Mbps per sample means "exclude any CPU
whose bandwidth is increasing by more than 200 Mbps every 3 seconds." A cache miss storm
starts gradually. The first few seconds show a gentle bandwidth rise as initial requests
arrive. EWMA catches it only after the smoothed value crosses 6 Gbps, by which time the CPU
is already congested. The slope constraint catches the trend 15-20 seconds earlier, when
bandwidth is still at 3-4 Gbps but climbing at 200 Mbps per tick.

### Window tuning

The `window` parameter controls the slope observation horizon. Its effect differs between
metrics because they sample at different rates:

| Window | Load coverage | BW/PPS coverage |
|--------|--------------|-----------------|
| 5 | 1 second | 15 seconds |
| 10 | 2 seconds | 30 seconds |
| 25 | 5 seconds (default) | 75 seconds |
| 50 | 10 seconds | 2.5 minutes |
| 100 | 20 seconds | 5 minutes |

For groups using slope constraints on both load and traffic metrics, the window is a
compromise. A window of 15 covers 3 seconds of load history (short enough to catch spikes)
and 45 seconds of traffic history (long enough to detect ramps). If the deployment needs
very different windows for load and traffic, splitting into two groups (each with its own
window) is a better approach.


## Putting It All Together

This section combines all the features into a complete multi-tier UPF deployment. The server
handles three traffic classes on dedicated CPU pools, each with a scheduling policy tuned to
its workload.

```
! --- Range partitions ---
range-partition teid-main
 type teid ipv4
 split 0x00000000/0 count 16
!
range-partition ipv4-enterprise
 type ipv4
 split 10.0.0.0/12 count 8
!
range-partition ipv4-consumer
 type ipv4
 split 10.16.0.0/12 count 8
!
range-partition ipv6-main
 type ipv6
 split 2001:db8::/46 count 16
!

! --- Flow steering policies ---
flow-steering-policy fs-upstream
 queue-id 0-15
 queue-id bind range-partition teid-main
!
flow-steering-policy fs-downstream-enterprise
 queue-id 0-7
 queue-id bind range-partition ipv4-enterprise
!
flow-steering-policy fs-downstream-consumer
 queue-id 8-15
 queue-id bind range-partition ipv4-consumer
!

! --- Scheduling groups ---
cpu-sched-group premium
 cpumask 0-7
 algorithm cbs
 constraint load ewma 0.7
 constraint bw ewma 4000000000
 fallback-algorithm wsc
 metric-weight load 2.0
 metric-weight sessions 1.0
 metric-weight bw 1.5
 metric-weight pps 0.5
 window 25
 cpumask bind range-partition teid-main
 cpumask bind range-partition ipv4-enterprise
 cpumask bind range-partition ipv6-main
!

cpu-sched-group standard
 cpumask 8-15
 algorithm wsc
 metric-weight load 1.0
 metric-weight bw 1.0
 metric-weight pps 1.0
 metric-weight sessions 1.0
 cpumask bind range-partition teid-main
 cpumask bind range-partition ipv4-consumer
 cpumask bind range-partition ipv6-main
!

interface p0
 flow-steering-policy fs-upstream
 flow-steering-policy fs-downstream-enterprise
 flow-steering-policy fs-downstream-consumer
!

! --- PFCP router and APNs ---
access-point-name enterprise
 cpu-sched premium
 range-partition ipv4-enterprise
!

access-point-name consumer
 ! inherits from pfcp-router
!

pfcp-router main
 cpu-sched standard
 range-partition teid-main
 range-partition ipv4-consumer
 range-partition ipv6-main
!
```

The TEID partition splits the full 32-bit space into 16 parts covering all 16 data-path
CPUs. Both scheduling groups bind this same partition, but each group only uses its own slice:
the premium group maps cpumask 0-7 to partitions 0-7, while the standard group maps cpumask
8-15 to partitions 8-15. There is no overlap.

The IPv4 pools are separate. Enterprise subscribers get addresses from `10.0.0.0/12`, consumer
subscribers from `10.16.0.0/12`. Each pool is split into 8 partitions matching its CPU group.

The premium group runs CBS with two constraints: EWMA load at 0.7 and EWMA bandwidth at
4 Gbps. These thresholds leave generous headroom for enterprise sessions. The WSC fallback
weights load 2x because latency correlates with CPU utilization, sessions 1x because
enterprise sessions are long-lived, and bandwidth 1.5x to track throughput. Any CPU that
exceeds 70% smoothed load or is pushing more than 4 Gbps gets filtered out. The survivors
enter WSC for final ranking.

The standard group runs plain WSC with equal weights. No hard limits, no filtering. Consumer
traffic tolerates higher latency and occasional congestion, so the multi-metric scoring alone
provides adequate balancing.

Enterprise subscribers land on CPUs 0-7, consumer subscribers on CPUs 8-15. Each class is
isolated at every level: different CPUs, different TEID sub-ranges, different IP pools,
different NIC queues, different scheduling policies. A consumer traffic surge cannot affect
enterprise session quality because the two never share a processing core.


## Debug and Observability

Each scheduling group has a `debug` toggle that can be enabled at runtime with
`debug cpu-sched <group>`. When the flag is on, every election decision is logged with the
elected CPU, its current session count, and its configured weight:

```
cpu-sched: group=premium algo=cbs elected=cpu2 (sessions=24 weight=100)
```

The trace confirms which group made the decision, which algorithm ran, and which CPU won.
For a CBS group, this line is the outcome of the constraint-filter plus fallback pipeline,
so CPU 2 is guaranteed to have passed every configured constraint. The companion
`show cpu-sched <group>` output gives the full per-CPU metric table used to reach that
decision, so operators can cross-check the election against live load, smoothed values, and
session counts.

Together with `show range-partition` and `show interface <name> flow-steering`, these
commands provide complete visibility into every layer of the session placement pipeline.
