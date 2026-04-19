---
hide:
  - toc
---
# Articles

These articles are raw notes on design decisions that surface while hacking on gtp-guard. Each one digs into a specific problem hit during design, implementation, or testing, and documents why a particular approach was picked over the alternatives. They reflect where the project is heading technically.

**[5G UPF: Smart Session Placement](5g-upf-smart-session-placement.md)** · *2026-04-19 · 5G*  
Goes beyond single-metric scheduling with trend-based algorithms that track load trajectory, a Weighted Score Composite that blends sessions, load, bandwidth, and PPS into one score, and a Constraint-Based Scheduler that enforces hard limits before delegating to any other algorithm.

**[5G UPF: From Flow Steering to Session Affinity](5g-upf-from-flow-steering-to-session-affinity.md)** · *2026-04-17 · 5G*  
Integrates range partitioning into the PFCP control plane so every session establishment becomes a scheduling decision the NIC enforces at line rate. Introduces `range-partition`, `flow-steering-policy`, and `cpu-sched-group` objects, and shows how they align TEID, IP pool, and CPU for the entire session lifetime.

**[Per-Core CPU Load Measurement](cpu_load_measurement.md)** · *2026-04-02 · System*  
Explains why `/proc/stat`, `/proc/schedstat`, and task-clock counters miss inline XDP/NAPI softirq work, and why GTP-Guard drives scheduling from `PERF_COUNT_HW_REF_CPU_CYCLES` to get accurate per-core load even when packets are processed outside the scheduler's view.

**[5G UPF: Pump Up the Volume!](5g-upf-pump-up-the-volume.md)** · *2026-03-27 · 5G*  
Lays the hardware foundation for a 800 Gbps UPF on a 1RU commodity server: NIC rx_queue pinning, IRQ affinity, range partitioning math on TEID and IP sub-prefixes, and end-to-end flow steering validation with TC flower rules.
