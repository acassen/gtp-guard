---
hide:
  - navigation
---
# Welcome to GTP-Guard

<img width="20%" src="assets/logo.png" align="left"/>

GTP-Guard is a routing daemon written in C that implements the **GTP** protocol (GPRS Tunneling Protocol), the tunneling layer that carries user traffic across mobile core networks. It covers **pGW** functions for 4G and **UPF** functions for 5G, acting as the border element between the mobile core and the external IP network.

Three internal frameworks handle the main forwarding roles. The **Proxy** framework intercepts and tweaks data-plane traffic in flight. The **Routing** framework manages encapsulation, interconnection, and layer-3 forwarding between network segments. The **Firewall** framework filters, rewrites, and redirects packets according to policy.

The data-plane runs through the Linux **XDP** framework via **eBPF** programs, which process packets directly in the driver interrupt handler before they reach the kernel network stack. Configuration and monitoring use a standard **VTY** terminal interface.

GTP-Guard is free software distributed under the **GNU Affero General Public License v3**.

---

## Last Updates

- **2026-04-19** · article · [5G UPF: Smart Session Placement](articles/5g-upf-smart-session-placement.md): multi-metric CPU scheduling with constraint-based gating for UE session placement
- **2026-04-17** · article · [5G UPF: From Flow Steering to Session Affinity](articles/5g-upf-from-flow-steering-to-session-affinity.md): TEID range partitioning, flow steering policy, and CPU scheduling groups
- **2026-04-02** · article · [Per-Core CPU Load Measurement](articles/cpu_load_measurement.md): why `/proc` misses XDP softirq work and how hardware perf counters fix it
- **2026-03-27** · article · [5G UPF: Pump Up the Volume!](articles/5g-upf-pump-up-the-volume.md): NIC flow steering and TEID-based range partitioning targeting 800 Gbps on a single server
