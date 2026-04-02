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

**April 2026** - [Per-Core CPU Load Measurement](articles/cpu_load_measurement.md)
: Standard `/proc` interfaces miss inline NAPI softirq work that XDP runs outside the scheduler. This article explains why `PERF_COUNT_HW_REF_CPU_CYCLES` was selected as the load metric, and describes the two measurement modes (TSC and calibrated) exposed by `lib/cpu.c`.

**March 2026** - [5G UPF: Pump Up the Volume!](articles/5g-upf-pump-up-the-volume.md)
: Hardware selection, system tuning, and TEID-based flow steering with range partitioning to route each UE session to a dedicated core. The design targets ~800 Gbps on a single 1RU commodity server using ConnectX-7 NICs and XDP.
