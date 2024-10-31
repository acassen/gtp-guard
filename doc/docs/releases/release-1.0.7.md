
# Release 1.0.7

October 31th, 2024 -
[Release Notes](release-1.0.7) -
[gtp-guard-1.0.7.tar.xz](/software/gtp-guard-1.0.7.tar.xz) -
MD5SUM:={023155c96b90d14757474b61b707a23b}

* pppoe: Add support to 'ignore-ingress-ppp-brd' feature for pppoe-bundle.
 This feature ensure that when interface are part of the same pppoe-bundle
 then PPP frame broadcast are ignored. In some networking design, having
 multiple interface into the same L2 segment can lead to L2 broadcast
 during MAC learning process at switch side. PPP is specialy sensitive
 to broadcast since it can force unappropriate state transition.
 This feature configured for a pppoe-bundle ensure that ingress PPP frame
 on diffrent ifindex as the one used during session init are silently
 ignored.
 This feature is an opt-in setting, since on some others networking
 design ones could want to setup asymetric L2 path for ingress and
 egress.
 This feature is made available via VTY 'ignore-ingress-ppp-brd' in
 pppoe-bundle configuration.

* router: fix F-TEID interface_type
* some cosmetics

