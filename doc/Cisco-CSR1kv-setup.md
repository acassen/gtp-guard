# Using Cisco CSR1000v for PPPoE Network Lab

One of the GTP-Guard use-cases is running it as a mobile Core-Network pGW starting a PPPoE session for each GTP session created. This can be specially useful when considering
network routing delegation in a per GTP session design fashion. Each GTP session created will negociate a PPPoE session with a remote BNG.

In order to create a real world networking lab for our project code debugging, we decided to use [Cisco Cloud Services Router 1000v](https://www.cisco.com/c/en/us/products/routers/cloud-services-router-1000v-series/index.html) for our BNG. CSR1kv runs IOS-XE which is kind of swiss army knife for networking features widely used on production network backbone.

Network topoly :

                        +----------+
                        |  csr1kv  |
                        +--[eno1]--+ 192.168.1.253
                             |
        -------+-------------+-----------------+-------
               |                               |
         +-----+-----+                +--------+------+
         | GTP-Guard |                | sGW emulation |
         +-----------+                +---------------+

This document will detail configuration steps for csr1kv node in order to get it acting as our PPPoE Access-Concentrator. This lab is running on an [Intel NUC](https://www.intel.com/content/www/us/en/products/docs/boards-kits/nuc/overview.html) running latest Ubuntu LTS release. csr1kv image will be run in a KVM.

## CSR1Kv node: packages

We need to use QEMU to host system image, install the following packages:
```
$ apt install qemu qemu-system qemu-kvm
$ apt install libvirt-daemon-system bridge-utils
$ apt install libvirt-clients virtinst
```

## CSR1Kv node: System

There is something wierd and quite alarming using CSR1kv out of the box... High CPU usage... too much CPU usage by default. While bringing up lab, NUC system was heating a lot and pushing noise to its max which was enough alarming to look deeper into it. After reading CSR doc and post around the internet this is solved easily by the following conf :
```
$ cat /etc/modprobe.d/qemu-system-x86.conf
options kvm halt_poll_ns=0
```
Mainly this configuration will restore linux kernel scheduling over KVM polling. If you are reading those lines and are runing a bunch of CSR1kv please use this configuration, it will benefit the planet by reducing heat and power consumption ! Most of CSR1kv deployment are done on remote data-center hosted equipements where it is mostly easy to ignore operations impacts.

## CSR1Kv node: Networking

On *csr1kv* node main default ethernet interface is **eno1**. default Qemu installation will create a **virbr0** as main/default network segment. Mainly all VM created can bridge this interface in order to be part of the same network, unfortunately this default **virbr0** interface is used for NAT and other TUN/TAP operations which make it impossible to join the directly attached L2 segment connected to **eno1**. To solve this issue we need to create a dedicated bridge interface to bridge **eno1**. Use the followinf steps :
```
$ ip link add br-lab type bridge
$ ip link set eno1 master br-lab
$ ip address flush eno1
$ ip address add 192.168.1.253/24 dev br-lab
$ ip link set br-lab up
$ ip route add default via 192.168.1.254

```
Create a virtual network for futur VM refering *br-lab* interface.
```
$ cat br-lab.xml
<network>
	<name>br-lab</name>
	<forward mode="bridge"/>
	<bridge name="br-lab"/>
</network>
```
Create virtual network and make it persistent :
```
$ virsh net-define br-lab.xml
$ virsh net-start br-lab
$ virsh net-autostart br-lab
```
New network available are :
```
$ virsh net-list
 Name      State    Autostart   Persistent
--------------------------------------------
 br-lab    active   yes         yes
 default   active   yes         yes
```

## CSR1Kv node: Configuration

Before configuring IOS-XE, just create and start a new KVM as following :

```
$ virt-install                             \
     --connect=qemu:///system              \
     --name=csr1kv                         \
     --os-variant=rhel4.0                  \
     --arch=x86_64                         \
     --cpu host                            \
     --vcpus=1,sockets=1,cores=1,threads=1 \
     --hvm                                 \
     --ram=4096                            \
     --import                              \
     --disk path=/_path_/csr1000v-universalk9.17.03.08a-serial.qcow2,bus=ide,format=qcow2 \
     --network bridge=br-lab,model=virtio
     --noreboot -v
$ virsh start csr1kv
$ virsh list
 Id   Name     State
------------------------
 1    csr1kv   running

```
Almost perfect, simply add this IOS-XE PPP configuration for a single hardcoded user :
```
hostname bng1
!
vrf definition A
 rd 1000:1
 !
 address-family ipv4
  route-target export 1000:1
  route-target import 1000:1
 exit-address-family
!
aaa new-model
!
aaa authentication login default local
aaa authentication ppp dummy1 local
aaa authorization config-commands
aaa authorization exec default local
aaa authorization network dummy1 local
!
aaa attribute list test@realm
 attribute type addr 10.100.1.1 service ppp protocol ip
 attribute type ip-unnumbered "loopback101" service ppp protocol ip
 attribute type vrf-id "A" service ppp protocol ip
 attribute type primary-dns 8.8.8.8 service ppp protocol ip
 attribute type secondary-dns 1.1.1.1 service ppp protocol ip
!
aaa session-id common
!
subscriber authorization enable
!
username test@realm password 0 test
username test@realm aaa attribute list test@realm
!
bba-group pppoe dummy
 virtual-template 1
!
interface Loopback1
 ip address 10.1.0.254 255.255.255.255
!
interface Loopback101
 vrf forwarding A
 ip address 10.100.1.254 255.255.255.255
!
interface Loopback1101
 vrf forwarding A
 ip address 10.100.111.254 255.255.255.255
!
interface GigabitEthernet1
 no ip address
 negotiation auto
 pppoe enable group dummy
 no mop enabled
 no mop sysid
!
interface Virtual-Template1
 no ip address
 ppp authentication pap dummy1
 ppp authorization dummy1
!
```

Enjoy,
Alexandre