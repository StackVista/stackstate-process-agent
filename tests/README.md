# Dump

Interface state

https://www.postgresql.org/docs/current/protocol-message-formats.html


```text
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: enp1s0f0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN group default qlen 1000
    link/ether c4:c6:e6:22:93:89 brd ff:ff:ff:ff:ff:ff
3: wlp2s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 8c:3b:4a:4d:19:56 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.7/24 brd 192.168.1.255 scope global dynamic noprefixroute wlp2s0
       valid_lft 77926sec preferred_lft 77926sec
    inet6 fe80::707:506d:cb14:153c/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
4: br-0461801a5dd7: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 42:73:b4:e0:37:90 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-0461801a5dd7
       valid_lft forever preferred_lft forever
    inet6 fc00:f853:ccd:e793::1/64 scope global nodad 
       valid_lft forever preferred_lft forever
5: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 7a:59:f4:29:bb:e3 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::7859:f4ff:fe29:bbe3/64 scope link 
       valid_lft forever preferred_lft forever
6: br-a804242ed6d0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 4e:b4:df:55:0d:ca brd ff:ff:ff:ff:ff:ff
    inet 172.20.0.1/16 brd 172.20.255.255 scope global br-a804242ed6d0
       valid_lft forever preferred_lft forever
7: br-d4c34b37c81b: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether b2:ef:13:b2:eb:55 brd ff:ff:ff:ff:ff:ff
    inet 172.19.0.1/16 brd 172.19.255.255 scope global br-d4c34b37c81b
       valid_lft forever preferred_lft forever
80: vethaecb269@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether be:17:6d:71:b1:90 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::bc17:6dff:fe71:b190/64 scope link tentative 
       valid_lft forever preferred_lft forever
81: veth8b2df50@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 6a:02:9d:c0:ce:77 brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet6 fe80::6802:9dff:fec0:ce77/64 scope link tentative 
       valid_lft forever preferred_lft forever
```

Full dump of packets from ebpf socket filter an all interfaces of the root ns (ingress+egress)

```text
           <...>-85664   [003] b.s21  9658.409063: bpf_trace_printk: [O] ifx: 5, sip: 172.17.0.1, sport: 35144, dip: 172.17.0.3, dport: 5432, s: 897823354, a: 0, f: S
           <...>-85664   [003] b.s21  9658.409070: bpf_trace_printk: [O] ifx: 81, sip: 172.17.0.1, sport: 35144, dip: 172.17.0.3, dport: 5432, s: 897823354, a: 0, f: S
           <...>-85664   [003] ..s21  9658.409085: bpf_trace_printk: [E] ifx: 81, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35144, s: 0, a: 897823355, f: A+R
           <...>-85664   [003] ..s21  9658.409086: bpf_trace_printk: [I] ifx: 5, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35144, s: 0, a: 897823355, f: A+R

           <...>-85667   [009] b..11  9659.543680: bpf_trace_printk: [O] ifx: 5, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182738889, a: 0, f: S
           <...>-85667   [009] b..11  9659.543696: bpf_trace_printk: [O] ifx: 81, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182738889, a: 0, f: S
           <...>-85667   [009] ..s21  9659.543727: bpf_trace_printk: [E] ifx: 81, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048260, a: 4182738890, f: S+A
           <...>-85667   [009] ..s21  9659.543734: bpf_trace_printk: [I] ifx: 5, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048260, a: 4182738890, f: S+A
           <...>-85667   [009] b..11  9659.543757: bpf_trace_printk: [O] ifx: 5, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182738890, a: 8048261, f: A
           <...>-85667   [009] b..11  9659.543763: bpf_trace_printk: [O] ifx: 81, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182738890, a: 8048261, f: A

    docker-proxy-85664   [003] b..11  9659.544001: bpf_trace_printk: [O] ifx: 5, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182738890, a: 8048261, f: A
    docker-proxy-85664   [003] b..11  9659.544008: bpf_trace_printk: [O] ifx: 81, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182738890, a: 8048261, f: A
    docker-proxy-85664   [003] ..s21  9659.544020: bpf_trace_printk: [E] ifx: 81, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048261, a: 4182738990, f: A
    docker-proxy-85664   [003] ..s21  9659.544023: bpf_trace_printk: [I] ifx: 5, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048261, a: 4182738990, f: A
           <...>-86016   [000] ..s21  9659.545243: bpf_trace_printk: [E] ifx: 81, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048261, a: 4182738990, f: A
           <...>-86016   [000] ..s21  9659.545249: bpf_trace_printk: [I] ifx: 5, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048261, a: 4182738990, f: A
           <...>-86016   [000] b.s31  9659.545263: bpf_trace_printk: [O] ifx: 5, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182738990, a: 8048274, f: A
           <...>-86016   [000] b.s31  9659.545266: bpf_trace_printk: [O] ifx: 81, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182738990, a: 8048274, f: A
           <...>-85665   [010] b..11  9659.545348: bpf_trace_printk: [O] ifx: 5, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182738990, a: 8048274, f: A
           <...>-85665   [010] b..11  9659.545356: bpf_trace_printk: [O] ifx: 81, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182738990, a: 8048274, f: A
        postgres-86016   [008] ..s21  9659.553982: bpf_trace_printk: [E] ifx: 81, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048274, a: 4182739031, f: A
        postgres-86016   [008] ..s21  9659.553992: bpf_trace_printk: [I] ifx: 5, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048274, a: 4182739031, f: A
    docker-proxy-85665   [014] b..11  9659.554201: bpf_trace_printk: [O] ifx: 5, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182739031, a: 8048592, f: A
    docker-proxy-85665   [014] b..11  9659.554214: bpf_trace_printk: [O] ifx: 81, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182739031, a: 8048592, f: A
        postgres-86016   [011] ..s21  9659.554312: bpf_trace_printk: [E] ifx: 81, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048592, a: 4182739038, f: A
        postgres-86016   [011] ..s21  9659.554317: bpf_trace_printk: [I] ifx: 5, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048592, a: 4182739038, f: A
    docker-proxy-85665   [014] b..11  9659.554469: bpf_trace_printk: [O] ifx: 5, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182739038, a: 8048603, f: A
    docker-proxy-85665   [014] bN.11  9659.554480: bpf_trace_printk: [O] ifx: 81, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182739038, a: 8048603, f: A
        postgres-86016   [012] ..s21  9659.568493: bpf_trace_printk: [E] ifx: 81, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048603, a: 4182739153, f: A
        postgres-86016   [012] ..s21  9659.568508: bpf_trace_printk: [I] ifx: 5, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048603, a: 4182739153, f: A
    docker-proxy-85665   [000] b..11  9659.568726: bpf_trace_printk: [O] ifx: 5, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182739153, a: 8048627, f: A
    docker-proxy-85665   [000] b..11  9659.568733: bpf_trace_printk: [O] ifx: 81, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182739153, a: 8048627, f: A
        postgres-86016   [012] ..s21  9659.569056: bpf_trace_printk: [E] ifx: 81, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048627, a: 4182739224, f: A
        postgres-86016   [012] ..s21  9659.569063: bpf_trace_printk: [I] ifx: 5, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048627, a: 4182739224, f: A
    docker-proxy-85665   [000] b..11  9659.569126: bpf_trace_printk: [O] ifx: 5, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182739224, a: 8048677, f: A
    docker-proxy-85665   [000] b..11  9659.569129: bpf_trace_printk: [O] ifx: 81, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182739224, a: 8048677, f: A
        postgres-86016   [012] ..s21  9659.569775: bpf_trace_printk: [E] ifx: 81, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048677, a: 4182739263, f: A
        postgres-86016   [012] ..s21  9659.569780: bpf_trace_printk: [I] ifx: 5, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048677, a: 4182739263, f: A
    docker-proxy-85665   [002] b..11  9659.569908: bpf_trace_printk: [O] ifx: 5, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182739263, a: 8048719, f: A
    docker-proxy-85665   [002] b..11  9659.569919: bpf_trace_printk: [O] ifx: 81, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182739263, a: 8048719, f: A
        postgres-86016   [012] ..s21  9659.570280: bpf_trace_printk: [E] ifx: 81, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048719, a: 4182739296, f: A
        postgres-86016   [012] ..s21  9659.570284: bpf_trace_printk: [I] ifx: 5, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048719, a: 4182739296, f: A
    docker-proxy-85665   [002] b..11  9659.570373: bpf_trace_printk: [O] ifx: 5, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182739296, a: 8048811, f: A
    docker-proxy-85665   [002] b..11  9659.570376: bpf_trace_printk: [O] ifx: 81, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182739296, a: 8048811, f: A
    docker-proxy-85665   [000] b..11  9659.570407: bpf_trace_printk: [O] ifx: 5, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182739301, a: 8048811, f: F+A
    docker-proxy-85665   [000] b..11  9659.570411: bpf_trace_printk: [O] ifx: 81, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182739301, a: 8048811, f: F+A
        postgres-86016   [009] ..s21  9659.572734: bpf_trace_printk: [E] ifx: 81, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048811, a: 4182739302, f: F+A
        postgres-86016   [009] ..s21  9659.572740: bpf_trace_printk: [I] ifx: 5, sip: 172.17.0.3, sport: 5432, dip: 172.17.0.1, dport: 35152, s: 8048811, a: 4182739302, f: F+A
        postgres-86016   [009] b.s31  9659.572756: bpf_trace_printk: [O] ifx: 5, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182739302, a: 8048812, f: A
        postgres-86016   [009] b.s31  9659.572761: bpf_trace_printk: [O] ifx: 81, sip: 172.17.0.1, sport: 35152, dip: 172.17.0.3, dport: 5432, s: 4182739302, a: 8048812, f: A
```

Tshark dump

```bash
sudo tshark -i docker0 -f "port 5432"
```

```text
Running as user "root" and group "root". This could be dangerous.
Capturing on 'docker0'
    1 0.000000000   172.17.0.1 → 172.17.0.3   TCP 74 38848 → 5432 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=945545925 TSecr=0 WS=128
    2 0.000017052   172.17.0.3 → 172.17.0.1   TCP 54 5432 → 38848 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0
    3 1.129273738   172.17.0.1 → 172.17.0.3   TCP 74 38860 → 5432 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=945547055 TSecr=0 WS=128
    4 1.129299627   172.17.0.3 → 172.17.0.1   TCP 74 5432 → 38860 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM TSval=2257740416 TSecr=945547055 WS=128
    5 1.129310928   172.17.0.1 → 172.17.0.3   TCP 66 38860 → 5432 [ACK] Seq=1 Ack=1 Win=64256 Len=0 TSval=945547055 TSecr=2257740416
    6 1.129479817   172.17.0.1 → 172.17.0.3   PGSQL 166 >?
    7 1.129486649   172.17.0.3 → 172.17.0.1   TCP 66 5432 → 38860 [ACK] Seq=1 Ack=101 Win=65152 Len=0 TSval=2257740416 TSecr=945547055
    8 1.130647820   172.17.0.3 → 172.17.0.1   PGSQL 79 <R
    9 1.130658641   172.17.0.1 → 172.17.0.3   TCP 66 38860 → 5432 [ACK] Seq=101 Ack=14 Win=64256 Len=0 TSval=945547056 TSecr=2257740417
   10 1.130745845   172.17.0.1 → 172.17.0.3   PGSQL 107 >p
   11 1.140856033   172.17.0.3 → 172.17.0.1   PGSQL 384 <R/S/S/S/S/S/S/S/S/S/S/S/K/Z
   
   12 1.141140018   172.17.0.1 → 172.17.0.3   PGSQL 73 >Q         // Empty query
   13 1.141232262   172.17.0.3 → 172.17.0.1   PGSQL 77 <I/Z       (I) means empty response, we only want the 'Q'
   
   14 1.141380482   172.17.0.1 → 172.17.0.3   PGSQL 181 >Q        // Simple query + response
   15 1.150807981   172.17.0.3 → 172.17.0.1   PGSQL 90 <C/Z     

   16 1.151015763   172.17.0.1 → 172.17.0.3   PGSQL 137 >P/D/S    // Extended query
   17 1.151468558   172.17.0.3 → 172.17.0.1   PGSQL 116 <1/t/T/Z
   18 1.151684074   172.17.0.1 → 172.17.0.3   PGSQL 105 >B/E/S
   19 1.152396348   172.17.0.3 → 172.17.0.1   PGSQL 108 <2/D/C/Z

   20 1.152544999   172.17.0.1 → 172.17.0.3   PGSQL 99 >Q         // Extended query
   21 1.152738494   172.17.0.3 → 172.17.0.1   PGSQL 158 <T/D/C/Z


   22 1.152818274   172.17.0.1 → 172.17.0.3   PGSQL 71 >X
   23 1.152840586   172.17.0.1 → 172.17.0.3   TCP 66 38860 → 5432 [FIN, ACK] Seq=412 Ack=551 Win=64128 Len=0 TSval=945547078 TSecr=2257740439
   24 1.155690434   172.17.0.3 → 172.17.0.1   TCP 66 5432 → 38860 [FIN, ACK] Seq=551 Ack=413 Win=65152 Len=0 TSval=2257740442 TSecr=945547078
   25 1.155708398   172.17.0.1 → 172.17.0.3   TCP 66 38860 → 5432 [ACK] Seq=413 Ack=552 Win=64128 Len=0 TSval=945547081 TSecr=2257740442
```
