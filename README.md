## Segment Routing SDN controller

Overview:
========
This is the SDN controller for Segment Routing tutorial: `http://www.cs.utah.edu/~binh/archive/segment_routing/segment-routing-tutorial.html`

Usage:
=====
* Prerequisite:
Must copy ofproto_v1_3_parser.py to /usr/local/lib/python2.7/dist-packages/ryu/ofproto/ofproto_v1_3_parser.py

* Run SDN controller:
`ryu-manager sr_controller_test.py`

* Install Segment Routing forwarding rules using RESTful API: 
`curl --data 'dpid=17779080870&match=ipv6_dst=2001::204:23ff:feb7:1e40,eth_type=0x86DD&actions=ipv6_dst=2001::208:204:23ff:feb7:1e40,ipv6_dst=2001::208:204:23ff:feb7:1e41,ipv6_dst=2001::208:204:23ff:feb7:1e42,output=1' http://0.0.0.0:8080/flow_mgmt/insert`

