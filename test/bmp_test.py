#!/usr/bin/python

from bmp_message import *

############################################################################### 

bmp_initiation_message()

bmp_peer_up_message('1.1.1.1', 0, 100, 0)
bmp_peer_up_message('2.1.1.1', 0, 200, 0)
bmp_peer_up_message('3.1.1.1', 0, 300, 0)


data = bgp_dummy_update_message(10, 60, 30)
bmp_route_monitoring_message('1.1.1.1', 0, 100, 0, data)
 
bmp_peer_down_message('3.1.1.1', 0, 300, 0)


nf.sleep()
