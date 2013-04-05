#!/usr/bin/python

from bmp_message import *

############################################################################### 

bmp_initiation_message()
i = 1
ip = '10'+str(i)+'.1.1.'+str(i)
bmp_peer_up_message(ip, 0, 100, 0)
bmp_peer_up_message('101.1.1.1', 0, 200, 0)
bmp_peer_up_message('102.1.1.1', 0, 300, 0)
bmp_peer_up_message('103.1.1.1', 0, 100, 0)
 



