#!/usr/bin/python

from bmp_message import *

############################################################################### 
 
bmp_initiation_message()

  bmp_peer_up_message('1.1.1.1', 0, 100, 0)
  bmp_peer_up_message('2.1.1.1', 0, 200, 0)
  bmp_peer_up_message('3.1.1.1', 0, 300, 0)
  bmp_peer_up_message('4.1.1.1', 0, 400, 0)
  bmp_peer_up_message('5.1.1.1', 0, 500, 0)
  bmp_peer_up_message('6.1.1.1', 0, 600, 0)

nf.sleep()
