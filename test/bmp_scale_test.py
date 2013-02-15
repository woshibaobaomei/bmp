#!/usr/bin/python

from bmp_message import *

############################################################################### 

bmp_initiation_message()

code = '';

for i in xrange(0,4):
    for j in xrange(0,256):
        code += "bmp_peer_up_message('10"+str(i)+".0.0."+str(j)+"', 0, 100, 0)"
        code += "\n"
    #end for
#end for

exec code
