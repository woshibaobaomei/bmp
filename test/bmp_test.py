#!/usr/bin/python

import sys
import os

sys.path.append(os.getcwd()+os.sep+'lib')

from nf import nf

############################################################################### 

def bmp_header (version, length, type):
    nf.byte(version)
    nf.dword(length)
    nf.byte(type)
    return 6
#end def


def bmp_peer_header (type, flags, rd, ip, asn, id, sec, msec):
    nf.byte(type)
    nf.byte(flags)
    nf.qword(rd)
    nf.ip(ip, 16)
    nf.dword(asn)
    nf.dword(id)
    nf.dword(sec)
    nf.dword(msec)
    return 42
#end def


def bmp_initiation_message (length):
    hlen = bmp_header(0, length, 4)
    for i in xrange(hlen,length):
        nf.byte(0)
    #end for
#end def


def bmp_termination_message (length):
    hlen = bmp_header(0, length, 5)
    for i in xrange(hlen, length):
        nf.byte(0)
    #end for
#end def


def bmp_peer_up_message (length):
    hlen = bmp_header(0, length, 3)
    plen = bmp_peer_header(0, 0, 0, 0, 0, 0, 0, 0)
    for i in xrange(hlen+plen, length):
        nf.byte(0)
    #end for
#end def

###############################################################################
 
nf.ip('1.2.3.4')
