#!/usr/bin/python

import os,sys

sys.path.append(os.getcwd()+'/lib/nf')

import nf


############################################################################### 


def bmp_header (type):
    nf.byte(3)
    nf.length(4)
    nf.byte(type)
    return 6
#end def


def bmp_peer_header (ip, flags, rd, asn, id, sec, msec):

    # type

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


def bmp_initiation_message ():

    nf.start()

    hlen = bmp_header(4)

    nf.end()

#end def


def bmp_termination_message ():

    nf.start()

    hlen = bmp_header(5)

    nf.end()

#end def


def bmp_peer_up_message (ip, flags, rd, asn, id):

    nf.start()

    bmp_header(3)
    bmp_peer_header(0, 0, 0, 0, 0, 0, 0, 0)

    
    nf.end()

#end def


def bmp_peer_down_message ():

    nf.start()

    hlen = bmp_header(2)
    plen = bmp_peer_header(0, 0, 0, 0, 0, 0, 0, 0)

    nf.end()

#end def


def bmp_route_monitoring_message (ip, flags, rd, asn, id, pdu):

    nf.start()

    hlen = bmp_header(0)
    plen = bmp_peer_header(0,0,0,0,0,0,0,0)


    nf.end()

#end def
    

###############################################################################

