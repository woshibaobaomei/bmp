#!/usr/bin/python

import os,sys,socket

sys.path.append(os.getcwd()+'/lib/nf')

import nf


############################################################################### 


def bmp_header (type):
    nf.byte(3)
    nf.length(4)
    nf.byte(type)
    return 6
#end def


def bmp_peer_header (ip, rd, asn, id, sec, msec):
 
    flags = 0

    try: # IPv4
        socket.inet_pton(socket.AF_INET, ip)
        flags &= ~(0x80)
    except socket.error:
        try: # IPv6
            socket.inet_pton(socket.AF_INET6, ip)
            flags |= 0x80
        except socket.error:
            raise Exception, "invalid address [%s]" % ip
        #end try IPv6
    #end try IPv4

    if not id:
        id = ip
    #end if

    type = (rd != 0)

    nf.byte(type)
    nf.byte(flags)
    nf.qword(rd)
    nf.ip(ip, 16)
    nf.dword(asn)
    nf.ip(id)
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


def bmp_peer_up_message (ip, rd, asn, id):

    nf.start()

    bmp_header(3)
    bmp_peer_header(ip, rd, asn, id, 0, 0)

    
    nf.end()

#end def


def bmp_peer_down_message (ip, rd, asn, id):

    nf.start()

    hlen = bmp_header(2)
    plen = bmp_peer_header(ip, rd, asn, id, 0, 0)

    nf.end()

#end def


def bmp_route_monitoring_message (ip, rd, asn, id, pdu):

    nf.start()

    hlen = bmp_header(0)
    plen = bmp_peer_header(0,0,0,0,0,0,0,0)


    nf.end()

#end def
    

###############################################################################

