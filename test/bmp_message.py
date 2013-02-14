#!/usr/bin/python

import os,sys,socket

sys.path.append(os.getcwd()+'/lib/nf')

import nf


###############################################################################


def bgp_header (type):
    nf.dword(0xffffffff)
    nf.dword(0xffffffff)
    nf.dword(0xffffffff)
    nf.dword(0xffffffff)
    nf.length(2)
    nf.byte(type)
#end def


def bgp_dummy_update_message(wdr, attr, nlri):
    nf.start()
    bgp_header(2)
    nf.word(wdr)     # Unfeasible routes length
    nf.pad(wdr)      # Unfeasible routes
    nf.word(attr)    # Path attribute length
    nf.pad(attr)     # Path attributes
    nf.pad(nlri)     # NLRI
    return nf.end(1) # End the block without writing anything
#end def


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


###############################################################################


def bmp_initiation_message ():

    nf.start()

    bmp_header(4)

    nf.end()

#end def


def bmp_termination_message ():

    nf.start()

    bmp_header(5)

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

    bmp_header(2)
    bmp_peer_header(ip, rd, asn, id, 0, 0)

    nf.end()

#end def


def bmp_route_monitoring_message (ip, rd, asn, id, pdu):

    nf.start()

    bmp_header(0)
    bmp_peer_header(ip, rd, asn, id, 0, 0)

    nf.data(pdu)
    
    nf.end()

#end def
    

###############################################################################

