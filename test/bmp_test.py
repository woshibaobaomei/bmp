#!/usr/bin/python

import sys
import socket

###############################################################################

def byte (b):
    if b > 0xFF:
        raise Exception, 'byte value > 0xFF';
    #end if
    sys.stdout.write(('\\x%02x' % b).decode('string_escape'));
#end def

def word (w):
    if w > 0xFFFF:
        raise Exception, 'word value > 0xFFFF'
    #end if
    byte((w & 0xFF00) >> 8)
    byte((w & 0x00FF) >> 0)
#end def

def dword (dw):
    if dw > 0xFFFFFFFF:
        raise Exception, 'dword value > 0xFFFFFFFF'
    #end if
    word((dw & 0xFFFF0000) >> 16)
    word((dw & 0x0000FFFF) >> 00)
#end def

def qword (qw):
    if qw > 0xFFFFFFFFFFFFFFFF:
        raise Exception, 'qword value > 0xFFFFFFFFFFFFFFFF'
    #end if
    dword((qw & 0xFFFFFFFF00000000) >> 32)
    dword((qw & 0x00000000FFFFFFFF) >> 00)
#end def

def ipbytes (ip, pad):
    try: # IPv4
        addr = socket.inet_pton(socket.AF_INET, ip)
        if pad: 
            for i in xrange(0,12): byte(0)
        #endif
    except socket.error:
        try: # IPv6
            addr = socket.inet_pton(socket.AF_INET6, ip)
        except socket.error:
            raise Exception, "invalid address [%s]" % ip
        #end try IPv6
    #end try IPv4
    for b in addr: byte(ord(b))
#end def
 
############################################################################### 
 
def bmp_header (version, length, type):
    byte(version)
    dword(length)
    byte(type)
    return 6
#end def

def bmp_peer_header (type, flags, rd, ip, asn, id, sec, msec):
    byte(type)
    byte(flags)
    qword(rd)
    ipbytes(ip)
    dword(asn)
    dword(id)
    dword(sec)
    dword(msec)
    return 42
#end def

def bmp_initiation_message (length):
    hlen = bmp_header(0, length, 4)
    for i in xrange(hlen,length):
        byte(0)
    #end for
#end def

def bmp_termination_message (length):
    hlen = bmp_header(0, length, 5)
    for i in xrange(hlen, length):
        byte(0)
    #end for
#end def

def bmp_peer_up_message (length):
    hlen = bmp_header(0, length, 3)
    plen = bmp_peer_header(0, 0, 0, 0, 0, 0, 0, 0)
    for i in xrange(hlen+plen, length):
        byte(0)
    #end for
#end def

###############################################################################

qword(0xaabbccddeeff0011)
ipbytes('1.2.3.4', 1)


