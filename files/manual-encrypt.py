#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Seoyeoung Jo, Tommy Gerardi and Daniel Oliveira Paiva"
__status__ 		= "Prototype"


from scapy.all import *
import rc4
import zlib

# wep key AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

# We read the original encrypted message from the wireshark file - rdpcap always returns an array, even if the pcap only contains one frame
arp = rdpcap('arp.cap')[0]

# Construct the seed
seed = arp.iv+key 
# Set the message
message = 'Hello sadness'
# Compute the ICV
icv = crc32(message) & 0xffffffff
icv = struct.pack('<L', icv)

#Encrypt the data
message_encrpyted = rc4.rc4crypt(message+str(icv), seed)

# Edit the packet
arp.icv = struct.unpack('!L', message_encrpyted[-4:])[0]
arp.wepdata = message_encrpyted[:-4]

#Write the pdacket
wrpcap('newarp.pcap', arp)

print 'Encrypted Message: ' + arp.wepdata.encode("hex")




