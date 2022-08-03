import socket
from unittest.mock import DEFAULT
from urllib import request
from scapy.all import *
from scapy.contrib.igmp import *
from amt import *
import secrets


ip_top_layer = IP(dst="162.250.137.254")        #relay addr
igmp_layer = scapy.contrib.igmp.IGMP()
udp_top_layer = UDP(sport=AMT_PORT, dport=AMT_PORT)
amt_layer = AMT_Discovery()
nonce = secrets.token_bytes(4)
amt_layer.setfieldval("nonce", nonce)
igmp_layer = IGMP()
# bind_layers(UDP, AMT_Discovery, dport=AMT_PORT)
packet =  ip_top_layer / udp_top_layer / amt_layer
# print(packet)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind(('', AMT_PORT))

    # Send relay discovery message and wait for response
    p = send(packet)
    data, addr = s.recvfrom(DEFAULT_MTU)
    relay_adv = AMT_Relay_Advertisement(data)   # convert raw packet to relay adv packet
    print(relay_adv.fields)                     # just checking, debug

    # once we receive the packet, craft a relay request
    relay_request = AMT_Relay_Request()
    relay_request.setfieldval("nonce", nonce)   # keep same nonce!
    request_pkt = ip_top_layer / udp_top_layer / relay_request
    p = send(request_pkt)
    data, addr = s.recvfrom(DEFAULT_MTU)        # receive the membership query
    print(data)
    membership_query = AMT_Membership_Query(data)
    print(membership_query.fields)

    # received the membership query, now pull out the info we need

            
