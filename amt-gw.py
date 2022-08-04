import socket
from unittest.mock import DEFAULT
from urllib import request
from scapy.all import *
from scapy.contrib.igmpv3 import *
from amt import *
import secrets
import time

def amt_mem_update(nonce, response_mac):
    ip_layer = IP(dst="162.250.137.254")
    udp_layer = UDP(sport=AMT_PORT, dport=AMT_PORT)
    amt_layer = AMT_Membership_Update()
    amt_layer.setfieldval("nonce", nonce)
    amt_layer.setfieldval("response_mac", response_mac)
    options_pkt = Packet(b"\x00")       # add IP options to match working C implementation
    ip_layer2 = IP(src="0.0.0.0", dst="224.0.0.22", options=[options_pkt])
    igmp_layer = IGMPv3()
    igmp_layer.type = 34        # {17: 'Membership Query', 34: 'Version 3 Membership Report', 48: 'Multicast Router Advertisement', 49: 'Multicast Router Solicitation', 50: 'Multicast Router Termination'}
    igmp_layer2 = IGMPv3mr(records=[IGMPv3gr(maddr='232.198.38.1', srcaddrs=["198.38.23.146"])])
    update = ip_layer / udp_layer / amt_layer / ip_layer2 / igmp_layer / igmp_layer2
    update.show()
    # send(update)
    return update


ip_top_layer = IP(dst="162.250.137.254")        #relay addr
# udp_rand_port = RandShort()
# print(udp_rand_port)
udp_top_layer = UDP(sport=AMT_PORT, dport=AMT_PORT)
amt_layer = AMT_Discovery()
nonce = secrets.token_bytes(4)
amt_layer.setfieldval("nonce", nonce)
# bind_layers(UDP, AMT_Discovery, dport=AMT_PORT)
packet =  ip_top_layer / udp_top_layer / amt_layer
# print(packet)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
s.bind(('', AMT_PORT))

# Send relay discovery message and wait for response
p = send(packet)
data, addr = s.recvfrom(DEFAULT_MTU)
relay_adv = AMT_Relay_Advertisement(data)   # convert raw packet to relay adv packet
print(relay_adv.fields)                     # just checking, debug

# once we receive the packet, craft a relay request
relay_request = AMT_Relay_Request()
relay_request.setfieldval("nonce", nonce)   # keep same nonce!
# udp_top_layer.sport = udp_rand_port
request_pkt = ip_top_layer / udp_top_layer / relay_request
p = send(request_pkt)
data, addr = s.recvfrom(DEFAULT_MTU)        # receive the membership query
print(data)
membership_query = AMT_Membership_Query(data)
response_mac = membership_query.response_mac
membership_query.show()

# received the membership query, send a membership update
req = struct.pack("=4sl", socket.inet_aton("232.198.38.1"), socket.INADDR_ANY)
s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, req)
# s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, 1)
update = amt_mem_update(nonce, response_mac)
send(update)
# while True:
    # receive the multicast data!
data, addr = s.recvfrom(DEFAULT_MTU)        # receive the membership query
print(data)
s.close()

