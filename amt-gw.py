import socket
import struct
import sys
from scapy.all import *
import scapy.contrib.igmp
from amt import *

################################################
# Various Lengths of Msgs or Hdrs
################################################
MAC_LEN = 6                # length of generated MAC in bytes
NONCE_LEN = 4              # length of nonce in bytes
MSG_TYPE_LEN = 1           # length of msg type 
RELAY_QUERY_MSG_LEN = 48   # total length of relay query 
RELAY_ADV_MSG_LEN = 12     # length of relay advertisement message 
IGMP_QUERY_LEN = 24        # length of encapsulated IGMP query message 
IGMP_REPORT_LEN = 20
AMT_HDR_LEN = 2            # length of AMT header on a packet 
IP_HDR_LEN = 20            # length of standard IP header 
IP_HDR_IGMP_LEN = 24       # length of IP header with an IGMP report 
UDP_HDR_LEN = 8            # length of standard UDP header 
AMT_REQUEST_MSG_LEN = 9    # length of AMT request message
AMT_DISCO_MSG_LEN = 8      # length of AMY discovery message

################################################
# Different AMT Message Types
################################################
AMT_RELAY_DISCO = 1        # relay discovery
AMT_RELAY_ADV = 2          # relay advertisement
AMT_REQUEST = 3            # reuqest
AMT_MEM_QUERY = 4          # memebership query
AMT_MEM_UPD = 5            # membership update
AMT_MULT_DATA = 6          # multicast data
AMT_TEARDOWN = 7           # teardown (not currently supported)

MCAST_ANYCAST = "0.0.0.0"
MCAST_ALLHOSTS = "224.0.0.22"
LOCAL_LOOPBACK = "127.0.0.1"
AMT_PORT = 2268

DEFAULT_MTU = (1500 - (20 + 8))


# message = 'very important data'.encode()
# multicast_group = ('224.3.29.71', 10000)

# # Create the datagram socket
# sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# # Set a timeout so the socket does not block indefinitely when trying
# # to receive data.
# sock.settimeout(0.2)
# # Set the time-to-live for messages to 1 so they do not go past the
# # local network segment.
# ttl = struct.pack('b', 1)
# sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
# try:

#     # Send data to the multicast group
#     print(sys.stderr, 'sending "%s"' % message)
#     sent = sock.sendto(message, multicast_group)

#     # Look for responses from all recipients
#     while True:
#         print(sys.stderr, 'waiting to receive')
#         try:
#             data, server = sock.recvfrom(16)
#         except socket.timeout:
#             print(sys.stderr, 'timed out, no more responses')
#             break
#         else:
#             print(sys.stderr, 'received "%s" from %s' % (data, server))

# finally:
#     print(sys.stderr, 'closing socket')
#     sock.close()

ip_top_layer = IP(dst="172.16.27.135")
igmp_layer = scapy.contrib.igmp.IGMP()
udp_top_layer = UDP(sport=AMT_PORT, dport=AMT_PORT)
amt_layer = AMT_Relay_Advertisement()
mickey_layer = Disney()
# bind_layers(UDP, AMT_Discovery, dport=AMT_PORT)
packet =  ip_top_layer / udp_top_layer / amt_layer
# print(packet)
send(packet)