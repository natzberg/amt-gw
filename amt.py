from ctypes import sizeof
import socket
import struct
import sys
from tkinter import Pack
from scapy.all import *

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
AMT_REQUEST = 3            # request
AMT_MEM_QUERY = 4          # memebership query
AMT_MEM_UPD = 5            # membership update
AMT_MULT_DATA = 6          # multicast data
AMT_TEARDOWN = 7           # teardown (not currently supported)

MCAST_ANYCAST = "0.0.0.0"
MCAST_ALLHOSTS = "224.0.0.22"
LOCAL_LOOPBACK = "127.0.0.1"
AMT_PORT = 2268

DEFAULT_MTU = (1500 - (20 + 8))

class AMT_Discovery(Packet):
    name = "AMT_Discovery"
    fields_desc = [ 
        BitField("version", 0, 4),
        BitField("type", AMT_RELAY_DISCO, 4),
        BitField("rsvd", 0, 24),
        IntField("nonce", 0),
    ]

class AMT_Relay_Advertisement(Packet):
    name = "AMT_Relay_Adv"
    fields_desc = [
        BitField("version", 0, 4),
        BitField("type", AMT_RELAY_ADV, 4),
        BitField("rsvd", 0, 24),
        IntField("nonce", 0),
        MultipleTypeField(
            [
                (IPField("relay_addr", "0.0.0.0"), lambda pkt: pkt.len == 12),  #ipv4, UDP datagram length - 8 = 4
                (IP6Field("relay_addr", "::"), lambda pkt: pkt.len == 20)       #ipv4, UDP datagram length - 8 = 16
            ],
            StrField("relay_addr", "")  #default
        )
    ]
class AMT_Relay_Request(Packet):
    name = "AMT_Relay_Request"
    fields_desc = [ 
        BitField("version", 0, 4),
        BitField("type", AMT_REQUEST, 4),
        BitField("rsvd1", 0, 7),
        BitField("p_flag", 0, 1),
        BitField("rsvd2", 0, 16),
        IntField("nonce", 0)
    ]

class AMT_Membership_Query(Packet):
    name = "AMT_Membership_Query"
    fields_desc = [
        BitField("version", 0, 4),
        BitField("type", AMT_MEM_QUERY, 4),
        BitField("rsvd1", 0, 6),
        BitField("l_flag", 0, 1),
        BitField("g_flag", 0, 0),
        BitField("rsvd2", 0, 16),
        MACField("response_mac", 0),
        IntField("nonce", 0),
    ]