"""
    Implementation of the AMT protocol (https://datatracker.ietf.org/doc/html/rfc7450)
    in Python. While AMT is designed to support both IPV4 and IPV6 traffic,
    as of Aug 2022 Scapy does not fully support IPV6. This implementation relies on Scapy.
"""

from ctypes import sizeof
import socket
import struct
import sys
from scapy.all import *
import scapy.contrib.igmpv3

################################################
# Various Lengths of Msgs or Hdrs
################################################
VERSION_LEN = 4            # length of version in packet
MSG_TYPE_LEN = 4           # length of msg type 

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
        BitField("version", 0, VERSION_LEN),
        BitField("type", AMT_RELAY_DISCO, MSG_TYPE_LEN),
        BitField("rsvd", 0, 24),
        XStrFixedLenField("nonce", 0, 4)
    ]

class AMT_Relay_Advertisement(Packet):
    name = "AMT_Relay_Advertisement"
    fields_desc = [
        BitField("version", 0, VERSION_LEN),
        BitField("type", AMT_RELAY_ADV, MSG_TYPE_LEN),
        BitField("rsvd", 0, 24),
        XStrFixedLenField("nonce", 0, 4),
        IPField("relay_addr", MCAST_ANYCAST)
    ]
class AMT_Relay_Request(Packet):
    name = "AMT_Relay_Request"
    fields_desc = [ 
        BitField("version", 0, VERSION_LEN),
        BitField("type", AMT_REQUEST, MSG_TYPE_LEN),
        BitField("rsvd1", 0, 7),
        BitField("p_flag", 0, 1),
        BitField("rsvd2", 0, 16),
        XStrFixedLenField("nonce", 0, 4)
    ]

"""
    A relay sends a Membership Query message to a gateway to solicit a
    Membership Update response, but only after receiving a Request
    message from the gateway.
"""
class AMT_Membership_Query(Packet):
    name = "AMT_Membership_Query"
    fields_desc = [
        BitField("version", 0, VERSION_LEN),
        BitField("type", AMT_MEM_QUERY, MSG_TYPE_LEN),
        BitField("rsvd1", 0, 6),
        BitField("l_flag", 0, 1),
        BitField("g_flag", 0, 1),
        BitField("rsvd2", 0, 16),
        MACField("response_mac", 0),
        XStrFixedLenField("nonce", 0, 4),
        #encapsulated IGMPv3 or MLDv2, defaults to IGMP
        PacketListField("amt_igmpv3", None, scapy.contrib.igmpv3.IGMPv3)
        # BitField("igmp_mld_type", 0x11, 8),
        # ConditionalField(BitField("igmp_max_resp_code", 0, 8), lambda pkt: pkt.igmp_mld_type == 0x11 ),
        # # ConditionalField(BitField("mld_code", 0, 0), lambda pkt: pkt.igmp_mld_type == 130),   #IPV6
        # XShortField("checksum", None),
        # ConditionalField(IPField("igmp_group_addr", MCAST_ANYCAST), lambda pkt: pkt.igmp_mld_type == 0x11),
        # # ConditionalField(BitField("mld_rsvd1", 0, 16), lambda pkt: pkt.igmp_mld_type == 130),     #IPV6
        # # ConditionalField(IP6Field("mld_addr", "::"), lambda pkt: pkt.igmp_mld_type == 130),       #IPV6
        # BitField("rsvd3", 0, 4),
        # BitField("s_flag", 0, 1),
        # BitField("qrv", 0, 3),
        # BitField("qqic", 0, 8),
        # IntField("num_of_srcs", 0),
        # ConditionalField(FieldListField("src_addrs", [], IPField("", MCAST_ANYCAST), count_from = lambda pkt: pkt.num_of_srcs), 
        #     lambda pkt: pkt.igmp_mld_type == 0x11),
        # # ConditionalField(FieldListField("src_addrs", [], IPField("", "::1"), count_from = lambda pkt: pkt.num_of_srcs), 
        # #     lambda pkt: pkt.igmp_mld_type == 130) #IPV6
    ]

"""
    A gateway sends a Membership Update message to a relay to report a
   change in group membership state, or to report the current group
   membership state in response to receiving a Membership Query message.
"""
class AMT_Membership_Update(Packet):
    name = "AMT_Membership_Update"

    igmptypes = {
        0x11: "IGMP: Group Membership Query",
        0x12: "IGMP: Version 1 - Membership Report",
        0x16: "IGMP: Version 2 - Membership Report",
        0x17: "IGMP: Leave Group"
    }

    # Currently not supported but here for future use
    mldtypes = {
        130: "MLD: Multicast Listener Query",
        143: "MLD: Version 2 Multicast Listener Report",
        131: "MLD: Version 1 Multicast Listener Report",
        132: "MLD: Version 1 Multicast Listener Done"
    }

    fields_desc = [
        BitField("version", 0, VERSION_LEN),
        BitField("type", AMT_MEM_UPD, MSG_TYPE_LEN),
        BitField("rsvd1", 0, 8),
        MACField("response_mac", 0),
        XStrFixedLenField("nonce", 0, 4),
        #encapsulated IGMPv3 or MLDv2, defaults to IGMP
        PacketListField("amt_igmpv3", None, scapy.contrib.igmpv3.IGMPv3)
        # ByteEnumField("igmp_mld_type", 0x16, igmptypes),
        # ConditionalField(BitField("igmp_max_resp_code", 0, 8), lambda pkt: pkt.igmp_mld_type == 0x11 ),
        # # ConditionalField(BitField("mld_code", 0, 0), lambda pkt: pkt.igmp_mld_type == 130), #IPV6
        # XShortField("checksum", None),
        # ConditionalField(IPField("igmp_group_addr", MCAST_ANYCAST), lambda pkt: pkt.igmp_mld_type == 0x11),
        # # ConditionalField(BitField("mld_rsvd1", 0, 16), lambda pkt: pkt.igmp_mld_type == 130), #IPV6
        # # ConditionalField(IP6Field("mld_addr", "::"), lambda pkt: pkt.igmp_mld_type == 130),   #IPV6
        # BitField("rsvd2", 0, 4),
        # BitField("s_flag", 0, 1),
        # BitField("qrv", 0, 3),
        # BitField("qqic", 0, 8),
        # IntField("num_of_srcs", 0),
        # ConditionalField(FieldListField("src_addrs", [], IPField("", MCAST_ANYCAST), count_from = lambda pkt: pkt.num_of_srcs), 
        #     lambda pkt: pkt.igmp_mld_type == 0x11),
        # # ConditionalField(FieldListField("src_addrs", [], IPField("", "::"), count_from = lambda pkt: pkt.num_of_srcs), 
        # #     lambda pkt: pkt.igmp_mld_type == 130) #IPV6
    ]

class AMT_Multicast_Data(Packet):
    name = "AMT_Multicast_Data"
    fields_desc = [
        BitField("version", 0, VERSION_LEN),
        BitField("type", AMT_MULT_DATA, 4),
        BitField("rsvd", 0, 8),
        PacketListField("amt_ip", None, scapy.layers.inet.IP)
    ]

"""
    A gateway sends a Teardown message to a relay to request that it stop
    sending Multicast Data messages to a tunnel endpoint created by an
    earlier Membership Update message.
"""
class AMT_Teardown(Packet):
    name = "AMT_Teardown"
    fields_desc = [
        BitField("version", 0, VERSION_LEN),
        BitField("type", AMT_TEARDOWN, 4),
        BitField("rsvd", 0, 8),
        MACField("response_mac", 0),
        XStrFixedLenField("nonce", 0, 4),
        ShortField("gw_port_num", 0),
        IPField("gw_ip_addr", MCAST_ANYCAST)
    ]