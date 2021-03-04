from scapy.fields import PacketField, MultipleTypeField, ByteField, XByteField, ShortEnumField, ShortField, XIntField, \
    ByteEnumField
from scapy.layers.inet import UDP
from scapy.packet import Packet, bind_layers, Padding, bind_bottom_up

# KNX CODES

SERVICE_IDENTIFIERS = {
    0x0203: "DESCRIPTION REQUEST"
}

HOST_PROTOCOL_CODES = {
    0x01: "IPV4_UDP"
}


# KNX BASE BLOCKS

class HPAI(Packet):
    name = "HPAI"
    fields_desc = [
        ByteField("structure_length", None),  # TODO: replace by a field that measures the packet length
        ByteEnumField("host_protocol_code", 0x01, HOST_PROTOCOL_CODES),
        XIntField("ip_address", None),  # TODO: replace by a (custom) IP address field
        ShortField("ip_port", None)
    ]


# KNX SERVICES

class KNXDescriptionRequest(Packet):
    name = "DESCRIPTION REQUEST"
    fields_desc = [
        PacketField("control_endpoint", HPAI(), HPAI)
    ]


# KNX FRAME

class KNXHeader(Packet):
    name = "Header"
    fields_desc = [
        ByteField("header_length", None),  # TODO: replace by a field that measures the packet length
        XByteField("protocol_version", 0x10),
        ShortEnumField("service_identifier", None, SERVICE_IDENTIFIERS),
        ShortField("total_length", None)  # TODO: replace by a field that measures the total frame length
    ]


class KNXnetIP(Packet):
    name = "KNXnet/IP"
    # header and body could also be linked using `bind_layers(KNXHeader, KNXBody, service_type_identifier=0x....)`
    # using `bind_layers` is the "scapiest" way, but `MultipleTypeField` seems closer to KNX specifications
    fields_desc = [
        PacketField("header", KNXHeader(), KNXHeader),
        MultipleTypeField(
            [
                (PacketField("body", KNXDescriptionRequest(), KNXDescriptionRequest),
                 lambda pkt: pkt.knx_header.service_identifier == 0x0203),
            ],
            PacketField("body", None, None)
        )

    ]


# LAYERS BINDING

bind_layers(UDP, KNXnetIP, dport=3671)
bind_bottom_up(UDP, KNXnetIP, sport=3671)

# for now we bind every layer used as PacketField to Padding in order to delete its payload
# (solution inspired by https://github.com/secdev/scapy/issues/360)
# we could also define a new Packet class with no payload
# (solution inspired by https://github.com/mlgiraud/scapy/blob/feature/opcua/scapy/contrib/opcua/helpers.py, l.74)

bind_layers(HPAI, Padding)

bind_layers(KNXDescriptionRequest, Padding)

bind_layers(KNXHeader, Padding)
