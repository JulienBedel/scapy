from scapy.fields import PacketField, MultipleTypeField, ByteField, XByteField, ShortEnumField, ShortField, \
    ByteEnumField, IPField, StrFixedLenField, MACField, XBitField, PacketListField, IntField
from scapy.layers.inet import UDP
from scapy.packet import Packet, bind_layers, Padding, bind_bottom_up

# KNX CODES

SERVICE_IDENTIFIER_CODES = {
    0x0201: "SEARCH_REQUEST",
    0x0202: "SEARCH_RESPONSE",
    0x0203: "DESCRIPTION_REQUEST",
    0x0204: "DESCRIPTION_RESPONSE",
    0x0205: "CONNECT_REQUEST",
    0x0206: "CONNECT_RESPONSE",
    0x0207: "CONNECTIONSTATE_REQUEST",
    0x0208: "CONNECTIONSTATE_RESPONSE"
}

HOST_PROTOCOL_CODES = {
    0x01: "IPV4_UDP"
}

DESCRIPTION_TYPE_CODES = {
    0x01: "DEVICE_INFO",
    0x02: "SUPP_SVC_FAMILIES"
}

# uses only one code collection for connection type, differentiates between CRI and CRD tunneling in classes (!= BOF)
CONNECTION_TYPE_CODES = {
    0x03: "DEVICE_MANAGEMENT_CONNECTION",
    0x04: "TUNNELING_CONNECTION"
}


# KNX SPECIFIC FIELDS

class KNXAddressField(ShortField):
    def i2repr(self, pkt, x):
        if x is None:
            return None
        else:
            return "%d.%d.%d" % ((x >> 12) & 0xf, (x >> 8) & 0xf, (x & 0xff))

    def any2i(self, pkt, x):
        if type(x) is str:
            try:
                a, b, c = map(int, x.split("."))
                x = (a << 12) | (b << 8) | c
            except:
                raise ValueError(x)
        return ShortField.any2i(self, pkt, x)


# KNX BASE BLOCKS

class HPAI(Packet):
    name = "HPAI"
    fields_desc = [
        ByteField("structure_length", None),  # TODO: replace by a field that measures the packet length
        ByteEnumField("host_protocol_code", 0x01, HOST_PROTOCOL_CODES),
        IPField("ip_address", None),
        ShortField("ip_port", None)
    ]


class ServiceFamily(Packet):  # may better suit as a field ?
    name = "Service Family"
    fields_desc = [
        ByteField("id", None),
        ByteField("version", None)
    ]


# DIB are differentiated using the "description_type_code" field
# Defining a generic DIB packet and differentiating with `dispatch_hook` or `MultipleTypeField` may better fit KNX specs
class DIBDeviceInfo(Packet):
    name = "DIB: DEVICE_INFO"
    fields_desc = [
        ByteField("structure_length", None),  # TODO: replace by a field that measures the packet length
        ByteEnumField("description_type", 0x01, DESCRIPTION_TYPE_CODES),
        ByteField("knx_medium", None),  # may be replaced by a ByteEnumField ?
        ByteField("device_status", None),
        KNXAddressField("knx_address", None),  # TODO: replace with a custom field defining a KNX address
        ShortField("project_installation_identifier", None),
        XBitField("device_serial_number", None, 48),
        IPField("device_multicast_address", None),
        MACField("device_mac_address", None),
        StrFixedLenField("device_friendly_name", None, 30)
    ]


class DIBSuppSvcFamilies(Packet):
    name = "DIB: SUPP_SVC_FAMILIES"
    fields_desc = [
        ByteField("structure_length", None),  # TODO: replace by a field that measures the packet length
        ByteEnumField("description_type", 0x02, DESCRIPTION_TYPE_CODES),
        # can the service family number be 0 ?
        PacketListField("service_family", ServiceFamily(), ServiceFamily, length_from=lambda pkt: pkt.structure_length)
    ]


class DeviceManagementConnection(Packet):
    name = "Device Management Connection"
    fields_desc = [
        IntField("ip_address_1", None),
        ByteField("port_1", None),
        IntField("ip_address_2", None),
        ByteField("port_2", None)
    ]


class TunnelingConnection(Packet):
    name = "Tunneling Connection"
    fields_desc = [
        ByteField("knx_layer", 0x02),
        ByteField("reserved", None)
    ]


class CRDTunnelingConnection(Packet):
    name = "CRD Tunneling Connection"
    fields_desc = [
        KNXAddressField("knx_individual_address", None)
    ]


class CRI(Packet):
    name = "CRI (Connection Request Information)"
    fields_desc = [
        ByteField("structure_length", 0x00),
        ByteEnumField("connection_type", 0x03, {
            0x03: "DEVICE_MANAGEMENT_CONNECTION",
            0x04: "TUNNELING_CONNECTION"
        }),
        MultipleTypeField(
            [
                # TODO: see if better way than "pkt.structure_length > 0x02" to check if a body is present
                (PacketField("connection_data", DeviceManagementConnection(), DeviceManagementConnection),
                 lambda pkt: pkt.connection_type == 0x03 and pkt.structure_length > 0x02),
                (PacketField("connection_data", TunnelingConnection(), TunnelingConnection),
                 lambda pkt: pkt.connection_type == 0x04 and pkt.structure_length > 0x02)
            ],
            PacketField("connection_data", None, ByteField)  # if no identifier matches then return no connection_data
        )

    ]


class CRD(Packet):
    name = "CRD (Connection Response Data)"
    fields_desc = [
        ByteField("structure_length", 0x00),
        ByteEnumField("connection_type", 0x03, {
            0x03: "DEVICE_MANAGEMENT_CONNECTION",
            0x04: "TUNNELING_CONNECTION"
        }),
        MultipleTypeField(
            [
                # TODO: see if better way than "pkt.structure_length > 0x02" to check if a body is present
                (PacketField("connection_data", DeviceManagementConnection(), DeviceManagementConnection),
                 lambda pkt: pkt.connection_type == 0x03 and pkt.structure_length > 0x02),
                (PacketField("connection_data", CRDTunnelingConnection(), CRDTunnelingConnection),
                 lambda pkt: pkt.connection_type == 0x04 and pkt.structure_length > 0x02)
            ],
            PacketField("connection_data", None, ByteField)  # if no identifier matches then return no connection_data
        )
    ]


# KNX SERVICES

class KNXSearchRequest(Packet):  # TODO: test (no pcap yet)
    name = "SEARCH_REQUEST",
    fields_desc = [
        PacketField("discovery_endpoint", HPAI(), HPAI)
    ]


class KNXSearchResponse(Packet):  # TODO: test (no pcap yet)
    name = "SEARCH_RESPONSE",
    fields_desc = [
        PacketField("control_endpoint", HPAI(), HPAI),
        PacketField("device_info", DIBDeviceInfo(), DIBDeviceInfo),
        PacketField("supported_service_families", DIBSuppSvcFamilies(), DIBSuppSvcFamilies)
    ]


class KNXDescriptionRequest(Packet):
    name = "DESCRIPTION_REQUEST"
    fields_desc = [
        PacketField("control_endpoint", HPAI(), HPAI)
    ]


class KNXDescriptionResponse(Packet):
    name = "DESCRIPTION_RESPONSE"
    fields_desc = [
        PacketField("device_info", DIBDeviceInfo(), DIBDeviceInfo),
        PacketField("supported_service_families", DIBSuppSvcFamilies(), DIBSuppSvcFamilies)
        # TODO: optional field in KNX specs, add conditions to take it into account
        # PacketField("other_device_info", DIBDeviceInfo(), DIBDeviceInfo)
    ]


class KNXConnectRequest(Packet):   # TODO: test with complex CRI (no pcap yet)
    name = "CONNECT_REQUEST"
    fields_desc = [
        PacketField("control_endpoint", HPAI(), HPAI),
        PacketField("data_endpoint", HPAI(), HPAI),
        PacketField("connection_request_information", CRI(), CRI)
    ]


class KNXConnectResponse(Packet):  # TODO: test with complex CRD (no pcap yet)
    name = "CONNECT_RESPONSE"
    fields_desc = [
        ByteField("communication_channel_id", None),
        ByteField("status", None),  # TODO: add ByteEnumField with status list (see KNX specifications)
        PacketField("data_endpoint", HPAI(), HPAI),
        PacketField("connection_response_data_block", CRD(), CRD)
    ]


class KNXConnectionstateRequest(Packet):  # TODO: test (no pcap yet)
    name = "CONNECTIONSTATE_REQUEST"
    fields_desc = [
        ByteField("communication_channel_id", None),
        ByteField("reserved", None),
        PacketField("control_endpoint", HPAI(), HPAI)
    ]


class KNXConnectionstateResponse(Packet):  # TODO: test (no pcap yet)
    name = "CONNECTIONSTATE_RESPONSE"
    fields_desc = [
        ByteField("communication_channel_id", None),
        ByteField("status", 0x00)
    ]


# KNX FRAME

class KNXHeader(Packet):
    name = "Header"
    fields_desc = [
        ByteField("header_length", None),  # TODO: replace by a field that measures the packet length
        XByteField("protocol_version", 0x10),
        ShortEnumField("service_identifier", None, SERVICE_IDENTIFIER_CODES),
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
                (PacketField("body", KNXSearchRequest(), KNXSearchRequest),
                 lambda pkt: pkt.header.service_identifier == 0x0201),
                (PacketField("body", KNXSearchResponse(), KNXSearchResponse),
                 lambda pkt: pkt.header.service_identifier == 0x0202),
                (PacketField("body", KNXDescriptionRequest(), KNXDescriptionRequest),
                 lambda pkt: pkt.header.service_identifier == 0x0203),
                (PacketField("body", KNXDescriptionResponse(), KNXDescriptionResponse),
                 lambda pkt: pkt.header.service_identifier == 0x0204),
                (PacketField("body", KNXConnectRequest(), KNXConnectRequest),
                 lambda pkt: pkt.header.service_identifier == 0x0205),
                (PacketField("body", KNXConnectResponse(), KNXConnectResponse),
                 lambda pkt: pkt.header.service_identifier == 0x0206),
                (PacketField("body", KNXConnectionstateRequest(), KNXConnectionstateRequest),
                 lambda pkt: pkt.header.service_identifier == 0x0207),
                (PacketField("body", KNXConnectionstateResponse(), KNXConnectionstateResponse),
                 lambda pkt: pkt.header.service_identifier == 0x0208)

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
bind_layers(ServiceFamily, Padding)
bind_layers(DIBDeviceInfo, Padding)
bind_layers(DIBSuppSvcFamilies, Padding)
bind_layers(DeviceManagementConnection, Padding)
bind_layers(TunnelingConnection, Padding)
bind_layers(CRDTunnelingConnection, Padding)
bind_layers(CRI, Padding)
bind_layers(CRD, Padding)

bind_layers(KNXSearchRequest, Padding)
bind_layers(KNXSearchResponse, Padding)
bind_layers(KNXDescriptionRequest, Padding)
bind_layers(KNXDescriptionResponse, Padding)
bind_layers(KNXConnectRequest, Padding)
bind_layers(KNXConnectResponse, Padding)
bind_layers(KNXConnectionstateRequest, Padding)
bind_layers(KNXConnectionstateResponse, Padding)

bind_layers(KNXHeader, Padding)
