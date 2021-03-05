from scapy.fields import PacketField, MultipleTypeField, ByteField, XByteField, ShortEnumField, ShortField, \
    ByteEnumField, IPField, StrFixedLenField, MACField, XBitField, PacketListField, IntField, FieldLenField, \
    StrLenField, BitEnumField, BitField
from scapy.layers.inet import UDP
from scapy.packet import Packet, bind_layers, Padding, bind_bottom_up

### KNX CODES

SERVICE_IDENTIFIER_CODES = {
    0x0201: "SEARCH_REQUEST",
    0x0202: "SEARCH_RESPONSE",
    0x0203: "DESCRIPTION_REQUEST",
    0x0204: "DESCRIPTION_RESPONSE",
    0x0205: "CONNECT_REQUEST",
    0x0206: "CONNECT_RESPONSE",
    0x0207: "CONNECTIONSTATE_REQUEST",
    0x0208: "CONNECTIONSTATE_RESPONSE",
    0x0209: "DISCONNECT_REQUEST",
    0x020A: "DISCONNECT_RESPONSE",
    0x0310: "CONFIGURATION_REQUEST",
    0x0311: "CONFIGURATION_ACK",
    0x0420: "TUNNELING_REQUEST",
    0x0421: "TUNNELING_ACK"
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

MESSAGE_CODES = {
    0x11: "L_Data.req",
    0x2e: "L_Data.con",
    0xFC: "PropRead.req",
    0xFB: "PropRead.con",
    0xF6: "PropWrite.req",
    0xF5: "PropWrite.con"
}


### KNX SPECIFIC FIELDS

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


class KNXGroupField(ShortField):
    def i2repr(self, pkt, x):
        return "%d/%d/%d" % ((x >> 11) & 0x1f, (x >> 8) & 0x7, (x & 0xff))

    def any2i(self, pkt, x):
        if type(x) is str:
            try:
                a, b, c = map(int, x.split("/"))
                x = (a << 11) | (b << 8) | c
            except:
                raise ValueError(x)
        return ShortField.any2i(self, pkt, x)


### KNX BASE BLOCKS

class HPAI(Packet):
    name = "HPAI"
    fields_desc = [
        ByteField("structure_length", None),  # TODO: replace by a field that measures the packet length
        ByteEnumField("host_protocol", 0x01, HOST_PROTOCOL_CODES),
        IPField("ip_address", None),
        ShortField("ip_port", None)
    ]


# DIB blocks

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
        KNXAddressField("knx_address", None),
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


# CRI and CRD blocks

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


# cEMI blocks

class LcEMI(Packet):
    name = "L_cEMI"
    fields_desc = [
        FieldLenField("additional_information_length", 0, fmt="B", length_of="additional_information"),  # TODO: replace with a field equals to the length info
        StrLenField("additional_information", None, length_from=lambda pkt: pkt.additional_information_length),
        # Controlfield 1 (1 byte made of 8*1 bits)
        BitEnumField("frame_type", 1, 1, {
            1: "standard"
        }),
        BitField("reserved", 0, 1),
        BitField("repeat_on_error", 1, 1),
        BitEnumField("broadcast_type", 1, 1, {
            1: "domain"
        }),
        BitEnumField("priority", 3, 2, {
            3: "low"
        }),
        BitField("ack_request", 0, 1),
        BitField("confirmation_error", 0, 1),
        # Controlfield 2 (1 byte made of 1+3+4 bits)
        BitEnumField("address_type", 1, 1, {
            1: "group"
        }),
        BitField("hop_count", 6, 3),
        BitField("extended_frame_format", 0, 4),
        KNXAddressField("source_address", None),
        KNXGroupField("destination_address", "1/2/3"),
        FieldLenField("npdu_length", 0x01, fmt="B", length_of="data"),
        # TPCI and APCI (2 byte made of 1+1+4+4+6 bits)
        BitEnumField("packet_type", 0, 1, {
            0: "data"
        }),
        BitEnumField("sequence_type", 0, 1, {
            0: "unnumbered"
        }),
        BitField("reserved2", 0, 4),
        BitEnumField("acpi", 2, 4, {
            2: "GroupValueWrite"
        }),
        BitField("reserved3", 0, 6),
        # TODO: test that data is correctly used from "npdu_length"
        StrLenField("data", None, length_from=lambda pkt: pkt.information_length)

    ]


class DPcEMI(Packet):
    name = "DP_cEMI"
    fields_desc = [
        # TODO: see if best representation is str or hex
        ShortField("object_type", None),
        ByteField("object_instance", None),
        ByteField("property_id", None),
        BitField("number_of_elements", None, 4),
        BitField("start_index", None, 12)
    ]


class LDataReq(Packet):
    name = "L_Data.req"
    fields_desc = [
        PacketField("L_Data.req", LcEMI(), LcEMI)
    ]


class LDataCon(Packet):
    name = "L_Data.con"
    fields_desc = [
        PacketField("L_Data.con", LcEMI(), LcEMI)
    ]


class PropReadReq(Packet):
    name = "PropRead.req"
    fields_desc = [
        PacketField("PropRead.req", DPcEMI(), DPcEMI)
    ]


class PropReadCon(Packet):
    name = "PropRead.con"
    fields_desc = [
        PacketField("PropRead.con", DPcEMI(), DPcEMI)
    ]


class PropWriteReq(Packet):
    name = "PropWrite.req"
    fields_desc = [
        PacketField("PropWrite.req", DPcEMI(), DPcEMI)
    ]


class PropWriteCon(Packet):
    name = "PropWrite.con"
    fields_desc = [
        PacketField("PropWrite.con", DPcEMI(), DPcEMI)
    ]


class CEMI(Packet):
    name = "CEMI"
    fields_desc = [
        ByteEnumField("message_code", None, MESSAGE_CODES),
        MultipleTypeField(
            [
                (PacketField("cemi_data", LDataReq(), LDataReq), lambda pkt: pkt.message_code == 0x11),
                (PacketField("cemi_data", LDataCon(), LDataCon), lambda pkt: pkt.message_code == 0x2e),
                (PacketField("cemi_data", PropReadReq(), PropReadReq), lambda pkt: pkt.message_code == 0xFC),
                (PacketField("cemi_data", PropReadCon(), PropReadCon), lambda pkt: pkt.message_code == 0xFB),
                (PacketField("cemi_data", PropWriteReq(), PropWriteReq), lambda pkt: pkt.message_code == 0xF6),
                (PacketField("cemi_data", PropWriteCon(), PropWriteCon), lambda pkt: pkt.message_code == 0xF5)
            ],
            PacketField("cemi_data", None, ByteField)  # if no identifier matches then return no cemi_data
        )
    ]


### KNX SERVICES

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


class KNXConnectRequest(Packet):  # TODO: test with complex CRI (no pcap yet)
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
        ByteField("status", 0x00)  # TODO: add ByteEnumField with status list (see KNX specifications)
    ]


class KNXDisconnectRequest(Packet):
    name = "DISCONNECT_REQUEST"
    fields_desc = [
        ByteField("communication_channel_id", 0x01),
        ByteField("reserved", None),
        PacketField("control_endpoint", HPAI(), HPAI)
    ]


class KNXDisconnectResponse(Packet):
    name = "DISCONNECT_RESPONSE"
    fields_desc = [
        ByteField("communication_channel_id", None),
        ByteField("status", 0x00)  # TODO: add ByteEnumField with status list (see KNX specifications)
    ]


class KNXConfigurationRequest(Packet):  # TODO: test with different cEMI payloads
    name = "CONFIGURATION_REQUEST"
    fields_desc = [
        ByteField("structure_length", 0x04),  # TODO: replace by a field that measures the packet length
        ByteField("communication_channel_id", 0x01),
        ByteField("sequence_counter", None),  # TODO: see where to actually handle KNX networking
        ByteField("reserved", None),
        PacketField("cemi", CEMI(), CEMI)
    ]


class KNXConfigurationACK(Packet):  # TODO: test with different cEMI payloads
    name = "CONFIGURATION_ACK"
    fields_desc = [
        ByteField("structure_length", None),  # TODO: replace by a field that measures the packet length
        ByteField("communication_channel_id", 0x01),
        ByteField("sequence_counter", None),  # TODO: see where to actually handle KNX networking
        ByteField("status", None)  # TODO: add ByteEnumField with status list (see KNX specifications)
    ]


class KNXTunnelingRequest(Packet):  # TODO: test with different cEMI payloads
    name = "TUNNELING_REQUEST"
    fields_desc = [
        ByteField("structure_length", 0x04),  # TODO: replace by a field that measures the packet length
        ByteField("communication_channel_id", 0x01),
        ByteField("sequence_counter", None),  # TODO: see where to actually handle KNX networking
        ByteField("reserved", None),
        PacketField("cemi", CEMI(), CEMI)
    ]


class KNXTunnelingACK(Packet):  # TODO: test with different cEMI payloads
    name = "TUNNELING_ACK"
    fields_desc = [
        ByteField("structure_length", None),  # TODO: replace by a field that measures the packet length
        ByteField("communication_channel_id", 0x01),
        ByteField("sequence_counter", None),  # TODO: see where to actually handle KNX networking
        ByteField("status", None)  # TODO: add ByteEnumField with status list (see KNX specifications)
    ]


### KNX FRAME

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
                 lambda pkt: pkt.header.service_identifier == 0x0208),
                (PacketField("body", KNXDisconnectRequest(), KNXDisconnectRequest),
                 lambda pkt: pkt.header.service_identifier == 0x0209),
                (PacketField("body", KNXDisconnectResponse(), KNXDisconnectResponse),
                 lambda pkt: pkt.header.service_identifier == 0x020A),
                (PacketField("body", KNXConfigurationRequest(), KNXConfigurationRequest),
                 lambda pkt: pkt.header.service_identifier == 0x0310),
                (PacketField("body", KNXConfigurationACK(), KNXConfigurationACK),
                 lambda pkt: pkt.header.service_identifier == 0x0311),
                (PacketField("body", KNXTunnelingRequest(), KNXTunnelingRequest),
                 lambda pkt: pkt.header.service_identifier == 0x0420),
                (PacketField("body", KNXTunnelingACK(), KNXTunnelingACK),
                 lambda pkt: pkt.header.service_identifier == 0x0421)
            ],
            PacketField("body", None, None)  # if no identifier matches then return an empty body
        )

    ]


### LAYERS BINDING

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
bind_layers(LcEMI, Padding)
bind_layers(DPcEMI, Padding)
bind_layers(LDataReq, Padding)
bind_layers(LDataCon, Padding)
bind_layers(PropReadReq, Padding)
bind_layers(PropReadCon, Padding)
bind_layers(PropWriteReq, Padding)
bind_layers(PropWriteCon, Padding)
bind_layers(CEMI, Padding)

bind_layers(KNXSearchRequest, Padding)
bind_layers(KNXSearchResponse, Padding)
bind_layers(KNXDescriptionRequest, Padding)
bind_layers(KNXDescriptionResponse, Padding)
bind_layers(KNXConnectRequest, Padding)
bind_layers(KNXConnectResponse, Padding)
bind_layers(KNXConnectionstateRequest, Padding)
bind_layers(KNXConnectionstateResponse, Padding)
bind_layers(KNXDisconnectRequest, Padding)
bind_layers(KNXDisconnectResponse, Padding)
bind_layers(KNXConfigurationRequest, Padding)
bind_layers(KNXConfigurationACK, Padding)
bind_layers(KNXTunnelingRequest, Padding)
bind_layers(KNXTunnelingACK, Padding)

bind_layers(KNXHeader, Padding)
