import asyncio
import struct
from src.database import log_event
from src.mac_lookup import get_mac_for_ip


# SNMP BER/ASN.1 constants
ASN1_SEQUENCE = 0x30
ASN1_INTEGER = 0x02
ASN1_OCTET_STRING = 0x04
ASN1_NULL = 0x05
ASN1_OID = 0x06
ASN1_GET_REQUEST = 0xA0
ASN1_GET_NEXT_REQUEST = 0xA1
ASN1_GET_RESPONSE = 0xA2
ASN1_SET_REQUEST = 0xA3

# Siemens building controller OID responses
OID_RESPONSES = {
    "1.3.6.1.2.1.1.1.0": ("Siemens DESIGO CC Building Automation Controller v5.0", ASN1_OCTET_STRING),
    "1.3.6.1.2.1.1.2.0": ("1.3.6.1.4.1.4329.1.1.1", ASN1_OID),
    "1.3.6.1.2.1.1.3.0": ("4729812", ASN1_INTEGER),  # uptime in hundredths of seconds
    "1.3.6.1.2.1.1.4.0": ("facilities@corp.local", ASN1_OCTET_STRING),
    "1.3.6.1.2.1.1.5.0": ("DESIGO-CC-01", ASN1_OCTET_STRING),
    "1.3.6.1.2.1.1.6.0": ("Building A, Floor 3, Server Room", ASN1_OCTET_STRING),
    "1.3.6.1.2.1.1.7.0": ("72", ASN1_INTEGER),
    "1.3.6.1.2.1.2.1.0": ("4", ASN1_INTEGER),  # number of interfaces
    "1.3.6.1.2.1.2.2.1.1.1": ("1", ASN1_INTEGER),
    "1.3.6.1.2.1.2.2.1.2.1": ("eth0", ASN1_OCTET_STRING),
    "1.3.6.1.2.1.2.2.1.3.1": ("6", ASN1_INTEGER),  # ethernetCsmacd
    "1.3.6.1.2.1.2.2.1.5.1": ("1000000000", ASN1_INTEGER),  # 1 Gbps
}

SORTED_OIDS = sorted(OID_RESPONSES.keys())


def encode_length(length):
    if length < 128:
        return bytes([length])
    elif length < 256:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def encode_integer(value):
    val = int(value)
    if val == 0:
        return bytes([ASN1_INTEGER, 1, 0])
    result = []
    negative = val < 0
    if negative:
        val = -val - 1
    while val > 0:
        result.insert(0, val & 0xFF)
        val >>= 8
    if not negative and result[0] & 0x80:
        result.insert(0, 0)
    if negative:
        result = [b ^ 0xFF for b in result]
    return bytes([ASN1_INTEGER]) + encode_length(len(result)) + bytes(result)


def encode_octet_string(value):
    data = value.encode() if isinstance(value, str) else value
    return bytes([ASN1_OCTET_STRING]) + encode_length(len(data)) + data


def encode_oid(oid_str):
    parts = [int(x) for x in oid_str.split(".")]
    if len(parts) < 2:
        return bytes([ASN1_OID, 0])
    encoded = [parts[0] * 40 + parts[1]]
    for part in parts[2:]:
        if part < 128:
            encoded.append(part)
        else:
            tmp = []
            while part > 0:
                tmp.insert(0, part & 0x7F)
                part >>= 7
            for i in range(len(tmp) - 1):
                tmp[i] |= 0x80
            encoded.extend(tmp)
    return bytes([ASN1_OID]) + encode_length(len(encoded)) + bytes(encoded)


def encode_null():
    return bytes([ASN1_NULL, 0])


def encode_sequence(data):
    return bytes([ASN1_SEQUENCE]) + encode_length(len(data)) + data


def decode_oid(data, offset):
    length = data[offset + 1]
    oid_bytes = data[offset + 2:offset + 2 + length]
    if not oid_bytes:
        return "", offset + 2
    parts = [oid_bytes[0] // 40, oid_bytes[0] % 40]
    i = 1
    while i < len(oid_bytes):
        val = 0
        while i < len(oid_bytes):
            val = (val << 7) | (oid_bytes[i] & 0x7F)
            if not (oid_bytes[i] & 0x80):
                i += 1
                break
            i += 1
        parts.append(val)
    return ".".join(str(p) for p in parts), offset + 2 + length


def decode_length(data, offset):
    if data[offset] < 128:
        return data[offset], offset + 1
    num_bytes = data[offset] & 0x7F
    length = 0
    for i in range(num_bytes):
        length = (length << 8) | data[offset + 1 + i]
    return length, offset + 1 + num_bytes


def parse_snmp_request(data):
    try:
        if data[0] != ASN1_SEQUENCE:
            return None
        _, offset = decode_length(data, 1)

        # Version
        if data[offset] != ASN1_INTEGER:
            return None
        ver_len = data[offset + 1]
        version = data[offset + 2]
        offset += 2 + ver_len

        # Community string
        if data[offset] != ASN1_OCTET_STRING:
            return None
        com_len = data[offset + 1]
        community = data[offset + 2:offset + 2 + com_len].decode("utf-8", errors="ignore")
        offset += 2 + com_len

        # PDU type
        pdu_type = data[offset]
        _, pdu_offset = decode_length(data, offset + 1)

        # Request ID
        if data[pdu_offset] != ASN1_INTEGER:
            return None
        rid_len = data[pdu_offset + 1]
        request_id_bytes = data[pdu_offset + 2:pdu_offset + 2 + rid_len]
        request_id = int.from_bytes(request_id_bytes, "big", signed=True)
        pdu_offset += 2 + rid_len

        # Error status + index (skip)
        for _ in range(2):
            skip_len = data[pdu_offset + 1]
            pdu_offset += 2 + skip_len

        # Varbind list
        oids = []
        if data[pdu_offset] == ASN1_SEQUENCE:
            _, vb_offset = decode_length(data, pdu_offset + 1)
            while vb_offset < len(data) - 2:
                if data[vb_offset] != ASN1_SEQUENCE:
                    break
                _, item_offset = decode_length(data, vb_offset + 1)
                if data[item_offset] == ASN1_OID:
                    oid_str, _ = decode_oid(data, item_offset)
                    oids.append(oid_str)
                vb_offset = item_offset + data[item_offset + 1] + 2
                # Skip the value part
                if vb_offset < len(data) and data[vb_offset] in (ASN1_NULL, ASN1_INTEGER, ASN1_OCTET_STRING, ASN1_OID):
                    vb_offset += 2 + (data[vb_offset + 1] if vb_offset + 1 < len(data) else 0)

        return {
            "version": version,
            "community": community,
            "pdu_type": pdu_type,
            "request_id": request_id,
            "oids": oids,
        }
    except (IndexError, ValueError):
        return None


def build_snmp_response(request_id, community, oid_str, value, value_type):
    # Encode the value
    if value_type == ASN1_INTEGER:
        encoded_value = encode_integer(value)
    elif value_type == ASN1_OID:
        encoded_value = encode_oid(value)
    else:
        encoded_value = encode_octet_string(value)

    # Varbind
    encoded_oid = encode_oid(oid_str)
    varbind = encode_sequence(encoded_oid + encoded_value)
    varbind_list = encode_sequence(varbind)

    # Request ID
    rid_encoded = encode_integer(request_id)
    error_status = encode_integer(0)
    error_index = encode_integer(0)

    pdu_content = rid_encoded + error_status + error_index + varbind_list
    pdu = bytes([ASN1_GET_RESPONSE]) + encode_length(len(pdu_content)) + pdu_content

    # Version
    version = encode_integer(0)  # SNMPv1
    comm = encode_octet_string(community)

    message = encode_sequence(version + comm + pdu)
    return message


class SNMPProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        ip, port = addr
        mac = get_mac_for_ip(ip)

        parsed = parse_snmp_request(data)
        if not parsed:
            return

        asyncio.get_event_loop().create_task(log_event(
            service="snmp",
            source_ip=ip,
            source_port=port,
            action="snmp_request",
            mac_address=mac,
            data={
                "community": parsed["community"],
                "version": parsed["version"],
                "pdu_type": hex(parsed["pdu_type"]),
                "oids": parsed["oids"],
            },
        ))

        # Respond to each OID
        for oid in parsed["oids"]:
            lookup_oid = oid
            if parsed["pdu_type"] == ASN1_GET_NEXT_REQUEST:
                # Find next OID
                for sorted_oid in SORTED_OIDS:
                    if sorted_oid > oid:
                        lookup_oid = sorted_oid
                        break
                else:
                    continue

            if lookup_oid in OID_RESPONSES:
                value, vtype = OID_RESPONSES[lookup_oid]
                response = build_snmp_response(
                    parsed["request_id"], parsed["community"],
                    lookup_oid, value, vtype
                )
                self.transport.sendto(response, addr)


async def start_snmp_service(host="0.0.0.0", port=161):
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        SNMPProtocol,
        local_addr=(host, port),
    )
    print(f"[resin] SNMP service listening on {host}:{port}/udp")
    return transport
