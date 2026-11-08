"""Owned usbmux handshake fixture and metadata-only pcapng inspection."""
import json
import os
import plistlib
import socket
import struct
import sys
import time


def read_exact(stream, length):
    result = b""
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise EOFError("service closed connection")
        result += part
    return result


def exchange(stream, message):
    body = plistlib.dumps(message)
    stream.sendall(struct.pack("<IIII", len(body) + 16, 1, 8, 1) + body)
    size, version, kind, tag = struct.unpack("<IIII", read_exact(stream, 16))
    if not 16 <= size <= 1048576 or (version, kind, tag) != (1, 8, 1):
        raise ValueError("invalid frame")
    return plistlib.loads(read_exact(stream, size - 16))


def fixture():
    with socket.create_connection(("127.0.0.1", 27015), 2) as service:
        service.settimeout(2)
        devices = exchange(service, {"MessageType": "ListDevices", "ProgName": "SafeDetach"})["DeviceList"]
    if len(devices) != 2:
        raise ValueError("This experiment requires exactly two connected devices")
    sockets = []
    try:
        targets = []
        for device in devices:
            stream = socket.socket()
            stream.settimeout(2)
            stream.bind(("127.0.0.1", 0))
            sockets.append(stream)
            targets.append({"port": stream.getsockname()[1], "device_id": device["DeviceID"]})
        print(json.dumps({"pid": os.getpid(), "targets": targets}), flush=True)
        if sys.stdin.readline().strip() != "continue":
            raise ValueError("capture not armed")
        for stream, target in zip(sockets, targets):
            stream.connect(("127.0.0.1", 27015))
            reply = exchange(stream, {"MessageType": "Connect", "DeviceID": target["device_id"], "PortNumber": socket.htons(62078), "ProgName": "SafeDetach", "kLibUSBMuxVersion": 3})
            target["result"] = reply.get("Number")
        print(json.dumps({"targets": targets}), flush=True)
        time.sleep(min(5, max(0, float(os.environ.get("SAFEDETACH_FIXTURE_HOLD_MS", "0")) / 1000)))
    finally:
        for stream in sockets:
            stream.close()


def handshake(packet, link):
    """Parse one complete test request; intentionally not a TCP stream decoder."""
    start = {1: 14, 101: 0, 0: 4, 108: 4, 113: 16}.get(link)
    if start is None or len(packet) < start + 40:
        return None
    if packet[start] >> 4 != 4 or packet[start + 9] != 6:
        return None
    ip_length = (packet[start] & 15) * 4
    total = struct.unpack_from("!H", packet, start + 2)[0]
    fragment = struct.unpack_from("!H", packet, start + 6)[0]
    tcp = start + ip_length
    end = start + total
    if ip_length < 20 or total < ip_length + 20 or end > len(packet) or fragment & 0x3fff:
        return None
    source, destination = struct.unpack_from("!HH", packet, tcp)
    tcp_length = (packet[tcp + 12] >> 4) * 4
    if destination != 27015 or tcp_length < 20 or tcp + tcp_length > end:
        return None
    payload = packet[tcp + tcp_length:end]
    if len(payload) < 16:
        return None
    length, version, message, _ = struct.unpack_from("<IIII", payload)
    if version != 1 or message != 8 or not 16 < length <= len(payload):
        return None
    try:
        body = plistlib.loads(payload[16:length])
        if body.get("MessageType") == "Connect" and type(body.get("DeviceID")) is int:
            return source, body["DeviceID"]
    except (ValueError, TypeError, AttributeError, plistlib.InvalidFileException):
        pass
    return None


def self_test():
    body = plistlib.dumps({"MessageType": "Connect", "DeviceID": 8})
    request = struct.pack("<IIII", 16 + len(body), 1, 8, 1) + body
    ip = bytearray(20)
    ip[0], ip[9] = 0x45, 6
    struct.pack_into("!H", ip, 2, 40 + len(request))
    tcp = bytearray(20)
    struct.pack_into("!HH", tcp, 0, 50825, 27015)
    tcp[12] = 0x50
    raw = bytes(ip + tcp) + request
    for link, header in ((101, b""), (0, struct.pack("<I", 2)),
                         (108, struct.pack("!I", 2)), (1, bytes(14)), (113, bytes(16))):
        assert handshake(header + raw, link) == (50825, 8)
        assert handshake(header + raw[:-1], link) is None
    wrong_port = bytearray(raw)
    struct.pack_into("!H", wrong_port, 22, 27016)
    assert handshake(wrong_port, 101) is None
    malformed = raw[:40] + bytes(len(request))
    assert handshake(malformed, 101) is None
    assert handshake(bytes(40), 999) is None
    print("PASS: complete Connect frames, link types, truncation, wrong port and invalid frames")


def inspect(path):
    data = open(path, "rb").read()
    offset = 0
    links = []
    found = set()
    packets = 0
    while offset + 12 <= len(data):
        kind, size = struct.unpack_from("<II", data, offset)
        if size < 12 or offset + size > len(data):
            raise ValueError("invalid capture block")
        if kind == 1:
            links.append(struct.unpack_from("<H", data, offset + 8)[0])
        if kind == 6:
            packets += 1
            interface, _, _, captured, _ = struct.unpack_from("<IIIII", data, offset + 8)
            packet = data[offset + 28:offset + 28 + captured]
            result = handshake(packet, links[interface])
            if result is not None:
                found.add(result)
        offset += size
    print(json.dumps({"packet_count": packets, "observed_handshakes": [{"port": p, "device_id": d} for p, d in sorted(found)]}))


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    elif len(sys.argv) == 3 and sys.argv[1] == "inspect":
        inspect(sys.argv[2])
    else:
        fixture()
