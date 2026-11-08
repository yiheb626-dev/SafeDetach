"""Fail-closed diagnostic for newly opened IPv4 USBMux connections.

Requires SYN, reassembled first Connect request, successful matching first reply,
and both live TCP endpoints owned by the client and the registered service.
Bounded TCP reassembly: missed or conflicting handshakes remain unassigned.
Only the first protocol frame in each direction is retained in memory. No raw logs.
"""
import ctypes as c
import importlib.util
import json
from pathlib import Path
import plistlib
import socket
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("mux_capture", Path(__file__).with_name("Probe-MuxNpcap.py"))
capture_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture_module)


def tcp_rows():
    api = c.WinDLL("iphlpapi.dll").GetExtendedTcpTable
    api.argtypes = [c.c_void_p, c.POINTER(c.c_uint32), c.c_bool, c.c_uint32, c.c_uint32, c.c_uint32]
    api.restype = c.c_uint32
    size = c.c_uint32()
    status = api(None, c.byref(size), False, 2, 5, 0)
    for _ in range(4):
        if status != 122:
            break
        buffer = c.create_string_buffer(size.value)
        status = api(buffer, c.byref(size), False, 2, 5, 0)
    if status:
        raise OSError(status, "Cannot enumerate TCP owners")
    raw = buffer.raw
    rows = []
    for offset in range(4, 4 + struct.unpack_from("<I", raw)[0] * 24, 24):
        state, local, lp, remote, rp, pid = struct.unpack_from("<6I", raw, offset)
        if local == 0x0100007f:
            rows.append((state, socket.ntohs(lp & 65535), remote, socket.ntohs(rp & 65535), pid))
    return rows


def client_owner(rows, port, service):
    if not any(state == 2 and lp == 27015 and pid == service for state, lp, _, _, pid in rows):
        return None
    clients = {pid for state, lp, remote, rp, pid in rows
               if state == 5 and lp == port and rp == 27015 and remote == 0x0100007f}
    paired = any(state == 5 and lp == 27015 and rp == port and remote == 0x0100007f and pid == service
                 for state, lp, remote, rp, pid in rows)
    return next(iter(clients)) if paired and len(clients) == 1 else None


def packet_parts(raw, link):
    start = {0: 4, 1: 14, 101: 0, 108: 4, 113: 16}[link]
    if len(raw) < start + 40 or raw[start] >> 4 != 4 or raw[start + 9] != 6:
        return None
    length = struct.unpack_from("!H", raw, start + 2)[0]
    ip_length = (raw[start] & 15) * 4
    if ip_length < 20 or length < ip_length + 20 or start + length > len(raw):
        return None
    if struct.unpack_from("!H", raw, start + 6)[0] & 0x3fff:
        return None
    tcp = start + ip_length
    tcp_length = (raw[tcp + 12] >> 4) * 4
    if tcp_length < 20 or ip_length + tcp_length > length:
        return None
    source, destination, seq = struct.unpack_from("!HHI", raw, tcp)
    return source, destination, seq, raw[tcp + 13], raw[tcp + tcp_length:start + length]


def mux_frame(payload):
    if len(payload) < 16:
        return None
    length, version, kind, tag = struct.unpack_from("<4I", payload)
    if not 16 <= length <= len(payload):
        return None
    if version == 0 and kind == 2 and length == 24:
        return "Connect", tag, struct.unpack_from("<I", payload, 16)[0]
    if version == 0 and kind == 1 and length == 20:
        return "Result", tag, struct.unpack_from("<I", payload, 16)[0]
    if version == 1 and kind == 8:
        try:
            body = plistlib.loads(payload[16:length])
            kind = body.get("MessageType")
            value = body.get("DeviceID") if kind == "Connect" else body.get("Number")
            if kind in ("Connect", "Result") and type(value) is int:
                return kind, tag, value
        except (ValueError, AttributeError, TypeError, plistlib.InvalidFileException):
            pass
    return None


class FirstFrame:
    def __init__(self, sequence):
        self.sequence = sequence
        self.data = bytearray()
        self.pending = {}
        self.done = False

    def feed(self, sequence, data):
        if self.done:
            return None
        offset = (sequence - self.sequence) & 0xffffffff
        if offset > 65536 or offset + len(data) > 65536 or len(self.pending) > 64:
            raise ValueError("Handshake exceeds reassembly bounds")
        if offset in self.pending and self.pending[offset] != data:
            raise ValueError("Conflicting retransmission")
        self.pending[offset] = data
        for position in sorted(self.pending):
            if position > len(self.data):
                break
            part = self.pending.pop(position)
            overlap = min(len(part), len(self.data) - position)
            if self.data[position:position + overlap] != part[:overlap]:
                raise ValueError("Conflicting stream overlap")
            self.data.extend(part[overlap:])
        if len(self.data) < 16:
            return None
        length = struct.unpack_from("<I", self.data)[0]
        if not 16 <= length <= 65536:
            raise ValueError("Invalid handshake frame length")
        if len(self.data) >= length:
            self.done = True
            result = bytes(self.data[:length])
            self.data.clear()
            self.pending.clear()
            return result
        return None


def devices():
    with socket.create_connection(("127.0.0.1", 27015), 2) as service:
        service.settimeout(2)
        response = capture_module.fixture_module.exchange(service, {"MessageType": "ListDevices", "ProgName": "SafeDetach"})
    return [{"device_id": item["DeviceID"], "product_id": item["Properties"].get("ProductID")}
            for item in response["DeviceList"]]


def watch(service, seconds):
    mapping = devices()
    rows = tcp_rows()
    if not any(state == 2 and lp == 27015 and pid == service for state, lp, _, _, pid in rows):
        raise RuntimeError("Registered Apple service is not the loopback listener")
    api = capture_module.load_api()
    capture, link = capture_module.open_capture(api, b"ip and tcp and src host 127.0.0.1 and dst host 127.0.0.1 and port 27015")
    flows = {}
    confirmed = []
    try:
        print(json.dumps({"ready": True, "devices": mapping,
                          "existing_clients": len({pid for state, _, _, rp, pid in rows if state == 5 and rp == 27015})}), flush=True)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            header, packet = c.POINTER(capture_module.PacketHeader)(), c.POINTER(c.c_ubyte)()
            result = api.pcap_next_ex(capture, c.byref(header), c.byref(packet))
            if result == 0:
                time.sleep(0.01)
                continue
            if result != 1:
                raise RuntimeError("Npcap capture failed")
            parts = packet_parts(c.string_at(packet, min(1024, header.contents.captured)), link)
            if not parts:
                continue
            source, destination, seq, flags, payload = parts
            port = source if destination == 27015 else destination
            now = time.monotonic()
            flows = {p: f for p, f in flows.items() if now - f["time"] < 5}
            if destination == 27015 and flags & 0x12 == 0x02:
                if port not in flows:
                    flows[port] = {"out": FirstFrame((seq + 1) & 0xffffffff), "time": now}
                continue
            flow = flows.get(port)
            if flow is None:
                continue  # Started before observation: deliberately never inspect its payload.
            if source == 27015 and flags & 0x12 == 0x12:
                if "in" not in flow:
                    flow["in"] = FirstFrame((seq + 1) & 0xffffffff)
                continue
            if not payload:
                if flags & 5:
                    flows.pop(port, None)
                continue
            stream = flow.get("out" if destination == 27015 else "in")
            if stream is None:
                flows.pop(port, None)
                continue
            try:
                complete = stream.feed(seq, payload)
            except ValueError:
                flows.pop(port, None)
                continue
            if complete is None:
                continue
            frame = mux_frame(complete)
            if destination == 27015:
                if frame is None or frame[0] != "Connect":
                    flows.pop(port, None)
                    continue
                pid = client_owner(tcp_rows(), port, service)
                if pid is None:
                    flows.pop(port, None)
                    continue
                flow.update(tag=frame[1], device=frame[2], pid=pid)
            elif "device" in flow:
                if frame == ("Result", flow["tag"], 0):
                    pid = client_owner(tcp_rows(), port, service)
                    if pid == flow["pid"]:
                        event = {"pid": pid, "port": port, "device_id": flow["device"], "successful_new_connection": True}
                        confirmed.append(event)
                        print(json.dumps(event), flush=True)
                flows.pop(port, None)
        print(json.dumps({"completed": True, "confirmed_connections": len(confirmed)}), flush=True)
    finally:
        api.pcap_close(capture)


def self_test():
    for version in (0, 1):
        for kind, value in (("Connect", 8), ("Result", 0)):
            if version:
                body = plistlib.dumps({"MessageType": kind, "DeviceID" if kind == "Connect" else "Number": value})
                message = 8
            else:
                body = struct.pack("<I", value) + (bytes(4) if kind == "Connect" else b"")
                message = 2 if kind == "Connect" else 1
            frame = struct.pack("<4I", len(body) + 16, version, message, 123) + body
            assert mux_frame(frame) == (kind, 123, value)
            assert mux_frame(frame[:-1]) is None
            stream = FirstFrame(0xfffffff8)
            assert stream.feed((0xfffffff8 + 16) & 0xffffffff, frame[16:]) is None
            assert stream.feed(0xfffffff8, frame[:8]) is None
            assert stream.feed(0xfffffff8, frame[:8]) is None
            assert stream.feed(0, frame[8:16]) == frame
            assert stream.feed(0xfffffff8, frame) is None
    stream = FirstFrame(100)
    stream.feed(100, bytes(4))
    try:
        stream.feed(100, bytes([1, 0, 0, 0]))
    except ValueError:
        pass
    else:
        raise AssertionError("Conflicting stream accepted")
    rows = [(2, 27015, 0, 0, 6392), (5, 50000, 0x0100007f, 27015, 100), (5, 27015, 0x0100007f, 50000, 6392)]
    assert client_owner(rows, 50000, 6392) == 100
    assert client_owner(rows[:-1], 50000, 6392) is None
    assert client_owner(rows, 50000, 999) is None
    print("PASS: plist/binary frames, TCP segmentation/reordering/retransmit/wrap/conflict and endpoint ownership")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        watch(int(sys.argv[1]), min(180, max(1, int(sys.argv[2]))))
