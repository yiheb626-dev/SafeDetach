"""Optional Npcap experiment: observe ONLY two owned fixture connections.

Requires an existing Npcap installation; never installs or changes a driver.
No capture files, device serials or transferred content are written.
Not a production observer: only complete single-packet IPv4 Connect requests.
"""
import ctypes as c
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("mux_fixture", Path(__file__).with_name("Probe-MuxHandshake.py"))
fixture_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_module)


class BpfProgram(c.Structure):
    _fields_ = [("length", c.c_uint), ("instructions", c.c_void_p)]


class PacketHeader(c.Structure):
    _fields_ = [("seconds", c.c_long), ("microseconds", c.c_long),
                ("captured", c.c_uint32), ("original", c.c_uint32)]


def load_api():
    directory = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Npcap"
    dll = directory / "wpcap.dll"
    if not dll.is_file():
        raise RuntimeError("Npcap is not installed; no capture or fixture started")
    # Explicit DLL search path prevents loading a library from the working directory.
    with os.add_dll_directory(str(directory)):
        api = c.CDLL(str(dll))
    signatures = {
        "pcap_open_live": (c.c_void_p, [c.c_char_p, c.c_int, c.c_int, c.c_int, c.c_char_p]),
        "pcap_compile": (c.c_int, [c.c_void_p, c.POINTER(BpfProgram), c.c_char_p, c.c_int, c.c_uint32]),
        "pcap_setfilter": (c.c_int, [c.c_void_p, c.POINTER(BpfProgram)]),
        "pcap_freecode": (None, [c.POINTER(BpfProgram)]),
        "pcap_setnonblock": (c.c_int, [c.c_void_p, c.c_int, c.c_char_p]),
        "pcap_datalink": (c.c_int, [c.c_void_p]),
        "pcap_next_ex": (c.c_int, [c.c_void_p, c.POINTER(c.POINTER(PacketHeader)), c.POINTER(c.POINTER(c.c_ubyte))]),
        "pcap_geterr": (c.c_char_p, [c.c_void_p]),
        "pcap_close": (None, [c.c_void_p]),
    }
    for name, (result, arguments) in signatures.items():
        method = getattr(api, name)
        method.restype, method.argtypes = result, arguments
    return api


def open_capture(api, expression):
    err = c.create_string_buffer(256)
    capture = api.pcap_open_live(b"\\Device\\NPF_Loopback", 1024, 0, 100, err)
    if not capture:
        raise RuntimeError("Cannot open loopback capture: " + err.value.decode(errors="replace"))
    try:
        program = BpfProgram()
        if api.pcap_compile(capture, c.byref(program), expression, 1, 0xffffffff) != 0:
            raise RuntimeError("Cannot compile capture filter")
        try:
            if api.pcap_setfilter(capture, c.byref(program)) != 0:
                raise RuntimeError("Cannot set capture filter")
        finally:
            api.pcap_freecode(c.byref(program))
        if api.pcap_setnonblock(capture, 1, err) != 0:
            raise RuntimeError("Cannot enable bounded nonblocking capture")
        link = api.pcap_datalink(capture)
        if link not in (0, 1, 101, 108, 113):
            raise RuntimeError("Unsupported capture link type: " + str(link))
        return capture, link
    except BaseException:
        api.pcap_close(capture)
        raise


def observe():
    api = load_api()
    fixture = None
    capture = None
    try:
        fixture = subprocess.Popen([sys.executable, "-B", str(Path(__file__).with_name("Probe-MuxHandshake.py"))],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        # Fixture ListDevices uses a two-second socket timeout and emits no serials.
        line = fixture.stdout.readline()
        if not line:
            raise RuntimeError("Fixture preparation failed: " + fixture.stderr.read())
        prepared = json.loads(line)
        expected = {(target["port"], target["device_id"]) for target in prepared["targets"]}
        if len(expected) != 2:
            raise RuntimeError("Two distinct fixture connections required")
        # Bind the filter to BOTH client source ports and the service port before any Connect.
        ports = " or ".join("src port " + str(port) for port, _ in sorted(expected))
        expression = ("ip and tcp and src host 127.0.0.1 and dst host 127.0.0.1 "
                      "and dst port 27015 and (" + ports + ")").encode("ascii")
        capture, link = open_capture(api, expression)
        fixture.stdin.write("continue\n")
        fixture.stdin.flush()
        observed = set()
        packets = 0
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            header, packet = c.POINTER(PacketHeader)(), c.POINTER(c.c_ubyte)()
            result = api.pcap_next_ex(capture, c.byref(header), c.byref(packet))
            if result == 1:
                packets += 1
                raw = c.string_at(packet, min(header.contents.captured, 1024))
                match = fixture_module.handshake(raw, link)
                if match is not None:
                    observed.add(match)
                if observed == expected and fixture.poll() is not None:
                    break
            elif result == 0:
                if observed == expected and fixture.poll() is not None:
                    break
                time.sleep(0.01)
            else:
                raise RuntimeError("Capture failed: " + api.pcap_geterr(capture).decode(errors="replace"))
        output, errors = fixture.communicate(timeout=3)
        if fixture.returncode != 0:
            raise RuntimeError("Fixture failed: " + errors)
        connected = json.loads(output)
        if any(target.get("result") != 0 for target in connected["targets"]):
            raise RuntimeError("A device rejected the test connection")
        print(json.dumps({"fixture_pid": prepared["pid"], "packet_count": packets,
                          "observed_handshakes": [{"port": p, "device_id": d} for p, d in sorted(observed)],
                          "matched_both_devices": observed == expected}))
        return 0 if observed == expected else 2
    finally:
        if capture:
            api.pcap_close(capture)
        if fixture:
            if fixture.poll() is None:
                fixture.kill()
            fixture.communicate()


if __name__ == "__main__":
    try:
        sys.exit(observe())
    except Exception as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        sys.exit(1)
