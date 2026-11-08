#!/usr/bin/env python
# raw-serial.py -- talk to the Pico CDC console WITHOUT the Windows .NET
# SerialPort stack.
#
# Why this exists (2026-11-06, real machine): after a few crashed firmware
# boots, the Windows .NET `System.IO.Ports.SerialPort` (used by capture-log.ps1 /
# flash-auto.ps1) can permanently fail with "A device attached to the system is
# not functioning" / "access denied" even though the device is fine in Device
# Manager and `mode COMx` works. Raw Win32 CreateFile/ReadFile/WriteFile keeps
# working, so this is the emergency read/flash path.
#
# Usage:
#   python tools/raw-serial.py COM6 read 10                 # read N seconds
#   python tools/raw-serial.py COM6 send "BOOTSEL"          # send a line + CRLF
#   python tools/raw-serial.py COM6 monitor 24 11           # N samples, gap secs
#   python tools/raw-serial.py COM6 flash build/stadia_one.uf2
#
# IMPORTANT: DTR MUST be asserted. The firmware gates its log pump on
# tud_cdc_connected(), which is DTR-based; without DTR you get 0 bytes and would
# wrongly conclude the firmware is dead.
import ctypes, os, shutil, string, sys, time
from ctypes import wintypes

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE = ctypes.c_void_p(-1).value
SETDTR = 5

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
k32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
                         ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
k32.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
                          ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.EscapeCommFunction.argtypes = [ctypes.c_void_p, wintypes.DWORD]


class COMMTIMEOUTS(ctypes.Structure):
    _fields_ = [('ReadIntervalTimeout', wintypes.DWORD),
                ('ReadTotalTimeoutMultiplier', wintypes.DWORD),
                ('ReadTotalTimeoutConstant', wintypes.DWORD),
                ('WriteTotalTimeoutMultiplier', wintypes.DWORD),
                ('WriteTotalTimeoutConstant', wintypes.DWORD)]


k32.SetCommTimeouts.argtypes = [ctypes.c_void_p, ctypes.POINTER(COMMTIMEOUTS)]


def open_port(port):
    h = k32.CreateFileW('\\\\.\\' + port, GENERIC_READ | GENERIC_WRITE, 0, None,
                        OPEN_EXISTING, 0, None)
    if h == INVALID_HANDLE or h is None:
        return None
    ct = COMMTIMEOUTS(0xFFFFFFFF, 0, 250, 0, 250)
    k32.SetCommTimeouts(h, ctypes.byref(ct))
    k32.EscapeCommFunction(h, SETDTR)
    return h


def read_seconds(h, seconds, chunk=8192):
    buf = ctypes.create_string_buffer(chunk)
    out = b''
    end = time.time() + seconds
    while time.time() < end:
        n = wintypes.DWORD(0)
        k32.ReadFile(h, buf, chunk, ctypes.byref(n), None)
        if n.value:
            out += buf.raw[:n.value]
        time.sleep(0.05)
    return out


def write_line(h, text):
    data = (text + '\r\n').encode('ascii')
    n = wintypes.DWORD(0)
    ok = k32.WriteFile(h, data, len(data), ctypes.byref(n), None)
    return bool(ok), n.value, len(data)


def bootsel_drives():
    return [d for d in string.ascii_uppercase if os.path.exists(d + ':\\INFO_UF2.TXT')]


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 1
    port, cmd = argv[1], argv[2]
    if cmd == 'read':
        seconds = float(argv[3]) if len(argv) > 3 else 10.0
        h = open_port(port)
        if not h:
            print('open FAILED'); return 2
        data = read_seconds(h, seconds)
        k32.CloseHandle(h)
        sys.stdout.write(data.decode('utf-8', 'replace'))
        print('\n---BYTES=%d---' % len(data))
        return 0
    if cmd == 'send':
        h = open_port(port)
        if not h:
            print('open FAILED'); return 2
        ok, n, total = write_line(h, argv[3] if len(argv) > 3 else 'BOOTSEL')
        k32.CloseHandle(h)
        print('write ok=%s n=%d/%d' % (ok, n, total))
        return 0
    if cmd == 'monitor':
        iters = int(argv[3]) if len(argv) > 3 else 12
        gap = float(argv[4]) if len(argv) > 4 else 11.0
        for i in range(iters):
            ts = time.strftime('%H:%M:%S')
            h = open_port(port)
            if not h:
                print('%s OPEN_FAIL' % ts, flush=True)
            else:
                data = read_seconds(h, 2.5)
                k32.CloseHandle(h)
                last = data.decode('utf-8', 'replace').replace('\r', '').strip().split('\n')[-1][:80]
                print('%s iter=%d BYTES=%d drives=%s last=%s'
                      % (ts, i, len(data), bootsel_drives(), last if data else '(none)'), flush=True)
            time.sleep(gap)
        return 0
    if cmd == 'flash':
        uf2 = argv[3]
        h = open_port(port)
        if not h:
            print('open FAILED'); return 2
        ok, n, total = write_line(h, 'BOOTSEL')
        k32.CloseHandle(h)
        print('BOOTSEL ok=%s n=%d/%d' % (ok, n, total))
        deadline = time.time() + 20
        drive = None
        while time.time() < deadline:
            d = bootsel_drives()
            if d:
                drive = d[0]; break
            time.sleep(0.3)
        if not drive:
            print('NO BOOTSEL DRIVE'); return 3
        dst = drive + ':\\' + os.path.basename(uf2)
        shutil.copyfile(uf2, dst)
        print('COPIED -> %s (%d bytes)' % (dst, os.path.getsize(uf2)))
        return 0
    print('unknown command'); return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
