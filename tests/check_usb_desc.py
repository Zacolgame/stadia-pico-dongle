#!/usr/bin/env python
"""Structural self-check of the static USB descriptors in src/usb_hid.c.

p3-3500 plugplay: interface 4 is the VENDOR XInput function again (restored
byte-exact from the p3-3180 lineage; the interim p3-3200 standard-HID gamepad
is deleted) - class 0xFF/0x5D/0x01 + 17-byte 0x21 xusb capability blob + the
whole MS OS 1.0 WCID exchange, so Windows' inbox xusb22.sys binds the child
as "Xbox 360 Controller for Windows" and XInput games work zero-config. The
composite is UAC1 audio 0-1 (TinyUSB's own vendored 98741b55 driver) + CDC
2-3 (usbser) + XInput 4 (xusb via WCID). This checker asserts:

  device descriptor (tusb_desc_device_t struct)
    - idVendor 0x045E but idProduct 0xFFFF - the Xbox wired-pad PID 0x028E is
      FORBIDDEN (device-level xusb22.inf hw-id match kills usbccgp/CDC);
      0xFFFF is unclaimed by any inbox INF
    - bcdDevice == 0x0302 (p3-3500-plugplay: fresh REV - the vendor XInput
      interface + WCID exchange are restored and the audio source is
      automatic; 0x0300/0x0301 devnodes recorded "non-WCID" state)
    - IAD composite device-level class (0xEF/0x02/0x01): the CDC pair needs it

  configuration descriptor (214 bytes)
    - wTotalLength == actual byte count, walk lands exactly on the end
    - interface numbers [0,1,1,2,3,4] with alts [0,0,1,0,0,0] (p3-3160-uac3:
      AUDIO FIRST - AC 0 / AS 1, CDC 2-3, gamepad 4 - mirroring the proven
      DS5Dongle RP2350+TinyUSB+UAC1 composite)
    - two IADs: UAC1 0+2 (01/01 audio control) then CDC 2+2 (02/02 ACM)
    - every endpoint address unique (number 1..15, direction), EP0 excluded
    - interface 4 is vendor 0xFF/0x5D/0x01 with bNumEndpoints=2
    - the 17-byte 0x21 "xusb capability" descriptor directly follows the
      interface (byte-exact real-hardware blob; its IN/OUT packet sizes
      must match the endpoint descriptors: 0x81 -> 20, 0x01 -> 8)
    - EP 0x81 interrupt IN (input reports) and EP 0x01 interrupt OUT (rumble)
    - NO HID-class interface, no 9-byte 0x21 HID descriptor
    - UAC1 function: AC interface 0 (class 01/sub 01/proto 00, no EP) with
      header/IT/OT class descriptors (wTotalLength consistent, header
      baInterfaceNr == 1 = the AS interface, IT 0x0101 USB-streaming 2ch L+R,
      OT 0x0301 speaker fed by the IT); AS interface 1 alt 0 = no EP, alt 1 =
      one ADAPTIVE iso OUT EP 0x04 MPS 192 interval 1 (p3-3180: D7 of
      bEndpointAddress is the direction bit - 0x84 declared an IN endpoint on
      a playback AS interface and usbaudio.sys refused the function), AS
      general links the IT and declares PCM, format type I = 2ch/2B/16bit
      single rate 48000; the audio EP is the 9-byte UAC1 form with
      bRefresh 0 / bSynchAddress 0 and the CS iso endpoint is the 7-byte
      form with no control and no lock delay (adaptive OUT, no feedback
      endpoint) - p3-3300, the shapes DS5Dongle's AS block uses

  MS OS 1.0 descriptors (WCID) - the ONLY remaining XInput binding path once
  usbccgp owns the device (no inbox INF matches USB\\Class_FF&SubClass_5D&
  Prot_01):
    - string index 0xEE: 18 B "MSFT100" signature + one bVendorCode byte
    - Extended Compat ID descriptor (40 B): dwLength 40, bcdVersion 1.00,
      wIndex 0x0004, bCount 1, bFirstInterfaceNumber == the XInput interface,
      CompatibleID "XUSB10" -> child compatible id USB\\MS_COMP_XUSB10, which
      xusb22.inf matches ("Xbox 360 Controller for Windows")
    - the firmware actually serves both: tud_descriptor_string_cb has the
      0xEE branch, tud_vendor_control_xfer_cb answers bRequest == the same
      vendor code with wIndex 0x0004 + wValue == 0x0000 (page number; the
      p3-2420 build demanded wValue low byte == the XInput interface - that
      is the convention of the Extended PROPERTIES query (wIndex 5), the real
      Compat ID query carries wValue 0x0000, so the request STALLed and the
      XInput child stayed driverless - Code 28 - with no MS_COMP_XUSB10)

  report path
    - xinput_report_t is exactly 20 bytes (C _Static_assert mirrors this)
    - the rumble OUT parser expects the 8-byte frame (cmd 0x00, len 0x08)

  plug-and-play audio (p3-3500): the speaker source must be AUTOMATIC -
    usb_audio_ms_since_data() fed by usb_audio_pump, the auto-source tick in
    rtc.c (switch to USB when data arrives, mute after >100 ms idle), the
    "audio: usb source auto-detected" log line, and NO AUDIOSRC console
    command anywhere.

  --uac1-only (p3-3170) validates the UAC1_ONLY bisect variant instead: the
  #if [!]UAC1_ONLY branches of src/usb_hid.c are evaluated first, then
    - device descriptor: class 01/00/00 (plain Audio, NO IAD/MISC),
      VID/PID 0x0D8C:0x013C (C-Media -> inbox usbaudio.sys), bcdDevice 0x0202
    - configuration: 100 bytes, exactly 2 interfaces (AC 0 + AS 1 alt0/alt1),
      1 endpoint (EP 0x04 iso adaptive 192 B), ZERO IADs, no 0x21 descriptor;
      the AC/AS class descriptors are byte-checked by the SAME code as the
      composite (check_uac1_function) - only the surrounding structure differs
    - WCID/XInput/CDC/HID machinery must be fully compiled out (0xEE branch,
      ms_os_* arrays, vendor callback, xinput_report_t,
      hid_report_descriptor, tud_hid_* callbacks all absent)

  --uac1-cdc (p3-3190) validates the UAC1_CDC_ONLY bisect variant: the
  variant conditionals of src/usb_hid.c (UAC1_ONLY / UAC1_CDC_ONLY) are
  evaluated first, then
    - device descriptor: IAD composite EF/02/01 (the CDC pair needs it),
      VID/PID 0x045E:0xFFFF (same identity as the composite), bcdDevice
      exactly 0x0203 (fresh devnodes)
    - configuration: 174 bytes, 4 interfaces (UAC1 AC 0 + AS 1 alt0/alt1 +
      CDC ctrl 2 + CDC data 3), 4 endpoints (iso 0x04 + CDC 0x82/0x83/0x03),
      two IADs (audio 0+2, CDC 2+2); the audio bytes are checked by the SAME
      check_uac1_function as the composite, the CDC block by check_cdc_function
    - gamepad/WCID machinery must be fully compiled out (no 0x21 descriptor,
      no gamepad interface, 0xEE branch / ms_os_* arrays / vendor callback /
      xinput_report_t / hid_report_descriptor / tud_hid_* all absent) - CDC
      usage is EXPECTED here

Exit status 0 + "check_usb_desc: OK ..." on success, nonzero otherwise.
ASCII only, no third-party imports. Run from anywhere.
"""

import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAILURES = []


def strip_variants(src, uac1_only, uac1_cdc):
    """Evaluate the flat variant conditionals of src/usb_hid.c: any #if whose
    controlling expression mentions UAC1_ONLY / UAC1_CDC_ONLY (joined by !
    / && / ||; #elif / #else allowed - p3-3170 introduced the switches,
    p3-3190 the two-macro form) is resolved for the requested variant,
    everything else passes through. The file deliberately contains no other
    conditionals, so a line-scan is exact - the rest of this checker then
    sees exactly the source the compiler sees for the requested build."""
    def ev(expr):
        if not re.fullmatch(r'[\s!&|()A-Z0-9_]*', expr):
            raise SystemExit('check_usb_desc ERROR: unsupported variant expression %r' % expr)
        e = re.sub(r'\bUAC1_CDC_ONLY\b', 'True' if uac1_cdc else 'False', expr)
        e = re.sub(r'\bUAC1_ONLY\b', 'True' if uac1_only else 'False', e)
        e = e.replace('&&', ' and ').replace('||', ' or ').replace('!', ' not ')
        return bool(eval(e))   # boolean-only tokens after the substitution above

    out, depth, active, taken = [], 0, True, False
    for line in src.splitlines(True):
        s = line.strip()
        code = s.split('//', 1)[0].strip()   # drop trailing comments
        if depth == 0:
            m = re.match(r'#if\s+(.+)$', code)
            if m and re.search(r'\bUAC1_(?:ONLY|CDC_ONLY)\b', m.group(1)):
                depth, taken = 1, False
                active = ev(m.group(1))
                if active:
                    taken = True
                continue
            out.append(line)
            continue
        m = re.match(r'#elif\s+(.+)$', code)
        if depth == 1 and m:
            active = (not taken) and ev(m.group(1))
            if active:
                taken = True
            continue
        if depth == 1 and re.match(r'#else\b', code):
            active = not taken
            continue
        if re.match(r'#endif\b', code):
            depth -= 1
            continue
        if re.match(r'#if', code):
            depth += 1
            continue
        if active:
            out.append(line)
    if depth != 0:
        raise SystemExit('check_usb_desc ERROR: unbalanced variant conditionals')
    return ''.join(out)


# p3-3500 plugplay constants: the vendor XInput function of interface 4.
XINPUT_ITF_NUM = 4                  # interface number of the pad
# byte-exact from a real wired Xbox 360 pad (partsnotincluded.com descriptor dump):
# bLength 17, bDescriptorType 0x21, then bytes whose tail encodes
# IN EP 0x81 packet 0x14 (20) and OUT EP 0x01 packet 0x08 (8).
XINPUT_CAP_BLOB = [0x11, 0x21, 0x00, 0x01, 0x01, 0x25, 0x81, 0x14, 0x00, 0x00, 0x00, 0x00,
                   0x13, 0x01, 0x08, 0x00, 0x00]
BLOB_IN_EP, BLOB_IN_LEN = 6, 7      # blob[5:8]  = 0x25, 0x81, 0x14 (attr, EP, len)
BLOB_OUT_EP, BLOB_OUT_LEN = 13, 14  # blob[12:15] = 0x13, 0x01, 0x08 (attr, EP, len)
REPORT_IN_BYTES = 20                # EP 0x81 wire packet (xinput_report_t)
REPORT_OUT_BYTES = 8                # EP 0x01 rumble frame


def fail(msg):
    FAILURES.append(msg)


def array_text(src, name):
    # "static const uint8_t NAME[SIZE] __attribute__((...)) = { ... };" - size and
    # attributes optional ([^\]]* / [^=]* keep the match on the same declaration)
    m = re.search(r'static const uint8_t %s\s*\[[^\]]*\][^=]*=\s*\{(.*?)\};' % name, src, re.S)
    if not m:
        fail('array %s not found in src/usb_hid.c' % name)
        return None
    return re.sub(r'//[^\n]*', '', m.group(1))


def to_bytes(text, defs=None):
    out = []
    for x in text.split(','):
        x = x.strip()
        if not x:
            continue
        m = re.fullmatch(r"'(.)'", x)          # C character constant
        if m:
            out.append(ord(m.group(1)))
        elif defs and x in defs:               # e.g. MS_OS_VENDOR_CODE
            out.append(defs[x])
        else:
            out.append(int(x, 0))
    return out


def check_device(src, uac1_only, uac1_cdc=False):
    m = re.search(r'static const tusb_desc_device_t desc_device = \{(.*?)\};', src, re.S)
    if not m:
        fail('desc_device not found in src/usb_hid.c')
        return None
    body = m.group(1)
    def field(name):
        mm = re.search(r'\.%s\s*=\s*([^,]+),' % name, body)
        return int(mm.group(1).strip(), 0) if mm else None
    if uac1_cdc:
        # p3-3190 UAC1+CDC bisect: same IAD composite identity as the full
        # build (the CDC pair needs usbccgp; PID 0xFFFF unclaimed), but
        # bcdDevice exactly 0x0203 - a REV Windows has never cached (p3-3300:
        # TinyUSB-vendored UAC1 driver + 9/7-byte EP/CS-EP forms; 0x0202 was
        # the handwritten-driver bisect).
        vid, pid = field('idVendor'), field('idProduct')
        if (vid, pid) != (0x045E, 0xFFFF):
            fail('audio+CDC idVendor:idProduct = 0x%04X:0x%04X, want 0x045E:0xFFFF '
                 '(same identity as the composite; the bisect changes the LAYOUT, '
                 'not the identity)' % (vid, pid))
        bcd = field('bcdDevice')
        if bcd != 0x0203:
            fail('audio+CDC bcdDevice = 0x%04X, want 0x0203 (fresh devnode for the '
                 'p3-3300 layout: TinyUSB-vendored UAC1 driver + 9/7-byte EP/CS-EP '
                 'forms; 0x0202 = the p3-3190 handwritten-driver bisect, 0x0108 = '
                 'failing audio+CDC+XInput - neither cached state may be reused)' % bcd)
        cls, sub, proto = field('bDeviceClass'), field('bDeviceSubClass'), field('bDeviceProtocol')
        if (cls, sub, proto) != (0xEF, 0x02, 0x01):
            fail('audio+CDC class/sub/proto = 0x%02X/0x%02X/0x%02X, want IAD '
                 'composite EF/02/01 (the CDC interface pair requires usbccgp)'
                 % (cls, sub, proto))
        return {'vid': vid, 'pid': pid, 'bcdDevice': bcd}
    if uac1_only:
        # p3-3170 audio-only bisect: plain class-01 USB speaker (C-Media
        # identity, usbaudio.sys binds with zero install), NO IAD/MISC.
        vid, pid = field('idVendor'), field('idProduct')
        if (vid, pid) != (0x0D8C, 0x013C):
            fail('audio-only idVendor:idProduct = 0x%04X:0x%04X, want 0x0D8C:0x013C '
                 '(C-Media USB audio - native usbaudio.sys, the whole point of the '
                 'bisect build)' % (vid, pid))
        bcd = field('bcdDevice')
        if bcd != 0x0202:
            fail('audio-only bcdDevice = 0x%04X, want 0x0202 (p3-3300 fresh devnode: '
                 'TinyUSB-vendored UAC1 driver + 9/7-byte EP/CS-EP forms; 0x0201 = '
                 'p3-3180 direction fix, 0x0200 = the broken IN-endpoint function, '
                 'both poisoned)' % bcd)
        cls, sub, proto = field('bDeviceClass'), field('bDeviceSubClass'), field('bDeviceProtocol')
        if (cls, sub, proto) != (0x01, 0x00, 0x00):
            fail('audio-only class/sub/proto = 0x%02X/0x%02X/0x%02X, want 01/00/00 '
                 '(plain Audio device - no IAD/MISC composite headers)' % (cls, sub, proto))
        return {'vid': vid, 'pid': pid, 'bcdDevice': bcd}
    vid, pid = field('idVendor'), field('idProduct')
    if vid != 0x045E:
        fail('device idVendor = 0x%04X, want 0x045E (Xbox family)' % vid)
    if pid == 0x028E or pid == 0x028F or pid == 0x0719:
        fail('idProduct 0x%04X is device-level matched by inbox xusb22.inf '
             '(USB\\Vid_045E&Pid_%04X) - xusb22 takes the whole device and the '
             'CDC COM port disappears. Use an unclaimed PID (0xFFFF).' % (pid, pid))
    if pid != 0xFFFF:
        fail('device idProduct = 0x%04X, want 0xFFFF (unclaimed by any inbox INF '
             'so usbccgp loads; XInput binds per-function via MS OS WCID)' % pid)
    bcd = field('bcdDevice')
    if bcd != 0x0302:
        fail('bcdDevice = 0x%04X, want exactly 0x0302 (p3-3500-plugplay identity: '
             'vendor XInput + WCID restored over the stdhid build, automatic audio '
             'source; 0x0300/0x0301 = the stdhid composites whose devnodes recorded '
             '"non-WCID" and must never be reused - Windows caches WCID/binding '
             'state per VID/PID/REV)' % (bcd or 0))
    cls, sub, proto = field('bDeviceClass'), field('bDeviceSubClass'), field('bDeviceProtocol')
    if (cls, sub, proto) != (0xEF, 0x02, 0x01):
        fail('device class/sub/proto = 0x%02X/0x%02X/0x%02X, want IAD composite 0xEF/0x02/0x01'
             % (cls, sub, proto))
    return {'vid': vid, 'pid': pid, 'bcdDevice': bcd}


def check_uac1_function(ifs, eps, cs_by_itf):
    """The UAC1 audio function bytes, shared byte-for-byte between the full
    composite (p3-2700/3160) and the audio-only bisect (p3-3170): AC interface
    first, then AS alt0/alt1, one ADAPTIVE iso OUT endpoint 0x04 (p3-3180:
    was mis-addressed 0x84 = IN since p3-2700). ifs must be
    the three audio interface dicts ([AC, AS alt0, AS alt1])."""
    ac, as0, as1 = ifs[0], ifs[1], ifs[2]
    for tag, itf, sub, nep in (('AC', ac, 0x01, 0), ('AS alt0', as0, 0x02, 0),
                               ('AS alt1', as1, 0x02, 1)):
        if itf['class'] != 0x01 or itf['sub'] != sub or itf['proto'] != 0x00:
            fail('%s interface class/sub/proto = 0x%02X/0x%02X/0x%02X, want 01/%02X/00 '
                 '(UAC1: protocol 0x00 - 0x20 would be UAC2, which the driver and '
                 'usbaudio.sys both reject)' % (tag, itf['class'], itf['sub'],
                                                itf['proto'], sub))
        if itf['nep'] != nep:
            fail('%s interface bNumEndpoints=%d, want %d' % (tag, itf['nep'], nep))
    cs_ac = cs_by_itf.get(0, [])
    cs_as = cs_by_itf.get(1, [])
    if len(cs_ac) != 3 or cs_ac[0][2] != 0x01 or cs_ac[1][2] != 0x02 or cs_ac[2][2] != 0x03:
        fail('AC class-specific descriptors %r, want header/IT/OT (subtypes 1/2/3)'
             % [c[:3] for c in cs_ac])
        return None
    hdr, it, ot = cs_ac
    if hdr[0] != 9 or (hdr[3] | (hdr[4] << 8)) != 0x0100:
        fail('AC header bLength=%d bcdADC=0x%04X, want 9 / 0x0100 (UAC1)'
             % (hdr[0], hdr[3] | (hdr[4] << 8)))
    cs_total = hdr[5] | (hdr[6] << 8)
    if cs_total != sum(len(c) for c in cs_ac):
        fail('AC header wTotalLength=%d != sum of CS descriptors %d'
             % (cs_total, sum(len(c) for c in cs_ac)))
    if hdr[7] != 1 or hdr[8] != 1:
        fail('AC header bInCollection/baInterfaceNr = %d/%d, want 1/1'
             % (hdr[7], hdr[8]))
    if len(it) != 12 or (it[4] | (it[5] << 8)) != 0x0101 or it[7] != 2 \
            or (it[8] | (it[9] << 8)) != 0x0003:
        fail('Input Terminal len=%d type=0x%04X nch=%d chcfg=0x%04X, want '
             '12/0x0101 (USB streaming)/2/0x0003 (L+R)'
             % (len(it), it[4] | (it[5] << 8), it[7], it[8] | (it[9] << 8)))
    if len(ot) != 9 or (ot[4] | (ot[5] << 8)) != 0x0301 or ot[7] != it[3]:
        fail('Output Terminal len=%d type=0x%04X source=%d, want 9/0x0301 '
             '(speaker)/%d (the Input Terminal id)' % (len(ot), ot[4] | (ot[5] << 8), ot[7], it[3]))
    if len(cs_as) != 2 or cs_as[0][2] != 0x01 or cs_as[1][2] != 0x02:
        fail('AS class-specific descriptors %r, want AS general + format type I'
             % [c[:3] for c in cs_as])
        return None
    g, f = cs_as
    if len(g) != 7 or g[3] != it[3] or (g[5] | (g[6] << 8)) != 0x0001:
        fail('AS general len=%d terminal link=%d format tag=0x%04X, want 7 / %d '
             '(IT) / 0x0001 (PCM)' % (len(g), g[3], g[5] | (g[6] << 8), it[3]))
    if len(f) != 11 or f[3] != 1 or f[4] != 2 or f[5] != 2 or f[6] != 16 \
            or f[7] != 1 or (f[8] | (f[9] << 8) | (f[10] << 16)) != 48000:
        fail('format type I len=%d fmt=%d nch=%d sub=%d bits=%d nfreq=%d freq=%d, '
             'want 11/1/2/2/16/1/48000' % (len(f), f[3], f[4], f[5], f[6], f[7],
             f[8] | (f[9] << 8) | (f[10] << 16)))
    by_addr = {e['addr']: e for e in eps}
    if 0x04 not in by_addr:
        fail('UAC1 iso OUT endpoint 0x04 missing from the configuration')
    else:
        e = by_addr[0x04]
        if e['attr'] != 0x09:
            fail('EP 0x04 bmAttributes=0x%02X, want 0x09 (iso adaptive data)'
                 % e['attr'])
        if e['mps'] != 192:
            fail('EP 0x04 MPS=%d, want 192 (48000*2ch*2B/1000)' % e['mps'])
        if e['interval'] != 1:
            fail('EP 0x04 bInterval=%d, want 1 (one packet per USB frame)' % e['interval'])
        # p3-3300: the audio data EP must be the UAC1-spec 9-byte form
        # (bRefresh/bSynchAddress appended, audio10.pdf 4.6.1.1) with no
        # feedback endpoint (0/0) - the shape DS5Dongle's AS block uses
        if e.get('len') != 9:
            fail('EP 0x04 descriptor is %d bytes, want the 9-byte UAC1 audio form '
                 '(bRefresh/bSynchAddress present)' % e.get('len', 0))
        elif e.get('refresh') != 0 or e.get('synch') != 0:
            fail('EP 0x04 bRefresh=%d bSynchAddress=0x%02X, want 0/0 (adaptive OUT: '
                 'no explicit feedback endpoint)' % (e['refresh'], e['synch']))
        # p3-3180 guard: D7 of bEndpointAddress is the direction bit. A
        # playback data endpoint carries host->device audio and MUST be OUT
        # (0x04). 0x84 = IN on this AS interface is exactly the bug that made
        # every UAC1 build since p3-2700 fail Windows enumeration while the
        # p3-3170 bisect blamed the TinyUSB iso path.
        if e['addr'] & 0x80:
            fail('UAC1 data endpoint 0x%02X has the IN direction bit set - the AS '
                 'interface is playback (bTerminalLink -> USB-streaming Input '
                 'Terminal), its data endpoint must be OUT (0x04)' % e['addr'])
        if any(e2['addr'] & 0x80 and (e2['attr'] & 3) == 1 for e2 in eps):
            fail('iso IN endpoint present in a playback-only UAC1 function')
    return {'ep': '0x04'}


def check_cdc_function(ifs, eps):
    """The CDC function bytes (byte-identical block in every build that has
    CDC): control interface 2 (class 02/02/01, one interrupt IN EP 0x82 MPS 8
    interval 16) + data interface 3 (class 0A/00/00, bulk EP 0x83 IN + 0x03
    OUT, MPS 64). First used by the p3-3190 UAC1_CDC_ONLY bisect branch."""
    if len(ifs) >= 5:
        ctl, data = ifs[3], ifs[4]
        if (ctl['num'], ctl['class'], ctl['sub'], ctl['proto'], ctl['nep']) != \
                (2, 0x02, 0x02, 0x01, 1):
            fail('CDC control interface = num %d class/sub/proto %02X/%02X/%02X nep %d, '
                 'want 2 / 02/02/01 (ACM) / 1 (interrupt notification EP)'
                 % (ctl['num'], ctl['class'], ctl['sub'], ctl['proto'], ctl['nep']))
        if (data['num'], data['class'], data['sub'], data['proto'], data['nep']) != \
                (3, 0x0A, 0x00, 0x00, 2):
            fail('CDC data interface = num %d class/sub/proto %02X/%02X/%02X nep %d, '
                 'want 3 / 0A/00/00 (CDC Data) / 2 (bulk IN+OUT)'
                 % (data['num'], data['class'], data['sub'], data['proto'], data['nep']))
    by_addr = {e['addr']: e for e in eps}
    if 0x82 in by_addr:
        e = by_addr[0x82]
        if (e['attr'] & 3) != 3 or e['mps'] != 8 or e['interval'] != 16:
            fail('CDC notification EP 0x82 = %s, want interrupt MPS 8 interval 16'
                 % e)
    else:
        fail('CDC notification endpoint 0x82 missing')
    for addr in (0x83, 0x03):
        if addr not in by_addr:
            fail('CDC bulk endpoint 0x%02X missing' % addr)
        else:
            e = by_addr[addr]
            if (e['attr'] & 3) != 2 or e['mps'] != 64:
                fail('CDC bulk EP 0x%02X = attr 0x%02X MPS %d, want bulk / 64'
                     % (addr, e['attr'], e['mps']))


def check_config(cfg, uac1_only, uac1_cdc=False):
    if cfg[0] != 9 or cfg[1] != 2:
        fail('config descriptor header malformed (bLength=%d bDescriptorType=%d)' % (cfg[0], cfg[1]))
        return None
    wtotal = cfg[2] | (cfg[3] << 8)
    if wtotal != len(cfg):
        fail('wTotalLength=%d != actual bytes=%d' % (wtotal, len(cfg)))
    if uac1_only and cfg[4] != 2:
        fail('audio-only bNumInterfaces=%d, want 2 (AudioControl + AudioStreaming)'
             % cfg[4])
    if uac1_cdc and cfg[4] != 4:
        fail('audio+CDC bNumInterfaces=%d, want 4 (UAC1 AC + AS + CDC IAD pair - '
             'the bisect drops ONLY the gamepad interface)' % cfg[4])
    if not uac1_only and not uac1_cdc and cfg[4] != 5:
        fail('bNumInterfaces=%d, want 5 (UAC1 AC + AS + CDC IAD pair + XInput pad)' % cfg[4])

    i, ifs, eps, ep_seen, cap_blobs, iads = 9, [], [], set(), [], []
    cs_by_itf = {}                     # UAC1 class-specific descriptors, grouped by owner interface
    cur_itf = None
    xi_itf_at = None
    while i < len(cfg):
        ln, dt = cfg[i], cfg[i + 1]
        if ln not in (4, 5, 6, 7, 8, 9, 11, 12, 17) or i + ln > len(cfg):
            fail('bad sub-descriptor at offset %d (bLength=%d type=0x%02X)' % (i, ln, dt))
            return None
        if ln == 9 and dt == 4:  # interface
            cur_itf = cfg[i + 2]
            ifs.append({'num': cfg[i + 2], 'alt': cfg[i + 3], 'nep': cfg[i + 4],
                        'class': cfg[i + 5], 'sub': cfg[i + 6], 'proto': cfg[i + 7]})
            if cfg[i + 5] == 0xFF:
                xi_itf_at = i
        elif ln in (7, 9) and dt == 5:  # endpoint (7 = plain, 9 = UAC1 audio form)
            ep = cfg[i + 2]
            if ep & 0x0F == 0:
                fail('endpoint address 0x%02X in interface list (EP0 is implicit)' % ep)
            if ep in ep_seen:
                fail('duplicate endpoint address 0x%02X' % ep)
            ep_seen.add(ep)
            e = {'addr': ep, 'attr': cfg[i + 3], 'mps': cfg[i + 4] | (cfg[i + 5] << 8),
                 'interval': cfg[i + 6], 'len': ln}
            if ln == 9:
                # p3-3300: UAC1 audio data EP carries bRefresh/bSynchAddress
                # (audio10.pdf 4.6.1.1); adaptive OUT with no feedback EP: 0/0
                e['refresh'] = cfg[i + 7]
                e['synch'] = cfg[i + 8]
            eps.append(e)
        elif ln == 8 and dt == 0x0B:  # IAD
            iads.append((cfg[i + 2], cfg[i + 3], cfg[i + 4], cfg[i + 5]))
        elif ln == 17 and dt == 0x21:  # xusb capability blob (p3-3500)
            cap_blobs.append((i, cfg[i:i + 17]))
        elif dt == 0x24:            # UAC1 class-specific interface descriptor
            cs_by_itf.setdefault(cur_itf, []).append(cfg[i:i + ln])
        elif dt == 0x25:            # UAC1 class-specific iso endpoint descriptor
            # p3-3300: 7-byte UAC1-spec form (audio10.pdf 4.6.1.2): bmAttributes,
            # bLockDelayUnits, wLockDelay - the 5-byte legacy form is gone
            if ln != 7 or cfg[i + 3] != 0 or cfg[i + 4] != 0 or cfg[i + 5] != 0 or cfg[i + 6] != 0:
                fail('CS iso endpoint descriptor len=%d attr=%d lockunits=%d lockdelay='
                     '0x%02X%02X, want 7/0/0/0 (no pitch/samfreq control, no lock '
                     'delay; adaptive OUT: no explicit feedback)'
                     % (ln, cfg[i + 3], cfg[i + 4], cfg[i + 6], cfg[i + 5]))
        i += ln
    if i != len(cfg):
        fail('descriptor walk ends at %d/%d' % (i, len(cfg)))

    if uac1_only:
        # ---- p3-3170 audio-only bisect: 2 interfaces / 1 endpoint / no IAD ----
        if [x['num'] for x in ifs] != [0, 1, 1]:
            fail('audio-only interface numbers %r, want [0, 1, 1] (AC 0 + AS alt0+alt1)'
                 % [x['num'] for x in ifs])
        if [x['alt'] for x in ifs] != [0, 0, 1]:
            fail('audio-only alt settings %r, want [0, 0, 1]' % [x['alt'] for x in ifs])
        if len(eps) != 1:
            fail('audio-only: %d endpoint descriptors, want 1 (UAC1 iso OUT 0x04)'
                 % len(eps))
        if iads:
            fail('audio-only: IAD %r present, want NONE (device class 0x01 - an IAD '
                 'would drag usbccgp back in)' % (iads,))
        if cap_blobs:
            fail('audio-only: %d xusb 0x21 capability blobs, want 0 (no XInput '
                 'function in this build)' % len(cap_blobs))
        if any(x['class'] != 0x01 for x in ifs):
            fail('audio-only: non-audio interface classes %r, want all 0x01'
                 % [x['class'] for x in ifs])
        if len(ifs) == 3:
            check_uac1_function(ifs, eps, cs_by_itf)
        return {'ifs': len(ifs), 'eps': len(eps), 'wtotal': wtotal, 'xi_itf': None}

    if uac1_cdc:
        # ---- p3-3190 UAC1+CDC bisect: 4 interfaces / 4 EPs / 2 IADs / no gamepad ----
        if [x['num'] for x in ifs] != [0, 1, 1, 2, 3]:
            fail('audio+CDC interface numbers %r, want [0, 1, 1, 2, 3] (AC 0 + AS '
                 'alt0+alt1 + CDC ctrl 2 + CDC data 3 - the composite layout minus '
                 'interface 4)' % [x['num'] for x in ifs])
        if [x['alt'] for x in ifs] != [0, 0, 1, 0, 0]:
            fail('audio+CDC alt settings %r, want [0, 0, 1, 0, 0]' % [x['alt'] for x in ifs])
        if len(eps) != 4:
            fail('audio+CDC: %d endpoint descriptors, want 4 (UAC1 iso OUT 0x04 + '
                 'CDC 0x82/0x83/0x03)' % len(eps))
        if iads != [(0, 2, 0x01, 0x01), (2, 2, 0x02, 0x02)]:
            fail('IADs %r, want UAC1 0+2 (01/01 audio control) then CDC 2+2 (02/02 '
                 'ACM) - same two associations as the composite' % (iads,))
        if cap_blobs:
            fail('audio+CDC: %d 0x21 capability blobs, want 0 (the gamepad '
                 'function is the variable this bisect REMOVES)' % len(cap_blobs))
        if any(x['class'] in (0x03, 0xFF) for x in ifs):
            fail('audio+CDC: gamepad-class interface present (classes %r), want NONE '
                 '(no gamepad in this build)' % [x['class'] for x in ifs])
        if len(ifs) == 5:
            check_uac1_function(ifs, eps, cs_by_itf)   # same bytes as the composite
            check_cdc_function(ifs, eps)               # same bytes as the composite
        return {'ifs': len(ifs), 'eps': len(eps), 'wtotal': wtotal, 'xi_itf': None}

    # full composite (p3-3500 plugplay): 5 interface numbers; interface 1 twice
    if [x['num'] for x in ifs] != [0, 1, 1, 2, 3, 4]:
        fail('interface numbers %r, want [0, 1, 1, 2, 3, 4] (audio first: 1 = AS alt0+alt1)'
             % [x['num'] for x in ifs])
    if [x['alt'] for x in ifs] != [0, 0, 1, 0, 0, 0]:
        fail('interface alt settings %r, want [0, 0, 1, 0, 0, 0]' % [x['alt'] for x in ifs])
    if len(eps) != 6:
        fail('%d endpoint descriptors, want 6 (UAC1 iso 1 + CDC 3 + XInput 2)' % len(eps))
    if iads != [(0, 2, 0x01, 0x01), (2, 2, 0x02, 0x02)]:
        fail('IADs %r, want UAC1 0+2 (01/01 audio control) then CDC 2+2 (02/02 ACM)' % (iads,))
    if any(x['class'] == 0x03 for x in ifs):
        fail('HID-class interface present (classes %r) - the pad must be the vendor '
             'XInput function (0xFF/0x5D/0x01), not standard HID' % [x['class'] for x in ifs])

    if len(ifs) == 6:
        xi = ifs[5]
        if (xi['num'], xi['class'], xi['sub'], xi['proto']) != (XINPUT_ITF_NUM, 0xFF, 0x5D, 0x01):
            fail('XInput interface num/class/sub/proto = %d/0x%02X/0x%02X/0x%02X, want '
                 '%d/FF/5D/01 (vendor XInput - Windows matches USB\\Class_FF&SubClass_5D'
                 '&Prot_01)' % (xi['num'], xi['class'], xi['sub'], xi['proto'],
                                XINPUT_ITF_NUM))
        if xi['nep'] != 2:
            fail('XInput interface bNumEndpoints=%d, want 2 (IN report + OUT rumble)' % xi['nep'])

        if xi_itf_at is None or len(cap_blobs) != 1 or cap_blobs[0][0] != xi_itf_at + 9:
            fail('want exactly one 17-byte 0x21 xusb capability descriptor directly after '
                 'the XInput interface descriptor')
        else:
            if cap_blobs[0][1] != XINPUT_CAP_BLOB:
                fail('0x21 capability blob %s != real-hardware blob %s'
                     % (' '.join('%02X' % b for b in cap_blobs[0][1]),
                        ' '.join('%02X' % b for b in XINPUT_CAP_BLOB)))

        by_addr = {e['addr']: e for e in eps}
        for addr in (0x81, 0x01):
            if addr not in by_addr:
                fail('XInput endpoint 0x%02X missing from the configuration' % addr)
        if 0x81 in by_addr:
            e = by_addr[0x81]
            if (e['attr'] & 3) != 3:
                fail('EP 0x81 transfer type 0x%02X, want interrupt (3)' % e['attr'])
            if e['mps'] < REPORT_IN_BYTES:
                fail('EP 0x81 MPS %d < %d-byte report' % (e['mps'], REPORT_IN_BYTES))
        if 0x01 in by_addr:
            e = by_addr[0x01]
            if (e['attr'] & 3) != 3:
                fail('EP 0x01 transfer type 0x%02X, want interrupt (3)' % e['attr'])
            if e['mps'] < REPORT_OUT_BYTES:
                fail('EP 0x01 MPS %d < %d-byte rumble frame' % (e['mps'], REPORT_OUT_BYTES))
        # the blob's packet sizes must match what the endpoints actually carry
        if len(cap_blobs) == 1:
            blob = cap_blobs[0][1]
            if blob[BLOB_IN_EP] != 0x81 or blob[BLOB_IN_LEN] != REPORT_IN_BYTES:
                fail('blob IN entry = EP 0x%02X len %d, want 0x81 len %d'
                     % (blob[BLOB_IN_EP], blob[BLOB_IN_LEN], REPORT_IN_BYTES))
            if blob[BLOB_OUT_EP] != 0x01 or blob[BLOB_OUT_LEN] != REPORT_OUT_BYTES:
                fail('blob OUT entry = EP 0x%02X len %d, want 0x01 len %d'
                     % (blob[BLOB_OUT_EP], blob[BLOB_OUT_LEN], REPORT_OUT_BYTES))

        # ---- UAC1 audio function (p3-2700, first since p3-3160): AC 0, AS 1 ----
        # (byte checks shared with the audio-only build: check_uac1_function)
        check_uac1_function(ifs, eps, cs_by_itf)
    xi_itf = ifs[5]['num'] if len(ifs) == 6 else None
    return {'ifs': len(ifs), 'eps': len(eps), 'wtotal': wtotal, 'xi_itf': xi_itf}


def check_msos(src, xi_itf):
    """MS OS 1.0 WCID descriptors (restored p3-3500): the only path by which
    the XInput function of a usbccgp composite reaches xusb22.sys
    (USB\\MS_COMP_XUSB10)."""
    if xi_itf is None:
        return None
    # --- vendor code ---
    m = re.search(r'#define\s+MS_OS_VENDOR_CODE\s+(0x[0-9A-Fa-f]+)', src)
    if not m:
        fail('MS_OS_VENDOR_CODE not defined in src/usb_hid.c')
        return None
    vcode = int(m.group(1), 0)
    if vcode == 0:
        fail('MS_OS_VENDOR_CODE must be nonzero')
    # --- string 0xEE: 18 B, type 3, UTF-16 "MSFT100", vendor code, pad 0 ---
    txt = array_text(src, 'ms_os_string_ee')
    if txt is None:
        return None
    ee = to_bytes(txt, {'MS_OS_VENDOR_CODE': vcode})
    sig = [0x12, 0x03]
    for ch in 'MSFT100':
        sig += [ord(ch), 0x00]
    sig += [vcode, 0x00]
    if ee != sig:
        fail('ms_os_string_ee %s != WCID OS String %s (18 B, bLength 0x12, type '
             '0x03, UTF-16 "MSFT100", bVendorCode 0x%02X, pad 0)'
             % (' '.join('%02X' % b for b in ee), ' '.join('%02X' % b for b in sig), vcode))
    # --- extended compat id: 40 B, one function section, XUSB10, xi_itf ---
    txt = array_text(src, 'ms_os_ext_compat')
    if txt is None:
        return None
    ec = to_bytes(txt)
    if len(ec) != 40:
        fail('ms_os_ext_compat is %d bytes, want 40 (header 16 + function 24)' % len(ec))
        return None
    if ec[0] != 40 or ec[1] or ec[2] or ec[3]:
        fail('ms_os_ext_compat dwLength bytes %s, want 28 00 00 00 (40 LE)' % ec[0:4])
    if ec[4] != 0x00 or ec[5] != 0x01:
        fail('ms_os_ext_compat bcdVersion %s, want 00 01 (1.00)' % ec[4:6])
    if ec[6] != 0x04 or ec[7] != 0x00:
        fail('ms_os_ext_compat wIndex %s, want 04 00 (Extended Compat ID)' % ec[6:8])
    if ec[8] != 1:
        fail('ms_os_ext_compat bCount = %d, want 1 function section' % ec[8])
    if ec[16] != xi_itf:
        fail('ms_os_ext_compat bFirstInterfaceNumber = %d, want %d (the XInput '
             'interface from the config descriptor)' % (ec[16], xi_itf))
    compat = ec[18:26]
    if compat != list(b'XUSB10\x00\x00'):
        fail('CompatibleID %r, want "XUSB10" NUL-padded to 8 (child gets '
             'USB\\MS_COMP_XUSB10 -> xusb22.inf)' % bytes(compat))
    # --- the firmware serves both halves ---
    if not re.search(r'tud_descriptor_string_cb[^{]*\{[^}]*index\s*==\s*0xEE', src, re.S):
        fail('tud_descriptor_string_cb has no index==0xEE branch (usbccgp probe '
             'would stall and Windows would skip WCID entirely)')
    hook = re.search(r'bool\s+tud_vendor_control_xfer_cb\s*\((?:[^)]*)\)\s*\{(.*?)\n\}', src, re.S)
    if not hook:
        fail('tud_vendor_control_xfer_cb not found in src/usb_hid.c')
        return None
    h = hook.group(1)
    if 'CONTROL_STAGE_SETUP' not in h:
        fail('tud_vendor_control_xfer_cb does not gate on CONTROL_STAGE_SETUP '
             '(it is re-invoked as the transfer completion callback)')
    if not re.search(r'bRequest\s*==\s*MS_OS_VENDOR_CODE', h):
        fail('tud_vendor_control_xfer_cb does not match bRequest == MS_OS_VENDOR_CODE')
    if not re.search(r'wIndex\s*==\s*0x0004', h):
        fail('tud_vendor_control_xfer_cb does not match wIndex == 0x0004 (ext-compat)')
    if not re.search(r'wValue\s*==\s*0x0000', h):
        fail('tud_vendor_control_xfer_cb does not match wValue == 0x0000 (MS OS 1.0 '
             'page number for the wIndex=4 Compat ID query; the interface is bound '
             'by bFirstInterfaceNumber inside the descriptor, NOT by wValue - '
             'p3-2420 wrongly required wValue low byte == %d and STALLed the real '
             'query, so Windows treated the device as non-WCID)' % xi_itf)
    if not re.search(r'tud_control_xfer\(\s*rhport\s*,\s*request\s*,[^;]*ms_os_ext_compat', h, re.S):
        fail('tud_vendor_control_xfer_cb does not reply with ms_os_ext_compat')
    return {'vendor_code': vcode, 'compat': 'XUSB10', 'xi_itf': xi_itf}


def check_report(src):
    # the C side builds reports through xinput_report_t; its _Static_assert must
    # exist and pin 20 bytes (= the blob's declared IN packet size)
    m = re.search(r'_Static_assert\(sizeof\(xinput_report_t\) == (\d+)', src)
    if not m:
        fail('xinput_report_t 20-byte _Static_assert not found in src/usb_hid.c')
        return None
    if int(m.group(1)) != REPORT_IN_BYTES:
        fail('xinput_report_t _Static_assert pins %s bytes, want %d'
             % (m.group(1), REPORT_IN_BYTES))
    # the rumble OUT parser must expect the 8-byte frame (cmd 0x00, len 0x08)
    if not re.search(r'buffer\[0\]\s*==\s*0x00\s*&&\s*buffer\[1\]\s*==\s*0x08', src):
        fail('tud_vendor_rx_cb rumble frame match (cmd 0x00 len 0x08) not found')
    return {'report_bytes': REPORT_IN_BYTES}


def check_plugplay_audio():
    """p3-3500: PC audio must reach the speaker with ZERO commands. Asserts the
    automatic source machinery end-to-end on the source level: the fifo data
    recency probe (usb_audio.c), the auto-source tick + the verification log
    line + the 100 ms mute threshold (rtc.c), and that the AUDIOSRC console
    command is gone."""
    ua = open(os.path.join(ROOT, 'src', 'usb_audio.c'), encoding='utf-8').read()
    # p3-3600-dualcore: the recency probe is published to core0 through the IPC
    # snapshot (ipc_audio_data_seen), consumed by rtc.c as ipc_audio_ms_since_data.
    for needed in ('ipc_audio_data_seen', 'tud_audio_available', 'usb_audio_flush'):
        if needed not in ua:
            fail('src/usb_audio.c missing %s - the auto-source data probe is '
                 'incomplete' % needed)
    rc = open(os.path.join(ROOT, 'src', 'rtc.c'), encoding='utf-8').read()
    for needed in ('ipc_audio_ms_since_data', 'audio: usb source auto-detected',
                   'rtc_audio_set_source(1)'):
        if needed not in rc:
            fail('src/rtc.c missing %r - the automatic audio-source tick is '
                 'incomplete' % needed)
    # the 100 ms idle mute threshold
    if not re.search(r'since_ms\s*>\s*100', rc):
        fail('src/rtc.c auto-source mute threshold (>100 ms idle) not found')
    if not re.search(r'since_ms\s*<\s*100', rc):
        fail('src/rtc.c auto-source switch-on window (<100 ms since data) not found')
    # AUDIOSRC must be gone from the console parser (a no-op or a live command
    # both violate zero-config: nothing may override the automatic selection)
    uh = open(os.path.join(ROOT, 'src', 'usb_hid.c'), encoding='utf-8').read()
    code_uh = re.sub(r'//[^\n]*', '', uh)
    if re.search(r"A'\s*&&\s*cmd\[1\]\s*==\s*'U'\s*&&\s*cmd\[2\]\s*==\s*'D'\s*&&\s*cmd\[3\]\s*==\s*'I'",
                  code_uh) or 'AUDIOSRC usb' in code_uh:
        fail('src/usb_hid.c still parses an AUDIOSRC command - p3-3500 audio is '
             'fully automatic, no console command may remain')
    return {'auto_audio': True}


def check_core0_encode():
    """p3-3641-core0encode: the Opus encode must live on CORE 0.

    Why it is an invariant: core1 owns the single-buffered iso OUT endpoint, and a
    7.9 ms encode between tud_task() passes dropped 58% of the USB PCM on real
    hardware. The ring (ipc_pcm_push) is the ONLY audio data core1 may produce;
    the encode happens in rtc_tick -> audio_send_frame -> usb_audio_encode_live.
    """
    ua = open(os.path.join(ROOT, 'src', 'usb_audio.c'), encoding='utf-8').read()
    if 'ipc_pcm_push' not in ua:
        fail('src/usb_audio.c never pushes PCM into the IPC ring (ipc_pcm_push) - '
             'core1 must feed the ring, not encode')
    if 'usb_audio_core1_start' in ua:
        fail('src/usb_audio.c still has the core1-side encoder init '
             '(usb_audio_core1_start) - the encoder belongs to core0 now')
    # the core1 tick body must be encoder-free
    m = re.search(r'void\s+usb_audio_core1_tick\s*\(void\)\s*\{', ua)
    if not m:
        fail('src/usb_audio.c: usb_audio_core1_tick() not found')
    else:
        body = ua[m.end():]
        end = re.search(r'\n\}', body)
        body = body[:end.start()] if end else body
        if 'opus_encode' in re.sub(r'//[^\n]*', '', body):
            fail('usb_audio_core1_tick() still calls opus_encode() - the encode '
                 'must run on core0, never between tud_task() passes')
        if 'ipc_audio_push' in body:
            fail('usb_audio_core1_tick() still pushes encoded frames (ipc_audio_push)')
    rc = open(os.path.join(ROOT, 'src', 'rtc.c'), encoding='utf-8').read()
    if 'usb_audio_encode_live' not in rc:
        fail('src/rtc.c does not encode on core0 (usb_audio_encode_live missing)')
    if 'ipc_audio_demand' in rc:
        fail('src/rtc.c still uses the core1 demand pacing (ipc_audio_demand)')
    cm = open(os.path.join(ROOT, 'CMakeLists.txt'), encoding='utf-8').read()
    if 'NONTHREADSAFE_PSEUDOSTACK' not in cm or 'GLOBAL_STACK_SIZE' not in cm:
        fail('CMakeLists.txt: opus is not built with the NONTHREADSAFE_PSEUDOSTACK '
             '/ GLOBAL_STACK_SIZE scratch (core0 has a 4 KiB stack)')
    if re.search(r'VAR_ARRAYS\s*=\s*1', cm):
        fail('CMakeLists.txt still builds opus with VAR_ARRAYS=1 - ~33 KB of VLA '
             'scratch would overflow core0\'s 4 KiB stack')
    return {'core0_encode': True}


def check_tinyuac_driver():
    """p3-3300-tinyuac: the audio function must be driven by TinyUSB's OWN
    audio class, vendored from upstream 98741b55 into
    src/tinyusb-patch/class/audio/ (the SDK's 0.18 copy is UAC2-only) and
    swapped in via CMakeLists.txt - NOT by the hand-written driver that used
    to live in usb_audio.c (it crashed the firmware when Windows initialized
    the iso endpoints). Asserts the swap is in place and complete."""
    # 1. the vendored driver files exist and the .c carries the UAC1 accept
    vdir = os.path.join(ROOT, 'src', 'tinyusb-patch', 'class', 'audio')
    for name in ('audio_device.c', 'audio_device.h', 'audio.h'):
        if not os.path.isfile(os.path.join(vdir, name)):
            fail('vendored TinyUSB audio class file %s missing from %s' % (name, vdir))
            return None
    vc = open(os.path.join(vdir, 'audio_device.c'), encoding='utf-8').read()
    if '98741b55' not in vc:
        fail('vendored audio_device.c has no 98741b55 provenance marker')
    if 'bInterfaceProtocol == AUDIO_INT_PROTOCOL_CODE_V1' not in vc:
        fail('vendored audio_device.c audiod_open does not accept UAC1 (protocol '
             'V1) - wrong upstream version?')
    if 'STADIA PATCH' not in vc or 'STADIA VENDOR PATCH' not in vc:
        fail('vendored audio_device.c lacks the STADIA vendor-patch header')

    # 2. the CMake swap drops the SDK copy and compiles ours (the CMake regex
    # literal escapes the dot as \\. - match either spelling)
    cm = open(os.path.join(ROOT, 'CMakeLists.txt'), encoding='utf-8').read()
    if not re.search(r'class/audio/audio_device\\\\?\.c\$', cm):
        fail('CMakeLists.txt no longer filters the SDK audio_device.c out of '
             'tinyusb_device_base INTERFACE_SOURCES')
    if 'src/tinyusb-patch/class/audio/audio_device.c' not in cm:
        fail('CMakeLists.txt does not add the vendored audio_device.c')

    # 3. tusb_config.h enables the builtin audio class for the EP OUT path
    tc = open(os.path.join(ROOT, 'tusb_config.h'), encoding='utf-8').read()
    if not re.search(r'#define\s+CFG_TUD_AUDIO\s+1\b', tc):
        fail('tusb_config.h does not set CFG_TUD_AUDIO 1')
    for macro, val in (('CFG_TUD_AUDIO_ENABLE_EP_OUT', '1'),
                       ('CFG_TUD_AUDIO_ENABLE_EP_IN', '0'),
                       ('CFG_TUD_AUDIO_FUNC_1_EP_OUT_SZ_MAX', '192')):
        if not re.search(r'#define\s+%s\s+%s\b' % (macro, val), tc):
            fail('tusb_config.h: %s %s missing (UAC1 EP OUT config)' % (macro, val))

    # 4. the hand-written driver is gone and the data path uses the TinyUSB API
    ua = open(os.path.join(ROOT, 'src', 'usb_audio.c'), encoding='utf-8').read()
    for absent, what in (('usbd_app_driver_get_cb', 'hand-written class driver '
                                                    'registration'),
                         ('usbd_edpt_iso_alloc', 'hand-written iso endpoint alloc'),
                         ('usbd_edpt_xfer', 'hand-written endpoint re-arm'),
                         ('usbd_class_driver_t', 'hand-written usbd driver struct')):
        if absent in re.sub(r'//[^\n]*', '', ua):
            fail('src/usb_audio.c still contains %s (%r) - the driver must be '
                 'TinyUSB\'s own, only the PCM->Opus pipeline stays' % (what, absent))
    for needed in ('tud_audio_available', 'tud_audio_read', 'usb_audio_pump',
                   'tud_audio_set_itf_cb', 'tud_audio_set_itf_close_ep_cb'):
        if needed not in ua:
            fail('src/usb_audio.c missing %s - the TinyUSB audio data path '
                 'incomplete' % needed)
    mc = open(os.path.join(ROOT, 'src', 'main.c'), encoding='utf-8').read()
    # p3-3600-dualcore: the audio pump/USB loop moved to core1 (core1_main.c). The
    # ownership rule is the invariant now: core1_main drains the driver fifo, and
    # main.c (core0) must NOT touch the USB stack any more.
    c1 = open(os.path.join(ROOT, 'src', 'core1_main.c'), encoding='utf-8').read()
    if 'usb_audio_core1_tick' not in c1:
        fail('src/core1_main.c never calls usb_audio_core1_tick() - the driver '
             'fifo is never drained into the ring on core1')
    for stale in ('usb_audio_pump', 'usb_hid_task', 'usb_hid_pump_cdc', 'tud_task'):
        if stale in re.sub(r'//[^\n]*', '', mc):
            fail('src/main.c still calls %s() - TinyUSB is owned by core1 only '
                 '(p3-3600-dualcore)' % stale)
    return {'vendored': True}


def main():
    ap = argparse.ArgumentParser(description='static USB descriptor check')
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument('--uac1-only', action='store_true',
                      help='validate the UAC1_ONLY bisect variant (p3-3170): audio '
                           'interfaces only, no CDC/gamepad/IAD/WCID.')
    mode.add_argument('--uac1-cdc', action='store_true',
                      help='validate the UAC1_CDC_ONLY bisect variant (p3-3190): '
                           'audio + CDC, no gamepad/WCID. Default validates the '
                           'full composite (p3-3500 plugplay: vendor XInput pad).')
    args = ap.parse_args()
    src = open(os.path.join(ROOT, 'src', 'usb_hid.c'), encoding='utf-8').read()
    src = strip_variants(src, args.uac1_only, args.uac1_cdc)
    cfg_text = array_text(src, 'desc_configuration')
    if FAILURES:
        for m in FAILURES:
            print('check_usb_desc FAIL: %s' % m)
        return 1
    cfg = to_bytes(cfg_text)

    dinfo = check_device(src, args.uac1_only, args.uac1_cdc)
    cinfo = check_config(cfg, args.uac1_only, args.uac1_cdc)

    # absent-machinery scans run on CODE only: usb_hid.c's comments legitimately
    # describe the deleted/restored surfaces in unconditional header text (the
    # file has // comments only, no /* */ blocks).
    code_only = re.sub(r'//[^\n]*', '', src)
    if args.uac1_only:
        # No WCID, no gamepad, no CDC in the bisect build - and the firmware
        # must not answer the 0xEE probe either (non-WCID plain class device).
        for absent, what in (('ms_os_string_ee', 'MS OS string descriptor'),
                             ('ms_os_ext_compat', 'MS OS ext-compat descriptor'),
                             ('tud_vendor_control_xfer_cb', 'vendor control callback'),
                             ('xinput_report_t', 'XInput report type'),
                             ('index == 0xEE', 'string 0xEE branch'),
                             ('hid_report_descriptor', 'HID report descriptor'),
                             ('hid_pad_report_t', 'HID report type'),
                             ('tud_hid_', 'HID class callbacks'),
                             ('CFG_TUD_CDC', 'CDC usage')):
            if absent in code_only:
                fail('audio-only build still contains %s (%r) - it must be inside '
                     'a #if !UAC1_ONLY block' % (what, absent))
        minfo = rinfo = {'skipped': 'audio-only'}
        check_tinyuac_driver()      # p3-3300 applies to every variant
    elif args.uac1_cdc:
        # CDC IS present in this variant (CFG_TUD_CDC=1, the COM port is half
        # of the read-out) - only the gamepad machinery must be gone, including
        # the WCID replies (usbccgp must see a non-WCID plain class composite so
        # both functions bind on standard compatible ids).
        for absent, what in (('ms_os_string_ee', 'MS OS string descriptor'),
                             ('ms_os_ext_compat', 'MS OS ext-compat descriptor'),
                             ('tud_vendor_control_xfer_cb', 'vendor control callback'),
                             ('xinput_report_t', 'XInput report type'),
                             ('index == 0xEE', 'string 0xEE branch'),
                             ('MS_OS_VENDOR_CODE', 'MS OS vendor code'),
                             ('hid_report_descriptor', 'HID report descriptor'),
                             ('hid_pad_report_t', 'HID report type'),
                             ('tud_hid_', 'HID class callbacks')):
            if absent in code_only:
                fail('audio+CDC build still contains %s (%r) - it must be inside '
                     'a #if !UAC1_ONLY && !UAC1_CDC_ONLY block' % (what, absent))
        minfo = rinfo = {'skipped': 'audio+CDC (no gamepad)'}
        check_tinyuac_driver()      # p3-3300 applies to every variant
    else:
        # p3-3500 plugplay: the vendor XInput + WCID surface must be PRESENT
        # (check_msos / check_report assert it below); the p3-3200 standard-HID
        # surface must be GONE - no HID report descriptor, no HID callbacks,
        # and CFG_TUD_HID must be off so Windows cannot find a HID interface
        # on the pad.
        for absent, what in (('hid_report_descriptor', 'HID report descriptor'),
                             ('hid_pad_report_t', 'HID report type'),
                             ('tud_hid_', 'HID class callbacks'),
                             ('CFG_TUD_HID 1', 'TinyUSB HID driver')):
            if absent in code_only:
                fail('plugplay composite still contains %s (%r) - the pad is the '
                     'vendor XInput function; no HID surface may remain' % (what, absent))
        tc = open(os.path.join(ROOT, 'tusb_config.h'), encoding='utf-8').read()
        if not re.search(r'#define\s+CFG_TUD_VENDOR\s+1\b', tc):
            fail('tusb_config.h does not set CFG_TUD_VENDOR 1 (vendor_device must '
                 'claim the XInput interface)')
        minfo = check_msos(src, cinfo['xi_itf'] if cinfo else None)
        rinfo = check_report(src)
        # p3-3300 + p3-3500: the TinyUSB-vendored driver swap and the
        # automatic audio source apply to the shipping composite
        check_tinyuac_driver()
        check_plugplay_audio()

    check_core0_encode()    # p3-3641: the encode moved to core0 (all variants)

    if FAILURES or dinfo is None or cinfo is None or minfo is None or rinfo is None:
        for m in FAILURES:
            print('check_usb_desc FAIL: %s' % m)
        return 1
    if args.uac1_only:
        print('check_usb_desc: OK UAC1_ONLY device 0x%04X:0x%04X bcdDevice 0x%04X '
              'class 01/00/00; config %d bytes, %d interface descriptors '
              '(AC 0 + AS 1 alt0/alt1), %d endpoint (EP 0x04 iso adaptive 192B '
              '48k stereo); no IAD, no CDC, no gamepad, no WCID - usbaudio.sys '
              'path only' % (dinfo['vid'], dinfo['pid'], dinfo['bcdDevice'],
                             cinfo['wtotal'], cinfo['ifs'], cinfo['eps']))
    elif args.uac1_cdc:
        print('check_usb_desc: OK UAC1_CDC_ONLY device 0x%04X:0x%04X bcdDevice 0x%04X '
              'class EF/02/01 (IAD); config %d bytes, %d interface descriptors '
              '(AC 0 + AS 1 alt0/alt1 + CDC 2-3), %d endpoints (EP 0x04 iso '
              'adaptive 192B 48k stereo + CDC 0x82/0x83/0x03); IADs audio 0+2 and '
              'CDC 2+2; no gamepad, no WCID - usbaudio.sys + usbser paths only'
              % (dinfo['vid'], dinfo['pid'], dinfo['bcdDevice'],
                 cinfo['wtotal'], cinfo['ifs'], cinfo['eps']))
    else:
        print('check_usb_desc: OK plugplay device 0x%04X:0x%04X bcdDevice 0x%04X '
              'class EF/02/01 (IAD); config %d bytes, %d interface descriptors, '
              '%d endpoints; audio-first (UAC1 AC 0 + AS 1) EP 0x04 iso adaptive '
              '192B 48k stereo (TinyUSB vendored 98741b55, auto-source); CDC 2-3; '
              'VENDOR XInput itf 4 (FF/5D/01) + 17B 0x21 xusb blob, EP 0x81 IN '
              '%dB reports / EP 0x01 OUT %dB rumble; MS OS WCID vcode 0x%02X %s -> '
              'iface %d; no HID surface; automatic audio source'
              % (dinfo['vid'], dinfo['pid'], dinfo['bcdDevice'], cinfo['wtotal'],
                 cinfo['ifs'], cinfo['eps'], REPORT_IN_BYTES, REPORT_OUT_BYTES,
                 minfo['vendor_code'], minfo['compat'], minfo['xi_itf']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
