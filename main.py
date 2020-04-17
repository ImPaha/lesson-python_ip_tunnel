#!/usr/bin/env python3

import sys
import pytun
import struct
import ipaddress
import json

class IpHeader:
    def __init__(self, raw):
        self.ver_ihl, \
            self.tos, \
            self.total_length, \
            self.ident, \
            self.flags_fragoffset, \
            self.ttl, \
            self.proto, \
            self.chksum, \
            src, \
            dst, \
            self.opt1, \
            self.opt2, \
            self.pad = struct.unpack('>BBHHHBBHIIHBB', raw)

        self.src = ipaddress.IPv4Address(src)
        self.dst = ipaddress.IPv4Address(dst)

def main():
    config_filename = sys.argv[1]

    with open(config_filename) as config_file:
        config = json.load(config_file)

    tun_iface = pytun.TunTapDevice()

    print(tun_iface.name)

    tun_iface.addr    = config['iface_addr']
    tun_iface.dstaddr = config['iface_dstaddr']
    tun_iface.netmask = config['iface_netmask']
    tun_iface.mtu     = config['iface_mtu']

    tun_iface.up()

    while True:
        buf = tun_iface.read(tun_iface.mtu)

        flags = buf[:2]
        proto = buf[2:4]

        if proto != b'\x08\x00':
            continue

        ip_header = IpHeader(buf[4:28])
        body = buf[28:]

        print(ip_header.src, '→', ip_header.dst, 'len: %d' % ip_header.total_length)


if __name__ == '__main__':
    main()
