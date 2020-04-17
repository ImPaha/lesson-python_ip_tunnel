#!/usr/bin/env python3

import sys
import pytun
import struct
import ipaddress
import json
import socket

class Config:
    def __init__(self, data):
        if data['mode'] == 'server':
            self.is_server = True
        elif data['mode'] == 'client':
            self.is_server = False
        else:
            raise RuntimeError('invalid mode "%s"' % data['mode'])

        self.address = data['address']
        self.port    = data['port']

        self.iface_name    = data['iface_name']
        self.iface_addr    = data['iface_addr']
        self.iface_dstaddr = data['iface_dstaddr']
        self.iface_netmask = data['iface_netmask']
        self.iface_mtu     = data['iface_mtu']

class IpPacket:
    def __init__(self, header, body):
        self.header = header
        self.body = body

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
        config = Config(json.load(config_file))

    tun_iface = pytun.TunTapDevice()

    print(tun_iface.name)

    tun_iface.addr    = config.iface_addr
    tun_iface.dstaddr = config.iface_dstaddr
    tun_iface.netmask = config.iface_netmask
    tun_iface.mtu     = config.iface_mtu

    tun_iface.up()

    addr_and_port = (config.address, config.port)

    if config.is_server:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print('binding to %s, port %s' % addr_and_port)
        sock.bind(addr_and_port)
        sock.listen(1)
        print('waiting for incoming connection')
        conn, client_addr = sock.accept()
        print('accepted incoming connection from %s' % client_addr[0])

    else:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print('connecting to %s, port %s' % addr_and_port)
        conn.connect(addr_and_port)
        print('connected!')

    while True:
        buf = tun_iface.read(tun_iface.mtu)

        flags = buf[:2]
        proto = buf[2:4]

        if proto != b'\x08\x00':
            continue

        ip_packet = IpPacket(IpHeader(buf[4:28]), buf[28:])

        handle_ip_packet(ip_packet, conn, tun_iface, config)

def handle_ip_packet(ip_packet, conn, tun_iface, config):
    print(
        ip_packet.header.src,
        '→',
        ip_packet.header.dst,
        'len: %d' % ip_packet.header.total_length,
    )

if __name__ == '__main__':
    main()
