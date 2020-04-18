#!/usr/bin/env python3

import ipaddress
import json
import os
import socket
import struct
import sys

import pytun

MAGIC = b'\x16\xd9\x6b\x52'
IP_V4_PROTO = b'\x08\x00'

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
        self.iface_netmask = data['iface_netmask']
        self.iface_mtu     = data['iface_mtu']

        self.iface_addr    = ipaddress.IPv4Address(data['iface_addr'])
        self.iface_dstaddr = ipaddress.IPv4Address(data['iface_dstaddr'])

class IpPacket:
    def __init__(self, header, body):
        self.header = header
        self.body = body

    def to_byte_string(self):
        return self.header.to_byte_string() + self.body

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

    def to_byte_string(self):
        return struct.pack(
            '>BBHHHBBH4s4sHBB',
            self.ver_ihl,
            self.tos,
            self.total_length,
            self.ident,
            self.flags_fragoffset,
            self.ttl,
            self.proto,
            self.chksum,
            self.src.packed,
            self.dst.packed,
            self.opt1,
            self.opt2,
            self.pad,
        )

def main():
    config_filename = sys.argv[1]

    with open(config_filename) as config_file:
        config = Config(json.load(config_file))

    print('TUN interface addr:     ', config.iface_addr)
    print('TUN interface dest addr:', config.iface_dstaddr)
    print('TUN interface name:     ', config.iface_name)

    tun_iface = pytun.TunTapDevice(name=config.iface_name)

    tun_iface.addr    = str(config.iface_addr)
    tun_iface.dstaddr = str(config.iface_dstaddr)
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

    conn.setblocking(0)
    os.set_blocking(tun_iface.fileno(), False)

    while True:
        handle_iface_data(conn, tun_iface, config)
        handle_stream_data(conn, tun_iface, config)

def handle_iface_data(conn, tun_iface, config):
    try:
        buf = tun_iface.read(tun_iface.mtu)
    except:
        return

    flags = buf[:2]
    proto = buf[2:4]

    if proto != IP_V4_PROTO:
        return

    ip_packet = IpPacket(IpHeader(buf[4:28]), buf[28:])

    handle_ip_packet(ip_packet, conn, tun_iface, config)

def handle_stream_data(conn, tun_iface, config):
    try:
        data = conn.recv(10000)
    except:
        return

    while data != b'':
        if data[0:4] != MAGIC:
            raise RuntimeError('invalid magic number')

        ip_packet_length = struct.unpack('>I', data[4:8])[0]

        if len(data) < ip_packet_length + 8:
            raise RuntimeError('not enough data')

        ip_packet_packed = data[8:8 + ip_packet_length]

        data = data[8 + ip_packet_length:]

        ip_packet = IpPacket(IpHeader(ip_packet_packed[:24]), ip_packet_packed[24:])

        handle_ip_packet(ip_packet, conn, tun_iface, config)

def handle_ip_packet(ip_packet, conn, tun_iface, config):
    print('-' * 100)
    print(
        ip_packet.header.src,
        '→',
        ip_packet.header.dst,
        'len: %d' % ip_packet.header.total_length,
    )

    ip_packet_packed = ip_packet.to_byte_string()

    if len(ip_packet_packed) != ip_packet.header.total_length:
        raise RuntimeError('invalid "total length" header value')

    if ip_packet.header.dst == config.iface_addr:
        print('sending to tun iface')
        buf = b'\x00\x00' + IP_V4_PROTO + ip_packet_packed
        tun_iface.write(buf)
    elif ip_packet.header.dst == config.iface_dstaddr:
        print('sending to remote peer')
        ip_packet_length = struct.pack('>I', len(ip_packet_packed))
        buf = MAGIC + ip_packet_length + ip_packet_packed
        conn.sendall(buf)
    else:
        print('unknown destination, doing nothing')

if __name__ == '__main__':
    main()
