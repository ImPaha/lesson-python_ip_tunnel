#!/usr/bin/env python3

import pytun

def main():
    tun_iface = pytun.TunTapDevice()

    print(tun_iface.name)

    tun_iface.addr = '10.0.0.1'
    tun_iface.dstaddr = '10.0.0.2'
    tun_iface.netmask = '255.255.255.0'
    tun_iface.mtu = 1500

    tun_iface.up()

    while True:
        buf = tun_iface.read(tun_iface.mtu)
        print(buf)

if __name__ == '__main__':
    main()
