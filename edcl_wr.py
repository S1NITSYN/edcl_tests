#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sock_edcl_rdwr import *
import time
import argparse

def read_data(edcl_c, file, addr, size):
    f = open(file, "wb")

    data = edcl_c.read(addr.to_bytes(4, "big"), size)

    f.write(data)

    f.close()

def write_data(edcl_c, file, addr):
    f = open(file, "rb")

    data = f.read()

    if len(data) % 4 != 0:
        data += b'\0' * (4 - len(data) % 4)
        print ("WARNING: file size is not aligned to 4 bytes")
        print ("WARNING: file padded to ", len(data), " bytes")

    edcl_c.write((addr + 0x4).to_bytes(4, "big"), len(data) - 4, data[4:])

    time.sleep(0.2)

    edcl_c.write(addr.to_bytes(4, "big"), 4, data[0:4])

    f.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send/Receive data trough EDCL')
    parser.add_argument('-f', '--file', required=True,
                        help='binary file to send / to dump in')
    parser.add_argument('-a', '--addr', required=True, help='address of memory',
                        type=lambda x: int(x,0))
    parser.add_argument('-i', '--ip', help='target ip address', required=True)
    parser.add_argument('-o', '--operation', required=True, choices=['read', 'write'],
                        help='select operation: read / write')
    parser.add_argument('-s', '--size',
                        help='number of bytes to read (ignored for write)',
                        type=lambda x: int(x,0))
    args = parser.parse_args()

    if args.operation == "read" and args.size is None:
        print ("Argument 'size' is required to read data")
        exit()

    edcl_c = edcl(args.ip)

    if args.operation == "read":
        read_data(edcl_c, args.file, args.addr, args.size)
    else:
        write_data(edcl_c, args.file, args.addr)
