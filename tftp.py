#!/usr/bin/env python3

import socket
import hashlib
import binascii
import sys

from tftp_common import TFTPConnection, RRQPacket, TransferModes

BLOCK_SIZE = 2048
WINDOW_SIZE = 10
OUT_FILENAME = 'out'


class TFTPClient(TFTPConnection):
    def __init__(self, server_address: str, port: int = 6969):
        super().__init__(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), (server_address, port))

    def request_file(self, filename: bytes, block_size: int = 512, window_size: int = 1):
        self.send_packet(RRQPacket(filename, TransferModes.OCTET, block_size, window_size))

    def download_file(self, filename: bytes, block_size: int = 512, window_size: int = 1):
        self.request_file(filename, block_size, window_size)
        return self.receive_file()


m = hashlib.md5()
client = TFTPClient(sys.argv[1], int(sys.argv[2]))
data = client.download_file(sys.argv[3].encode('utf8'), block_size=BLOCK_SIZE, window_size=WINDOW_SIZE)
m.update(data)
print(binascii.hexlify(m.digest()).decode('utf8'))
file = open(OUT_FILENAME, 'wb')
file.write(data)
file.close()
