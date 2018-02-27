#!/usr/bin/env python3

import socket
import sys
import threading

from tftp_common import TFTPConnection, TransferModes, ErrorPacket, ErrorCodes, RRQPacket, DEBUG, TFTPPacket, \
    OACKPacket, ACKPacket


class TFTPServerConnection(TFTPConnection):
    def __init__(self, client_address, base_path: bytes):
        connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        connection.bind(('', 0))
        super().__init__(connection, client_address)
        self.base_path = base_path

    def handle_file_request(self, packet: RRQPacket):
        if packet.bad_opts:
            if DEBUG:
                print('Bad opts')
            self.send_packet(ErrorPacket(ErrorCodes.UNSUPPORTED_OPTS, b'Only blksize and windowsize opts supported'))
            return
        if packet.mode != TransferModes.OCTET:
            if DEBUG:
                print('Bad mode: ', packet.mode)
            self.send_packet(ErrorPacket(ErrorCodes.ILLEGAL_OPERATION, b'Only octet mode supported'))
            return
        if packet.block_size != 512 or packet.window_size != 1:
            counter = 0
            while counter < 20:
                counter += 1
                self.send_packet(OACKPacket(packet.block_size, packet.window_size))
                try:
                    packed, _ = self.receive_packet()
                except TimeoutError:
                    pass
                if isinstance(packet, ACKPacket):
                    if packet.ack_id == 0:
                        break
        try:
            file = open(self.base_path + packet.filename, 'rb')
            self.transmit_file(file, packet.block_size, packet.window_size)
            file.close()
        except IOError as er:
            self.send_packet(ErrorPacket(ErrorCodes.FILE_NOT_FOUND, str(er).encode('utf8')))


class TFTPServer:
    def __init__(self, bind_to: str = '', port: int = 6969, base_path: bytes = b''):
        self.master_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.master_socket.bind((bind_to, port))
        self.base_path = base_path

    def file_request(self, packet: RRQPacket, client_address):
        if DEBUG:
            print('File requested ', packet.filename)
        connection = TFTPServerConnection(client_address, base_path=self.base_path)
        connection.handle_file_request(packet)
        connection.close()

    def run(self):
        while True:
            frame, client_address = self.master_socket.recvfrom(65535)
            if DEBUG:
                print('Connection form ', client_address)
            packet = TFTPPacket.decode(frame)
            if isinstance(packet, RRQPacket):
                threading.Thread(target=self.file_request, args=(packet, client_address)).run()


path = sys.argv[2].encode('utf8')
if path[-1] != b'/':
    path += b'/'
TFTPServer(port=int(sys.argv[1]), base_path=path).run()
