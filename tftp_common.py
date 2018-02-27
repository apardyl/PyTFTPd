import socket
from enum import Enum, unique
import signal

DEBUG = False
INFO = True


@unique
class OptCodes(Enum):
    UNKNOWN = 0
    RRQ = 1
    WRQ = 2
    DATA = 3
    ACK = 4
    ERROR = 5
    OACK = 6


@unique
class ErrorCodes(Enum):
    UNDEFINED = 0
    FILE_NOT_FOUND = 1
    ACCESS_VIOLATION = 2
    DISK_FULL_OR_ALLOCATION_EXCEEDED = 3
    ILLEGAL_OPERATION = 4
    UNKNOWN_TRANSFER_ID = 5
    FILE_EXISTS = 6
    NO_SUCH_USER = 7
    UNSUPPORTED_OPTS = 9


class TransferModes(Enum):
    UNKNOWN = b'unknown'
    OCTET = b'octet'

    @staticmethod
    def get_mode(mode: bytes):
        try:
            return TransferModes(mode)
        except ValueError:
            return TransferModes.UNKNOWN


class TFTPPacket:
    def __init__(self, opt_code):
        self.opt_code = opt_code

    def encode(self):
        return bytearray([(self.opt_code.value & 0xFF00) >> 8, self.opt_code.value & 0xFF])

    @staticmethod
    def parse(packet: bytes):
        pass

    @staticmethod
    def decode(packet: bytes):
        if len(packet) < 2:
            return UnknownPacket()
        opt_code = (packet[0] << 8) | packet[1]
        return {
            OptCodes.UNKNOWN: UnknownPacket,
            OptCodes.RRQ: RRQPacket,
            OptCodes.WRQ: WRQPacket,
            OptCodes.DATA: DATAPacket,
            OptCodes.ACK: ACKPacket,
            OptCodes.ERROR: ErrorPacket,
            OptCodes.OACK: OACKPacket,
        }.get(OptCodes(opt_code), UnknownPacket()).parse(packet)


class ACKPacket(TFTPPacket):
    def __init__(self, ack_id):
        super().__init__(OptCodes.ACK)
        self.ack_id = ack_id

    def encode(self):
        data = super().encode()
        data.append((self.ack_id & 0xFF00) >> 8)
        data.append(self.ack_id & 0xFF)
        return data

    @staticmethod
    def parse(packet: bytes):
        return ACKPacket((packet[2] << 8) | packet[3])


class OACKPacket(TFTPPacket):
    def __init__(self, block_size=512, window_size=1):
        super().__init__(OptCodes.OACK)
        self.block_size = block_size
        self.window_size = window_size

    def encode(self):
        data = super().encode()
        if self.block_size != 512:
            data += b'blksize'
            data.append(0)
            data += str(self.block_size).encode('utf8')
            data.append(0)
        if self.window_size != 1:
            data += b'windowsize'
            data.append(0)
            data += str(self.window_size).encode('utf8')
            data.append(0)
        return data

    @staticmethod
    def parse(packet: bytes):
        block_size = 512
        window_size = 1
        packet = packet[2:].split(b'\0')
        for i in range(0, len(packet), 2):
            if packet[i].lower() == b'blksize':
                block_size = int(packet[i + 1])
            elif packet[i].lower() == b'windowsize':
                window_size = int(packet[i + 1])
        return OACKPacket(block_size, window_size)


class DATAPacket(TFTPPacket):
    def __init__(self, packet_id, payload: bytes):
        super().__init__(OptCodes.DATA)
        self.packet_id = packet_id
        self.payload = payload

    def encode(self):
        data = super().encode()
        data.append((self.packet_id & 0xFF00) >> 8)
        data.append(self.packet_id & 0xFF)
        data += self.payload
        return data

    @staticmethod
    def parse(packet: bytes):
        return DATAPacket((packet[2] << 8) | packet[3], packet[4:])


class ErrorPacket(TFTPPacket):
    def __init__(self, error_code, error_msg: bytes):
        super().__init__(OptCodes.ERROR)
        self.error_code = error_code
        self.error_msg = error_msg

    def encode(self):
        data = super().encode()
        data.append((self.error_code.value & 0xFF00) >> 8)
        data.append(self.error_code.value & 0xFF)
        data += self.error_msg
        data.append(0)
        return data

    @staticmethod
    def parse(packet: bytes):
        return ErrorPacket(ErrorCodes((packet[2] << 8) | packet[3]), packet[4:-1])


class RQPacket(TFTPPacket):
    def __init__(self, opt_code, filename: bytes, mode: TransferModes, block_size: int = 512, window_size: int = 1,
                 bad_opts=False):
        super().__init__(opt_code)
        self.filename = filename
        self.mode = mode
        self.block_size = block_size
        self.window_size = window_size
        self.bad_opts = bad_opts

    def encode(self):
        data = super().encode()
        data += self.filename
        data.append(0)
        data += self.mode.value
        data.append(0)
        if self.block_size != 512:
            data += b'blksize'
            data.append(0)
            data += str(self.block_size).encode('utf8')
            data.append(0)
        if self.window_size != 1:
            data += b'windowsize'
            data.append(0)
            data += str(self.window_size).encode('utf8')
            data.append(0)
        return data

    @staticmethod
    def parse(packet: bytes):
        pass

    @staticmethod
    def parse_rq(packet: bytes, constructor):
        block_size = 512
        window_size = 1
        bad_opts = False
        packet = packet[2:].split(b'\0')
        for i in range(2, len(packet), 2):
            if packet[i].lower() == b'blksize':
                block_size = int(packet[i + 1])
            elif packet[i].lower() == b'windowsize':
                window_size = int(packet[i + 1])
            elif packet[i] != b'':
                bad_opts = True
        return constructor(packet[0], TransferModes.get_mode(packet[1]), block_size, window_size, bad_opts)


class RRQPacket(RQPacket):
    def __init__(self, filename: bytes, mode: TransferModes, block_size: int = 512, window_size: int = 1,
                 bad_opts=False):
        super().__init__(OptCodes.RRQ, filename, mode, block_size, window_size, bad_opts)

    @staticmethod
    def parse(packet: bytes):
        return RQPacket.parse_rq(packet, RRQPacket)


class WRQPacket(RQPacket):
    def __init__(self, filename: bytes, mode: TransferModes, block_size: int = 512, window_size: int = 1,
                 bad_opts=False):
        super().__init__(OptCodes.WRQ, filename, mode.value, block_size, window_size, bad_opts)

    @staticmethod
    def parse(packet: bytes):
        return RQPacket.parse_rq(packet, WRQPacket)


class UnknownPacket(TFTPPacket):
    def __init__(self):
        super().__init__(OptCodes.UNKNOWN)

    @staticmethod
    def parse(packet: bytes):
        return UnknownPacket()


def timeout_handler(signum, frame):
    if INFO:
        print('TIMEOUT')
    raise TimeoutError()


class TFTPConnection:
    def __init__(self, connection: socket.socket, client_address):
        self.connection = connection
        self.client_address = client_address
        self.frame_size = 512
        self.window_size = 1

    def close(self):
        self.connection.close()

    def send_packet(self, packet: TFTPPacket):
        self.connection.sendto(packet.encode(), self.client_address)

    def receive_packet(self):
        signal.signal(signal.SIGALRM, timeout_handler)
        while True:
            signal.setitimer(signal.ITIMER_REAL, 0.1)
            frame = self.connection.recvfrom(65535)
            signal.setitimer(signal.ITIMER_REAL, 0)
            try:
                return TFTPPacket.decode(frame[0]), frame[1]
            except RuntimeError:
                pass

    def receive_file(self):
        data = bytearray()
        packet = None
        current_id = 1
        timeout_counter = 0
        window_state = [None] * self.window_size
        window_count = 0
        batch_size = self.window_size + 1
        while timeout_counter < 300:
            try:
                packet, self.client_address = self.receive_packet()
            except TimeoutError:
                timeout_counter += 1
                if packet is not None:
                    for i in range(0, self.window_size):
                        if window_state[i] is not None:
                            current_id = (current_id + 1) % 65536
                            data += window_state[i]
                        else:
                            break
                    for i in range(0, self.window_size):
                        window_state[i] = None
                    window_count = 0
                    self.send_packet(ACKPacket(current_id))
                continue
            if isinstance(packet, DATAPacket):
                if (current_id <= packet.packet_id < min(current_id + self.window_size, 65536)) \
                        or (packet.packet_id < current_id + self.window_size - 65536):
                    pos = packet.packet_id - current_id if current_id <= packet.packet_id else packet.packet_id + (
                            65536 - current_id)
                    if window_state[pos] is not None:
                        if INFO:
                            print('Ignoring (duplicated) ', packet.packet_id)
                        continue
                    else:
                        window_state[pos] = packet.payload
                        if len(packet.payload) < self.frame_size:
                            batch_size = pos + 1
                        window_count += 1
                        if INFO:
                            print('Received', packet.packet_id)
                        if DEBUG:
                            print(packet.packet_id, ' - ', packet.payload)
                        if window_count == self.window_size or window_count == batch_size:
                            for i in range(0, min(self.window_size, batch_size)):
                                data += window_state[i]
                                window_state[i] = None
                            current_id = (current_id + min(self.window_size, batch_size) - 1) % 65536
                            self.send_packet(ACKPacket(current_id))
                            current_id = (current_id + 1) % 65536
                            if window_count == batch_size:
                                return data
                            window_count = 0
                            timeout_counter = 0
                else:
                    if INFO:
                        print('Ignoring ', packet.packet_id)
                    continue
            elif isinstance(packet, OACKPacket):
                self.frame_size = packet.block_size
                self.window_size = packet.window_size
                batch_size = self.window_size + 1
                window_state = [None] * self.window_size
                self.send_packet(ACKPacket(0))
                packet = None
            elif isinstance(packet, ErrorPacket):
                print("Error ", packet.error_code.name, " ", packet.error_msg)
                raise RuntimeError
        raise TimeoutError

    def transmit_file_part(self, file, current_id: int, block_id: int):
        file.seek((block_id * 65536 + current_id - 1) * self.frame_size)
        data = file.read(self.frame_size)
        if INFO:
            print('Sending ' + str(block_id) + ':' + str(current_id))
        if DEBUG:
            print(str(block_id) + ':' + str(current_id) + ' - ', data)

        self.send_packet(DATAPacket(current_id, data))
        return len(data) == self.frame_size

    def transmit_file(self, file, block_size: int = 512, window_size: int = 1):
        self.frame_size = block_size
        self.window_size = window_size
        current_id = 1
        block_id = 0
        timeout_counter = 0
        next_packet = True
        last_sent = 0
        while timeout_counter < 300:
            for i in range(0, self.window_size):
                next_packet = self.transmit_file_part(file, (current_id + i) % 65536,
                                                      block_id + ((current_id + i) // 65536))
                last_sent = (current_id + i) % 65536
                if not next_packet:
                    break
            try:
                packet, _ = self.receive_packet()
            except TimeoutError:
                timeout_counter += 1
                continue

            if isinstance(packet, ACKPacket):
                if INFO:
                    print('Got ACK ', packet.ack_id)
                if (current_id <= packet.ack_id <= last_sent) or (last_sent < current_id <= packet.ack_id <= 65535) \
                        or (packet.ack_id <= last_sent < current_id):
                    if current_id > packet.ack_id:
                        block_id += 1
                    current_id = (packet.ack_id + 1) % 65536
                    block_id += (packet.ack_id + 1) // 65536
                else:
                    if INFO:
                        print('Ignoring ACK ', packet.ack_id)
                    continue
                if (not next_packet) and last_sent == packet.ack_id:
                    if INFO:
                        print('DONE')
                    return
            elif isinstance(packet, ErrorPacket):
                if INFO:
                    print('Error packet received')
                return
        print('Giving up')
        raise TimeoutError
