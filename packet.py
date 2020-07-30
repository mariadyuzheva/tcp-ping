#!/usr/bin/env python3

import socket
import struct
import time
import binascii


class PortScanner:
    PORT_STATES = {
        'SYN, ACK': 'open',
        'SYN, RST': 'closed'
    }

    def __init__(self, dest_ip, dest_port):
        self.packet = Packet(dest_ip, dest_port)
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.received = []
        self.conn_time = []

    def send_packet(self, sock, timeout):
        sock.sendto(self.packet.packet, (self.dest_ip, self.dest_port))

        timeout *= 1000
        time_s = time.time()
        try:
            while True:
                data = sock.recv(1024)
                received_packet = ReceivedPacket(data)
                response_time = (time.time() - time_s) * 1000
                if response_time > timeout:
                    self.conn_time.append(timeout)
                    self.received.append(0)
                    return None, timeout

                if self.packet_is_correct(received_packet):
                    self.conn_time.append(response_time)
                    self.received.append(1)
                    return received_packet, response_time

        except socket.timeout:
            self.conn_time.append(timeout)
            self.received.append(0)
            return None, timeout

    def packet_is_correct(self, received_packet):
        for sent, received in (
                (self.packet.dest_ip, received_packet.source_ip),
                (self.packet.dest_port, received_packet.source_port),
                (self.packet.source_ip, received_packet.dest_ip),
                (self.packet.SOURCE_PORT, received_packet.dest_port),
                (1, received_packet.ack_number)):
            if sent != received:
                return False
        return True

    def get_port_state(self, packet):
        if packet.flags in self.PORT_STATES:
            return self.PORT_STATES[packet.flags]
        return 'unexpected flags {}'.format(packet.flags)


class Packet:
    SOURCE_PORT = 1234
    VERSION = 4
    IHL = 5
    TYPE_OF_SERVICE = 0
    TOTAL_LENGTH = 40
    ID = 54321
    FLAGS = 0
    FRAG_OFF = 0
    TTL = 64
    PROTOCOL = socket.IPPROTO_TCP
    SEQ_NUMBER = 0
    ACK_NUMBER = 0
    DATA_OFFSET = 5
    WINDOW_SIZE = 28944
    URGENT_POINTER = 0

    def __init__(self, dest_ip, dest_port):
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.source_ip = self.get_source_ip()
        self.packet = self.get_ip_header() + self.get_tcp_header()

    @staticmethod
    def get_source_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        source_ip = s.getsockname()[0]
        s.close()
        return source_ip

    @staticmethod
    def count_checksum(data):
        checksum = 0
        for i in range(0, len(data), 2):
            if isinstance(data[i], str):
                word = (ord(data[i]) << 8) + ord(data[i + 1])
            else:
                word = (data[i] << 8) + data[i + 1]
            checksum = checksum + word

        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum = ~checksum & 0xffff
        return checksum

    def get_ip_header(self):
        checksum = 0
        source_addr = socket.inet_aton(self.source_ip)
        dest_addr = socket.inet_aton(self.dest_ip)

        ihl_version = (self.VERSION << 4) + self.IHL
        final_frag_off = (self.FLAGS << 13) + self.FRAG_OFF

        tmp_ip_header = struct.pack(
            "!BBHHHBBH4s4s", ihl_version, self.TYPE_OF_SERVICE,
            self.TOTAL_LENGTH, self.ID, final_frag_off, self.TTL,
            self.PROTOCOL, checksum, source_addr, dest_addr)

        final_ip_header = struct.pack(
            "!BBHHHBBH4s4s", ihl_version, self.TYPE_OF_SERVICE,
            self.TOTAL_LENGTH, self.ID, final_frag_off, self.TTL,
            self.PROTOCOL, self.count_checksum(tmp_ip_header),
            source_addr, dest_addr)

        return final_ip_header

    def get_tcp_header(self):
        checksum = 0
        syn = 1 << 1

        data_offset_flags = (self.DATA_OFFSET << 12) | syn
        source_addr = socket.inet_aton(self.source_ip)
        dest_addr = socket.inet_aton(self.dest_ip)

        tmp_tcp_header = struct.pack(
            "!HHLLHHHH", self.SOURCE_PORT, self.dest_port, self.SEQ_NUMBER,
            self.ACK_NUMBER, data_offset_flags, self.WINDOW_SIZE, checksum,
            self.URGENT_POINTER)

        pseudo_header = struct.pack(
            "!4s4sBBH", source_addr, dest_addr, checksum, self.PROTOCOL,
            len(tmp_tcp_header))

        final_checksum = self.count_checksum(pseudo_header + tmp_tcp_header)
        final_tcp_header = struct.pack(
            "!HHLLHHHH", self.SOURCE_PORT, self.dest_port, self.SEQ_NUMBER,
            self.ACK_NUMBER, data_offset_flags, self.WINDOW_SIZE,
            final_checksum, self.URGENT_POINTER)

        return final_tcp_header


class ReceivedPacket:
    FLAGS = {
        b'002': 'SYN',
        b'012': 'SYN, ACK',
        b'014': 'SYN, RST'
    }

    def __init__(self, header):
        self.unpacked_header = struct.unpack(
            '!BBHHHBBH4s4sHHLLHHHH', header[:40])

        self.total_length = self.unpacked_header[2]
        self.source_ip = socket.inet_ntoa(self.unpacked_header[8])
        self.dest_ip = socket.inet_ntoa(self.unpacked_header[9])
        self.source_port = self.unpacked_header[10]
        self.dest_port = self.unpacked_header[11]
        self.seq_number = self.unpacked_header[12]
        self.ack_number = self.unpacked_header[13]
        self.flags = binascii.hexlify(header)[65:68]

        if self.flags in self.FLAGS:
            self.flags = self.FLAGS[self.flags]
