#!/usr/bin/env python3

import os
import sys
import unittest
import socket
import binascii
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from packet import PortScanner, Packet, ReceivedPacket


class TestPacket(unittest.TestCase):
    def test_form_syn_packet(self):
        dest_ip = '10.10.10.2'
        dest_port = 80
        packet = Packet(dest_ip, dest_port)

        self.assertEqual(binascii.hexlify(packet.packet)[65:68], b'002')

    def test_count_checksum(self):
        checksum = Packet.count_checksum(
            b'E\x00\x00(\xab\xcd\x00\x00@\x06\x00\x00\n\n\n\x01\n\n\n\x02')
        self.assertEqual(checksum, 0xa6ec)


REQUIREMENTS = sys.platform.startswith('linux') and os.getuid() == 0
REASON = 'requires linux and admin rights'


class TestPortScanner(unittest.TestCase):
    @unittest.skipIf(not REQUIREMENTS, REASON)
    def test_send_packets_to_open_port(self):
        dest_ip = socket.gethostbyname('google.com')
        dest_port = 80
        scanner = PortScanner(dest_ip, dest_port)
        timeout = 5
        number = 3

        with socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(timeout)

            for n in range(number):
                received_packet, _ = scanner.send_packet(sock, timeout)
                self.assertEqual(received_packet.flags, 'SYN, ACK')

        self.assertEqual(scanner.received, [1, 1, 1])

    @unittest.skipIf(not REQUIREMENTS, REASON)
    def test_send_packets_to_closed_port(self):
        dest_ip = socket.gethostbyname('localhost')
        dest_port = 1234
        scanner = PortScanner(dest_ip, dest_port)
        timeout = 5
        number = 3

        with socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(timeout)

            for n in range(number):
                received_packet, _ = scanner.send_packet(sock, timeout)
                self.assertEqual(received_packet.flags, 'SYN, RST')

        self.assertEqual(scanner.received, [1, 1, 1])

    @unittest.skipIf(not REQUIREMENTS, REASON)
    def test_send_packet_without_response(self):
        dest_ip = socket.gethostbyname('google.com')
        dest_port = 1234
        scanner = PortScanner(dest_ip, dest_port)
        timeout = 2
        number = 3

        with socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(timeout)

            for n in range(number):
                response = scanner.send_packet(sock, timeout)
                self.assertEqual(response, (None, timeout * 1000))

        self.assertEqual(scanner.received, [0, 0, 0])

    @unittest.skipIf(not REQUIREMENTS, REASON)
    def test_timeout(self):
        dest_ip = socket.gethostbyname('google.com')
        dest_port = 80
        scanner = PortScanner(dest_ip, dest_port)
        timeout = 0.5
        number = 3

        with socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(timeout)

            for n in range(number):
                scanner.send_packet(sock, timeout)

        for t in scanner.conn_time:
            self.assertTrue(t <= timeout * 1000)

    @unittest.skipIf(not REQUIREMENTS, REASON)
    def test_received_packets_correct(self):
        dest_ip = socket.gethostbyname('google.com')
        dest_port = 80
        scanner = PortScanner(dest_ip, dest_port)
        timeout = 5
        number = 3

        with socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(timeout)

            for n in range(number):
                packet, _ = scanner.send_packet(sock, timeout)
                self.assertTrue(scanner.packet_is_correct(packet))

    def test_packet_is_correct(self):
        scanner = PortScanner('10.10.10.2', 80)

        with patch('packet.ReceivedPacket') as mock:
            packet = mock.return_value
            packet.source_ip = scanner.packet.dest_ip
            packet.source_port = scanner.packet.dest_port
            packet.dest_ip = scanner.packet.source_ip
            packet.dest_port = scanner.packet.SOURCE_PORT
            packet.ack_number = 1

            self.assertTrue(scanner.packet_is_correct(packet))

    def test_packet_not_correct(self):
        scanner = PortScanner('10.10.10.2', 80)

        with patch('packet.ReceivedPacket') as mock:
            packet = mock.return_value
            packet.source_ip = scanner.packet.dest_ip
            packet.source_port = scanner.packet.dest_port
            packet.dest_ip = scanner.packet.source_ip
            packet.dest_port = scanner.packet.SOURCE_PORT
            packet.ack_number = 1

            wrong_packet = packet
            wrong_packet.source_ip = '10.10.10.1'
            self.assertFalse(scanner.packet_is_correct(packet))

            wrong_packet = packet
            wrong_packet.source_port = 1234
            self.assertFalse(scanner.packet_is_correct(packet))

            wrong_packet = packet
            wrong_packet.ack_number = 100
            self.assertFalse(scanner.packet_is_correct(packet))

    def test_port_state(self):
        scanner = PortScanner('10.10.10.2', 80)

        with patch('packet.ReceivedPacket') as mock:
            packet = mock.return_value
            packet.flags = 'SYN, ACK'
            self.assertEqual(scanner.get_port_state(packet), 'open')

            packet.flags = 'SYN, RST'
            self.assertEqual(scanner.get_port_state(packet), 'closed')

            packet.flags = 'SYN'
            self.assertEqual(
                scanner.get_port_state(packet), "unexpected flags SYN")


if __name__ == '__main__':
    unittest.main()
