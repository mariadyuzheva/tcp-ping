#!/usr/bin/env python3

ERROR_PYTHON_VERSION = 1
ERROR_OS = 2
ERROR_ADMIN = 3
ERROR_MODULES_MISSING = 4
ERROR_HOSTNAME = 5
ERROR_PORT = 6
ERROR_PARAMETERS = 7
ERROR_SCANNING = 8
ERROR_MATPLOTLIB = 9
ERROR_GRAPH = 10

import sys
import os

if sys.version_info < (3, 6):
    print('Use python >= 3.6', file=sys.stderr)
    sys.exit(ERROR_PYTHON_VERSION)

if not sys.platform.startswith('linux'):
    print('This utility is applicable only for Linux', file=sys.stderr)
    sys.exit(ERROR_OS)

import socket
import argparse
import time
import itertools

try:
    from packet import PortScanner, ReceivedPacket
except Exception as e:
    print('Modules not found: "{}"'.format(e), file=sys.stderr)
    sys.exit(ERROR_MODULES_MISSING)


__author__ = 'Dyuzheva Maria'
__email__ = 'mdyuzheva@gmail.com'


def parse_args():
    parser = argparse.ArgumentParser(
        description='tcping',
        epilog='Author: {} <{}>'.format(__author__, __email__))

    parser.add_argument(
        'host', metavar='HOST', type=str, help='hostname or ip address')
    parser.add_argument(
        'port', metavar='PORT', type=int, help='port number')
    parser.add_argument(
        '-n', '--number', type=int,
        metavar='NUMBER', help='number of packets')
    parser.add_argument(
        '-i', '--interval', type=float, default=1,
        metavar='INTERVAL', help='interval between sending packets in seconds')
    parser.add_argument(
        '-t', '--timeout', type=float, default=1,
        metavar='TIMEOUT', help='waiting timeout in seconds')
    parser.add_argument(
        '-d', '--debug', action='store_true', default=False,
        help='disable debug mode')
    parser.add_argument(
        '-g', '--graph', type=str,
        metavar='FILENAME', help='displays the graph in the file')

    return parser.parse_args()


if parse_args().graph:
    try:
        import matplotlib
        import matplotlib.pyplot
    except Exception as e:
        print('matplotlib not found: "{}".'.format(e), file=sys.stderr)
        sys.exit(ERROR_MATPLOTLIB)


def get_statistics(dest_ip, dest_port, packet_number, conn_time, received):
    print('--- {}:{} tcping statistics ---'.format(dest_ip, dest_port))

    packet_loss = int((1 - sum(received) / packet_number) * 100)
    print('{} packets transmitted, {} received, {}% packet loss'.format(
        packet_number, sum(received), packet_loss))

    if sum(received):
        received_time = []

        for resp_time, received in zip(conn_time, received):
            if received:
                received_time.append(resp_time)

        min_time = format(min(received_time), '.2f')
        max_time = format(max(received_time), '.2f')
        average_time = format(sum(received_time) / len(received_time), '.2f')
        print('Response time: min={} ms, max={} ms, average={} ms'.format(
            min_time, max_time, average_time))


def dump_packet(packet):
    return (f'source={packet.source_ip}:{packet.source_port}, '
            f'dest={packet.dest_ip}:{packet.dest_port}, '
            f'protocol=TCP, len={packet.total_length}, '
            f'flags={packet.flags}, seq={packet.seq_number}, '
            f'ack={packet.ack_number}')


def print_result(scanner, received_packet, number, response_time, debug):
    if debug:
        print(''.join((
            'Sent: ', dump_packet(ReceivedPacket(scanner.packet.packet)))))

    if received_packet:
        if debug:
            print(''.join(('Received: ', dump_packet(received_packet))))

        print('%d bytes from %s:%d seq=%d time=%.2f ms [%s] port: %s '
              % (received_packet.total_length, scanner.dest_ip,
                 scanner.dest_port, number, response_time,
                 received_packet.flags,
                 scanner.get_port_state(received_packet)))
    else:
        print("%s:%d doesn't respond seq=%d time=%.2f ms"
              % (scanner.dest_ip, scanner.dest_port, number, response_time))


def scan_port(dest_ip, dest_port, number, interval, timeout, debug, graph):
    scanner = PortScanner(dest_ip, dest_port)
    timeout = min(timeout, interval)
    print("Sending {} bytes to {}:{}".format(
        scanner.packet.TOTAL_LENGTH, scanner.dest_ip,
        scanner.dest_port))

    with socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.settimeout(timeout)

        if number:
            packet_range = range(number)
        else:
            packet_range = itertools.count(0, 1)

        for curr_number in packet_range:
            try:
                received_packet, resp_time = scanner.send_packet(sock, timeout)
                print_result(scanner, received_packet, curr_number + 1,
                             resp_time, debug)
                if curr_number + 1 != number:
                    time.sleep(interval - resp_time / 1000)

            except KeyboardInterrupt:
                number = curr_number + 1
                break

    get_statistics(dest_ip, dest_port, number, scanner.conn_time,
                   scanner.received)
    if graph:
        try:
            build_graph(graph, number, interval, scanner)
        except Exception as e:
            print('Error while building graph\n{}'.format(e), file=sys.stderr)
            sys.exit(ERROR_GRAPH)


def build_graph(filename, number, interval, scanner):
    x_values = [(n + 1) * interval for n in range(number)]
    y_left_values = scanner.conn_time
    y_right_values = [(1 - sum(scanner.received[:(n + 1)]) / (n + 1)) * 100
                      for n in range(number)]

    matplotlib.rcParams['figure.figsize'] = (max(8.0, number * 1.0), 6.0)
    first_ax = matplotlib.pyplot.axes()
    first_line, = first_ax.plot(x_values, y_left_values, 'bo-')
    first_ax.axis([0, (number + 1) * interval,
                   -max(scanner.conn_time) * 0.01,
                   max(scanner.conn_time) * 1.05])
    first_ax.grid(color='b', ls=':', alpha=0.5)
    first_ax.set_xlabel('Time, sec (sent packets)')
    first_ax.set_ylabel('Response time, ms')
    first_ax.set_title(
        f'Tcping results for {scanner.dest_ip}:{scanner.dest_port}')

    second_ax = first_ax.twinx()
    second_line, = second_ax.plot(x_values, y_right_values, 'ro-')
    second_ax.axis([0, (number + 1) * interval, -0.5, 106])
    second_ax.set_xticks([n * interval for n in range(number + 2)])
    second_ax.set_xticklabels(
        [f'{n * interval} ({n})' for n in range(number + 2)])
    second_ax.set_ylabel('Loss rate, %')
    second_ax.grid(color='r', ls=':', alpha=0.5)

    second_ax.legend((first_line, second_line), ('Response time', 'Loss rate'),
                     loc='lower right')
    matplotlib.pyplot.savefig(filename)


def main():
    args = parse_args()
    if os.getuid() != 0:
        print('You need admin rights to run this application', file=sys.stderr)
        sys.exit(ERROR_ADMIN)

    try:
        dest_ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print('Wrong hostname {}'.format(args.host), file=sys.stderr)
        sys.exit(ERROR_HOSTNAME)

    dest_port = args.port
    if not 0 <= dest_port <= 65535:
        print('Wrong port number {}'.format(dest_port), file=sys.stderr)
        sys.exit(ERROR_PORT)

    if (any(p <= 0 for p in (args.interval, args.timeout))
            or args.number and args.number <= 0):
        print('Parameters should be positive', file=sys.stderr)
        sys.exit(ERROR_PARAMETERS)

    try:
        scan_port(dest_ip, dest_port, args.number, args.interval, args.timeout,
                  args.debug, args.graph)
    except Exception as e:
        print('Error while checking {}:{}\n{}'.format(dest_ip, dest_port, e),
              file=sys.stderr)
        sys.exit(ERROR_SCANNING)


if __name__ == '__main__':
    main()
