import asyncore
import socket
import time
import random
import DeNiSePkg

keepalive_timeout = 10.0
serverip = '192.168.0.45'

lastdnspacket = 0

class local_reader(asyncore.file_dispatcher):
    def __init__(self, writer):
        asyncore.file_dispatcher.__init__(self, writer)
        self.writes = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.writes.setblocking(0)
        self.writes.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 15 )
        self.encoder = DeNiSePkg.Encoder('key', ['t.23.nu',
                                                 't.bewaff.net',
                                                 't.c0re.jp',
                                                 't.lolitacoders.org'])

    def handle_read(self):
        global lastdnspacket
        data = self.recv(8192)
        # send just read data out
        for x in self.encoder.encodeDnsQuery(DeNiSePkg.TYPE_PAYLOAD, 0, data):
            self.writes.sendto(x, (serverip, 53))
            lastdnspacket = time.time()
            print repr(x)

    def handle_error(self):
        import sys
        a, b, c = sys.exc_info()
        print sys.excepthook(a, b, c )
        
    def handle_write(self):
        pass

class dns_reader(asyncore.dispatcher):
    def __init__(self):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)

    def handle_read(self):
        data, source = self.recvfrom(8192)

    def handle_error(self):
        import sys
        a, b, c = sys.exc_info()
        print sys.excepthook(a, b, c )
        
    def handle_write(self):
        pass

c = local_reader(0)
        
def sendkeepalive():
    global lastdnspacket
    for x in c.encoder.encodeDnsQuery(DeNiSePkg.TYPE_KEEPALIVE, 0, str(int(time.time())/1000)):
        c.writes.sendto(x, (serverip, 53))
        lastdnspacket = time.time()


def loop():
    map=asyncore.socket_map
    poll_fun = asyncore.poll
    while map:
        poll_fun(keepalive_timeout/2, map)
        if lastdnspacket + keepalive_timeout < time.time():
            sendkeepalive()
        
loop()
