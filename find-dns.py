from port53 import *
import socket, time, sys, random

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setblocking(0)

bps = 25 * 1024

def walkIpSpace():
  r1 = range(256)
  r2 = range(256)
  r3 = range(256)
  r4 = range(256)
  random.shuffle(r1)
  random.shuffle(r2)
  random.shuffle(r3)
  random.shuffle(r4)
  for d in r1:
    for b in r2:
      for c in r3:
        for a in r4:
          if a == 127:
            continue
          yield '%i.%i.%i.%i' % (a, b, c, d)  
        random.shuffle(r4)
      random.shuffle(r3)
    random.shuffle(r2)
  random.shuffle(r1)

bytes = 0
starttime = time.time()
logfile = open('dnslog.txt', 'a')
for ip in walkIpSpace():
  for name in ['localhost', 'www.microsoft.com', 'localhost.localdomain']:
    d = DNS()
    q = DNSQR()
    q.qname = name
    d.rd = 1
    d.qd = q
    d.do_build()
    p = str(d)
    try:
      bytes += s.sendto(p, 0, (ip, 53))
    except socket.error, msg:
      print '%s: %s' % (ip, msg)
    try:
      recv = s.recvfrom(800)
      info = (p, recv, time.time())
      logfile.write(repr(info))
      logfile.write("\n")
      print recv
    except socket.error:
      pass  
    while bytes / (time.time() - starttime) > bps:
      print ip, "bps: %i\t\t\t\r" % (bytes / (time.time() - starttime)),
      sys.stdout.flush()
      time.sleep(0.001)
    