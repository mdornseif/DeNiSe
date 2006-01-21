from port53 import *
import socket, time, sys, random

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# s.setblocking(0)

name = 'mara-%06i.test.23.nu'
ip = '213.221.113.2'
for i  in range (100000):
  d = DNS()
  q = DNSQR()
  q.qname = name % i
  d.rd = 1
  d.qd = q
  d.do_build()
  p = str(d)
  bytes += s.sendto(p, 0, (ip, 53))
  time.sleep(0.01)
    