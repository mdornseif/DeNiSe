from port53 import *
import socket, time, sys, random

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# s.setblocking(0)

name = 'pdns-%06i.test.23.nu'
ip = '127.0.0.1'

bytes = 0

for i  in range (15000):
  d = DNS()
  q = DNSQR()
  q.qname = (name) % i
  d.rd = 1
  d.qd = q
  d.do_build()
  p = str(d)
  bytes += s.sendto(p, 0, (ip, 5353))
  print q.qname
  time.sleep(0.01)
    