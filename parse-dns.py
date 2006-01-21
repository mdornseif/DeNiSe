from port53 import *
import socket, time, sys, random

logfile = open('dnslog--airvent.txt', 'r')
for line in logfile:
  try:
    (p, recv, t) = eval(line)
    answer, (ip, port) = recv
    # print ip, port
    d = DNS()
    try:
      d.dissect(answer)
      if d.arcount > 0:
        r = d.ar
        while r:
          print ip, port, d.arcount, d.rcode, r.rrname, dnstypes[r.type], repr(r.rdata) #, repr(d)
          r = r.payload
    except:
      pass
  except SyntaxError:
    pass
