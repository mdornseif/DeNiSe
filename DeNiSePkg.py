""" Decode and encode Data in DNS querys or DNS answer RRs.

This functions encapsulate and deencapsulate data in a series of
FQDNs suited for transmitting Data via DNS. The data is compressed,
fragmented and encoded before sending.

You create a Encode() or Decode() object instance and use its
encodeDns() or decodeDns() methods.

Data structure:

TTFFSLXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
TFSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

T = Packet Type
F = Flags
C - ClientID
S = Sequence number
L = Length of Payload
X = Payload (max 74 bytes)

"""

# hacked on devcon X by robotnik and drt --hackers@c0re.jp

FLAG_LASTFRAGMENT = 1
TYPE_PAYLOAD = 1
TYPE_KEEPALIVE = 2

import base64
import zlib
import random
import Crypto.Cipher.AES
import DNS.Lib
import DNS.Type
import DNS.Opcode
import DNS.Class

def pad(inbuf, bytes, pchar = '='):
   "Pad inbuf to multiples of bytes using pchar."
   if len(inbuf) % bytes > 0:
      p = bytes - (len(inbuf) % bytes)
      return inbuf + (pchar * p) 
   return inbuf

def padRand(inbuf, bytes):
   "Pad inbuf to multiples of bytes using pseudo-random characters."
   if len(inbuf) % bytes > 0:
      p = bytes - (len(inbuf) % bytes)
      ps = []
      for i in range(p):
         ps.append(chr(random.randrange(256)))
      return inbuf + ''.join(ps)
   return inbuf


class Encoder:
   """Encode data in a stream of DNS queries.

   You have to call the constructor with a AES key (preferable 32
   bytes) and a list of domains which can be used to access the tunneling Server.

   Then just call encodeDns(packettype, flags, data) and you get a
   list of FQDNs to request for data transport.
   """
   
   def __init__(self, key, domains):
      self._sequence_number = 0
      self.domains = domains
      self.cipher = Crypto.Cipher.AES.new(pad(key, 16))
      self.maxfragmentsize = 72

   def encode64(self, inbuf):       
      return base64.encodestring(inbuf).replace('+', '-').replace('/', '_').replace('\n', '').strip()

   def encodePacket(self, data, flags, seq):
      """Encode a single Packet of Data"""
      
      s = "%s%s%s%s" % (chr(flags),
                        chr(seq),
                        chr(len(data)),
                        data)
      s = padRand(s, 16)
      s = self.cipher.encrypt(s)
      s = self.encode64(s)
      s = s.replace('=', '')
      return s

   def fragmentData(self, data, flags=0):
      """Break down a big chunk of bytes into packets and encode them."""
      self._sequence_number = 0
      cdata = zlib.compress(data)
      ret = []
      for i in range(0, len(cdata), self.maxfragmentsize):
         if i > len(cdata) - self.maxfragmentsize:
            # last packet
            ret.append(self.encodePacket(cdata[i:i+self.maxfragmentsize],
                                         flags | FLAG_LASTFRAGMENT,
                                         self._sequence_number))
         else:
            ret.append(self.encodePacket(cdata[i:i+self.maxfragmentsize],
                                         flags, self._sequence_number,
                                         self._sequence_number))
         self._sequence_number = (self._sequence_number + 1) % 256
      return ret

   def encodeDns(self, data, flags=0):
      """Break down a big chunk of bytes into packets and encode them as dmonainnames"""
      ret = []
      for x in self.fragmentData(data, flags):
         # split into host and subdomain
         spos = random.randrange(max([len(x) - 62, 0]), min([63, len(x)]))
         ret.append("x%s.%s" % ('.x'.join([x[:spos], x[spos:]]), random.choice(self.domains)))
      return ret

   def encodeDnsQuery(self, data, flags=0):
      ret = []
      for x in self.encodeDns(data, flags):      
         m = DNS.Lib.Mpacker()
         m.addHeader(1234, 0, DNS.Opcode.QUERY, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0)
         m.addQuestion(x, DNS.Type.TXT, DNS.Class.IN)
         ret.append(m.getbuf())
      return ret

   def encodeDnsResponse(self, data, query='\0x5dummy\0x7example\0x3com\0x0', flags=0,):
      ret = []
      for x in self.fragmentData(data, flags):      
         m = DNS.Lib.Mpacker()
         m.addHeader(1234, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0)
         m.addQuestion('\0x3bla\0x0', DNS.Type.TXT, DNS.Class.IN)
         m.addTXT(query, DNS.Class.IN, 3, x)
         ret.append(m.getbuf())
      return ret



class Decoder:
   def __init__(self, key, domains):
      self.cipher = Crypto.Cipher.AES.new(pad(key, 16))
      self.domains = domains
      self.datastore = {}
      self.seen_lastfragment = 1
      self.packetqueue = []

   def checkDataComplete(self):
      k = self.datastore.keys()
      for i in range(max(k)):
         if not  self.datastore.has_key(i+1):
            return None
      return 1

   def packetsToData(self):
      k = self.datastore.keys()
      k.sort()
      ret = []
      for i in k:
         ret.append(self.datastore[i][0])
      return zlib.decompress(''.join(ret))
      
   def removeDomain(self, data):
      for x in self.domains:
         if data.endswith(x):
            return data[:data.find(x)]

   def rfc1035ToFqdn(self, data):
      """convert an "pascal encoded" dns name in an packetet to a string"""
      ret = []
      i = 0
      c = ord(data[i])
      while 1:
         ret.append(data[i+1:i+1+c])
         i = i + c + 1
         c = ord(data[i])
         if c == 0:
            break
      return '.'.join(ret)
   
   def decode64(self, inbuf):
      return base64.decodestring(inbuf.replace('-', '+').replace('_', '/'))

   def decodePacket(self, inbuf):
      s = pad(inbuf, 4)
      s = self.decode64(s + '=')
      s = self.cipher.decrypt(s)
      flags = ord(s[0])
      seq = ord(s[1])
      plen = ord(s[2])
      data = s[3:plen + 3]
      return (data, flags, seq)

   def decodeData(self, data):
      for p in data:
         payload, flags, serial = self.decodePacket(p)
         self.datastore[serial] = (payload, flags, serial)
         if flags & FLAG_LASTFRAGMENT == FLAG_LASTFRAGMENT:
            self.seen_lastfragment = 1
      if self.seen_lastfragment == 1:
         if self.checkDataComplete():
            return self.packetsToData(), (flags ^ FLAG_LASTFRAGMENT)
      return None

   def decodeDns(self, data):
      buf = []
      for s in data:
         s = s[1:]
         buf.append(self.removeDomain(s.replace('.x', '')))
      return self.decodeData(buf)

   def decodeDnsQuery(self, datal):
      self.packetqueue.extend(datal) 
      if not self.packetqueue:
         return None
      data = self.packetqueue.pop(0)
      while data:
         s = data[12:]
         s = self.rfc1035ToFqdn(s)
         ret = self.decodeDns([s])
         if ret:
            return ret
         if not self.packetqueue:
            return None
         data = self.packetqueue.pop(0)

   
   
class BDecoder:


   def decodeDnsQuery(self, data):
      "feed me one packet at time"
      # parse DNS packet
      m = DNS.Lib.Munpacker(data[0])
      r = DNS.Lib.DnsResult(m, None) 
      for x in  r.answers:
         if x['typename'] == 'TXT':
            return self.decodeDns(x['data'])

def test(indata, transform1, transform2):
   print indata,
   x = transform1(*indata)
   print x,
   y = transform2(*(x,))
   print y, transform1, transform2
   assert y == indata

if __name__ == '__main__':
   longdata = """Dies ist ein Test Text.

   Und der sollte schön lang sein, damit er kompremiert immernoch
   deutlich länger als 74 Zeichen ist und in mehr als ein Datenpaket
   kompremiert. Ob das jetzt reicht?
   
   """
   
   e = Encoder('key', ['t.23.nu', 't.bewaff.net', 't.c0re.jp', 't.lolitacoders.org'])
   d = Decoder('key', ['t.23.nu', 't.bewaff.net', 't.c0re.jp', 't.lolitacoders.org'])



   for data in ("Test", longdata):
      data = "Test"
      test((data, 0, 0), e.encodePacket, d.decodePacket)
      test((data, 0), e.encodeDns, d.decodeDns)
      test((data, 0), e.encodeDnsQuery, d.decodeDnsQuery)
      print e.encodeDnsResponse("TEST")
   #x = e.encodePacket(0,0, "Test")
   #x = e.encodeDnsResponse('\0x3die\0x8original\0x5query\0x5kommt\0x4hier\x02de\0x0', 0, 0, "Test")
   #print d.decodeDnsQuery(x)
