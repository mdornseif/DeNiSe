""" Decode and encode Data in DNS querys or DNS answer RRs.

This functions encapsulate and deencapsulate data in a series of
FQDNs suited for transmitting Data via DNS. The data is compressed,
fragmented and encoded before sending.

You create a Encode() or Decode() object instance and use its
encodeDns() or decodeDns() methods.

Data structure:

TTFFSLXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

T = Packet Type
F = Flags
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

   def encode64(self, inbuf):       
      return base64.encodestring(inbuf).replace('+', '-').replace('/', '_').replace('\n', '').strip()

   def encodePacket(self, ptype, flags, data):
      s = "%s%s%s%s%s%s%s" % (chr((ptype >> 8) & 0xff),
                              chr(ptype & 0xff),
                              chr((flags >> 8) & 0xff),
                              chr(flags & 0xff),
                              chr(self._sequence_number),
                              chr(len(data)), data)
      self._sequence_number = (self._sequence_number + 1) % 256
      s = padRand(s, 16)
      s = self.cipher.encrypt(s)
      s = self.encode64(s)
      s = s.replace('=', '')
      return s

   def encodeData(self, ptype, flags, data):
      self._sequence_number = 0
      cdata = zlib.compress(data)
      ret = []
      for i in range(0, len(cdata), 74):
         if i > len(cdata) - 74:
            # last packet
            ret.append(self.encodePacket(ptype, flags | FLAG_LASTFRAGMENT, cdata[i:i+74]))
         else:
            ret.append(self.encodePacket(ptype, flags, cdata[i:i+74]))
      return ret

   def encodeDns(self, ptype, flags, data):
      ret = []
      for x in self.encodeData(ptype, flags, data):
         # split into host and subdomain
         spos = random.randrange(max([len(x) - 62, 0]), min([63, len(x)]))
         ret.append("x%s.%s" % ('.x'.join([x[:spos], x[spos:]]), random.choice(self.domains)))
      return ret

   def encodeDnsQuery(self, ptype, flags, data):
      ret = []
      for x in self.encodeDns(ptype, flags, data):      
         m = DNS.Lib.Mpacker()
         m.addHeader(1234, 0, DNS.Opcode.QUERY, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0)
         m.addQuestion(x, DNS.Type.TXT, DNS.Class.IN)
         ret.append(m.getbuf())
      return ret

class Decoder:
   def __init__(self, key, domains):
      self.cipher = Crypto.Cipher.AES.new(pad(key, 16))
      self.domains = domains
      self.datastore = {}
      self.seen_lastfragment = 1

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
         ret.append(self.datastore[i][3])
      return zlib.decompress(''.join(ret))
      
   def removeDomain(self, data):
      for x in self.domains:
         if data.endswith(x):
            return data[:data.find(x)]

   def rfc1035ToFqdn(self, data):
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
      ptype = (ord(s[0]) << 8) + ord(s[1])
      flags = (ord(s[2]) << 8) + ord(s[3])
      seq = ord(s[4])
      plen = ord(s[5])
      data = s[6:plen + 6]
      return (ptype, flags, seq, data)

   def decodeData(self, data):
      for p in data:
         ptype, flags, serial, payload = self.decodePacket(p)
         self.datastore[serial] = (ptype, flags, serial, payload)
         if flags & FLAG_LASTFRAGMENT == FLAG_LASTFRAGMENT:
            self.seen_lastfragment = 1
      if self.seen_lastfragment == 1:
         if self.checkDataComplete():
            return ptype, flags, serial, self.packetsToData()
      return None

   def decodeDns(self, data):
      buf = []
      for s in data:
         s = s[1:]
         buf.append(self.removeDomain(s.replace('.x', '')))
      return self.decodeData(buf)


   def decodeDnsQuery(self, data):
      "feed me one packet at time"
      s = data[12:]
      s = self.rfc1035ToFqdn(s)
      return self.decodeDns([s])
   
class BEncoder:
   
   def __init__(self, key):
      self._sequence_number = 0
      self.cipher = Crypto.Cipher.AES.new(pad(key, 16))


   def encodePacket(self, ptype, flags, data):
      s = "%s%s%s%s%s%s%s" % (chr((ptype >> 8) & 0xff),
                              chr(ptype & 0xff),
                              chr((flags >> 8) & 0xff),
                              chr(flags & 0xff),
                              chr(self._sequence_number),
                              chr(len(data)), data)
      self._sequence_number = (self._sequence_number + 1) % 256
      s = padRand(s, 16)
      s = self.cipher.encrypt(s)
      return s

   def encodeData(self, ptype, flags, data):
      self._sequence_number = 0
      cdata = zlib.compress(data)
      ret = []
      for i in range(0, len(cdata), 350):
         if i > len(cdata) - 350:
            # last packet
            ret.append(self.encodePacket(ptype, flags | FLAG_LASTFRAGMENT, cdata[i:i+350]))
         else:
            ret.append(self.encodePacket(ptype, flags, cdata[i:i+350]))
      return ret

   def encodeDnsResponse(self, query, ptype, flags, data):
      ret = []
      for x in self.encodeData(ptype, flags, data):      
         m = DNS.Lib.Mpacker()
         m.addHeader(1234, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0)
         m.addQuestion('\0x3bla\0x0', DNS.Type.TXT, DNS.Class.IN)
         m.addTXT(query, DNS.Class.IN, 3, x)
         ret.append(m.getbuf())
      return ret
   
class BDecoder:
   def __init__(self, key):
      self.cipher = Crypto.Cipher.AES.new(pad(key, 16))
      self.datastore = {}
      self.seen_lastfragment = 1

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
         ret.append(self.datastore[i][3])
      return zlib.decompress(''.join(ret))
      
   
   def decodePacket(self, inbuf):
      s = self.cipher.decrypt(inbuf)
      ptype = (ord(s[0]) << 8) + ord(s[1])
      flags = (ord(s[2]) << 8) + ord(s[3])
      seq = ord(s[4])
      plen = ord(s[5])
      data = s[6:plen + 6]
      return (ptype, flags, seq, data)

   def decodeData(self, data):
      for p in data:
         ptype, flags, serial, payload = self.decodePacket(p)
         self.datastore[serial] = (ptype, flags, serial, payload)
         if flags & FLAG_LASTFRAGMENT == FLAG_LASTFRAGMENT:
            self.seen_lastfragment = 1
      if self.seen_lastfragment == 1:
         if self.checkDataComplete():
            return ptype, flags, serial, self.packetsToData()
      return None

   def decodeDns(self, data):
      return self.decodeData(data)


   def decodeDnsQuery(self, data):
      "feed me one packet at time"
      # parse DNS packet
      m = DNS.Lib.Munpacker(data[0])
      r = DNS.Lib.DnsResult(m, None) 
      for x in  r.answers:
         if x['typename'] == 'TXT':
            return self.decodeDns(x['data'])
   

if __name__ == '__main__':
   t = """Dies ist ein Test Text.

   Und der sollte schön lang sein, damit er kompremiert immernoch
   deutlich länger als 74 Zeichen ist und in mehr als ein Datenpaket
   kompremiert. Ob das jetzt reicht?
   
   """
   
   e = Encoder('key', ['t.23.nu', 't.bewaff.net', 't.c0re.jp', 't.lolitacoders.org'])
   d = Decoder('key', ['t.23.nu', 't.bewaff.net', 't.c0re.jp', 't.lolitacoders.org'])
   #x = e.encodePacket(0,0, "Test")
   #x = e.encodeData(0, 0, t)
   #print d.decodeDns(e.encodeDns(0, 0, t))
   #print d.decodeData(x)
   #print d.decodeDnsQuery('\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\rx8k5Wycuh7X-G xmo9hAtQMyGpvIs6WJy79cO-u_Mx-Wyg\x01t\x04c0re\x02jp\x00\x00\x10\x00\x01')
   e = BEncoder('key')
   d = BDecoder('key')
   x = e.encodePacket(0,0, "Test")
   x = e.encodeDnsResponse('\0x3die\0x8original\0x5query\0x5kommt\0x4hier\x02de\0x0', 0, 0, "Test")
   print d.decodeDnsQuery(x)
