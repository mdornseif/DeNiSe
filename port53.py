import struct, time

# Most of the nice stuff is lifted from scapy

class Field:
    """Basic Field type, super class for all other fields."""
    islist=0
    def __init__(self, name, default, fmt="H"):
        self.name = name
        if fmt[0] in "@=<>!":
            self.fmt = fmt
        else:
            self.fmt = "!"+fmt
        self.default = self.any2i(None,default)
        self.sz = struct.calcsize(self.fmt)
    def h2i(self, pkt, x):
        return x
    def i2h(self, pkt, x):
        return x
    def m2i(self, pkt, x):
        return x
    def i2m(self, pkt, x):
        if x is None:
            x = 0
        return x
    def any2i(self, pkt, x):
        return x
    def i2repr(self, pkt, x):
        if x is None:
            x = 0
        return repr(self.i2h(pkt,x))
    def addfield(self, pkt, s, val):
        return s+struct.pack(self.fmt, self.i2m(pkt,val))
    def getfield(self, pkt, s):
        return  s[self.sz:], self.m2i(pkt, struct.unpack(self.fmt, s[:self.sz])[0])
    def do_copy(self, x):
        if hasattr(x, "copy"):
            return x.copy()
        elif type(x) is list:
            return x[:]
        else:
            return x
    def __eq__(self, other):
        return self.name == other
    def __hash__(self):
        return hash(self.name)
    def __repr__(self):
        return self.name
    def copy(self):
        return copy.deepcopy(self)


class Emph:
    fld = ""
    def __init__(self, fld):
        self.fld = fld
    def __getattr__(self, attr):
        return getattr(self.fld,attr)


class ShortField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "H")


class BitField(Field):
    def __init__(self, name, default, size):
        Field.__init__(self, name, default)
        self.size = size
        
    def addfield(self, pkt, s, val):
        if val is None:
            val = 0
        if type(s) is tuple:
            s,bitsdone,v = s
        else:
            bitsdone = 0
            v = 0
        v <<= self.size
        v |= val & ((1L<<self.size) - 1)
        bitsdone += self.size
        while bitsdone >= 8:
            bitsdone -= 8
            s = s+struct.pack("!B", v >> bitsdone)
            v &= (1L<<bitsdone)-1
        if bitsdone:
            return s,bitsdone,v
        else:
            return s
            
    def getfield(self, pkt, s):
        if type(s) is tuple:
            s,bn = s
        else:
            bn = 0
        # we don't want to process all the string
        nb_bytes = (self.size+bn-1)/8 + 1
        w = s[:nb_bytes]
        # split the substring byte by byte
        bytes = struct.unpack('!%dB' % nb_bytes , w)
        b = 0L
        for c in range(nb_bytes):
            b |= long(bytes[c]) << (nb_bytes-c-1)*8
        # get rid of high order bits
        b &= (1L << (nb_bytes*8-bn)) - 1
        # remove low order bits
        b = b >> (nb_bytes*8 - self.size - bn)
        bn += self.size
        s = s[bn/8:]
        bn = bn%8
        if bn:
            return (s,bn),b
        else:
            return s,b


class EnumField(Field):
    def __init__(self, name, default, enum, fmt = "H"):
        Field.__init__(self, name, default, fmt)
        i2s = self.i2s = {}
        s2i = self.s2i = {}
        if type(enum) is list:
            keys = xrange(len(enum))
        else:
            keys = enum.keys()
        if filter(lambda x: type(x) is str, keys):
            i2s,s2i = s2i,i2s
        for k in keys:
            i2s[k] = enum[k]
            s2i[enum[k]] = k
    def any2i(self, pkt, x):
        if type(x) is str:
            x = self.s2i[x]
        return x
    def i2repr(self, pkt, x):
        return self.i2s.get(x, repr(x))


class BitEnumField(BitField,EnumField):
    def __init__(self, name, default, size, enum):
        EnumField.__init__(self, name, default, enum)
        self.size = size
    def any2i(self, pkt, x):
        return EnumField.any2i(self, pkt, x)
    def i2repr(self, pkt, x):
        return EnumField.i2repr(self, pkt, x)


class ShortEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "H")


class IntField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "I")


class StrField(Field):
    """Generic String field."""
    def __init__(self, name, default, fmt="H", remain=0):
        Field.__init__(self,name,default,fmt)
        self.remain = remain
    def i2m(self, pkt, x):
        if x is None:
            x = ""
        return x
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)
    def getfield(self, pkt, s):
        if self.remain == 0:
            return "",self.m2i(pkt, s)
        else:
            return s[-self.remain:],self.m2i(pkt, s[:-self.remain])


class StrLenField(StrField):
    def __init__(self, name, default, fld):
        StrField.__init__(self, name, default)
        self.fld = fld
    def getfield(self, pkt, s):
        l = getattr(pkt, self.fld)
        # add the shift from the length field
        f = pkt.fields_desc[pkt.fields_desc.index(self.fld)]
        if isinstance(f, FieldLenField):
            l += f.shift
        return s[l:], self.m2i(pkt,s[:l])


class DNSStrField(StrField):
    def i2m(self, pkt, x):
        x = x.split(".")
        x = map(lambda y: chr(len(y))+y, x)
        x = "".join(x)
        if x[-1] != "\x00":
            x += "\x00"
        return x
    def getfield(self, pkt, s):
        n = ""
        while 1:
            l = ord(s[0])
            s = s[1:]
            if not l:
                break
            if l & 0xc0:
                raise Exception("DNS message can't be compressed at this point!")
            else:
                n += s[:l]+"."
                s = s[l:]
        return s, n


class DNSRRCountField(ShortField):
    def __init__(self, name, default, rr):
        ShortField.__init__(self, name, default)
        self.rr = rr
    def i2m(self, pkt, x):
        if x is None:
            x = getattr(pkt,self.rr)
            i = 0
            while isinstance(x, DNSRR) or isinstance(x, DNSQR):
                x = x.payload
                i += 1
            x = i
        return x
    def i2h(self, pkt, x):
        return self.i2m(pkt, x)


class DNSRRField(StrField):
    def __init__(self, name, countfld, passon=1):
        StrField.__init__(self, name, None)
        self.countfld = countfld
        self.passon = passon
    def i2m(self, pkt, x):
        if x is None:
            return ""
        return str(x)
    def decodeRR(self, name, s, p):
        ret = s[p:p+10]
        type,cls,ttl,rdlen = struct.unpack("!HHIH", ret)
        p += 10
        rr = DNSRR("\x00"+ret+s[p:p+rdlen])
        if rr.type in [2, 3, 4, 5]:
            rr.rdata = DNSgetstr(s,p)[0]
        del(rr.rdlen)
        
        p += rdlen
        
        rr.rrname = name
        return rr,p
    def getfield(self, pkt, s):
        if type(s) is tuple :
            s,p = s
        else:
            p = 0
        ret = None
        c = getattr(pkt, self.countfld)
        while c:
            c -= 1
            name,p = DNSgetstr(s,p)
            rr,p = self.decodeRR(name, s, p)
            if ret is None:
                ret = rr
            else:
                ret.add_payload(rr)
        if self.passon:
            return (s,p),ret
        else:
            return s[p:],ret
            

            
class DNSQRField(DNSRRField):
    def decodeRR(self, name, s, p):
        ret = s[p:p+4]
        p += 4
        rr = packets.DNSQR("\x00"+ret)
        rr.qname = name
        return rr,p
        
        


class RDataField(StrLenField):
    def m2i(self, pkt, s):
        if pkt.type == 1:
            s = socket.inet_ntoa(s)
        return s
    def i2m(self, pkt, s):
        if pkt.type == 1:
            if s:
                s = inet_aton(s)
        elif pkt.type in [2,3,4,5]:
            s = "".join(map(lambda x: chr(len(x))+x, s.split(".")))
            if ord(s[-1]):
                s += "\x00"
        return s


class RDLenField(Field):
    def __init__(self, name):
        Field.__init__(self, name, None, "H")
    def i2m(self, pkt, x):
        if x is None:
            rdataf = pkt.fieldtype["rdata"]
            x = len(rdataf.i2m(pkt, pkt.rdata))
        return x
    def i2h(self, pkt, x):
        if x is None:
            rdataf = pkt.fieldtype["rdata"]
            x = len(rdataf.i2m(pkt, pkt.rdata))
        return x


class RandField:
    pass

class Gen(object):
    def __iter__(self):
        return iter([])


class SetGen(Gen):
    def __init__(self, set):
        if type(set) is list:
            self.set = set
        elif isinstance(set, PacketList):
            self.set = list(set)
        else:
            self.set = [set]
    def transf(self, element):
        return element
    def __iter__(self):
        for i in self.set:
            if (type(i) is tuple) and (len(i) == 2):
                if  (i[0] <= i[1]):
                    j=i[0]
                    while j <= i[1]:
                        yield j
                        j += 1
            elif isinstance(i, Gen):
                for j in i:
                    yield j
            else:
                yield i
    def __repr__(self):
        return "<SetGen %s>" % self.set.__repr__()

class Packet(Gen):
    name="abstract packet"
    fields_desc = []
    aliastypes = []
    overload_fields = {}
    underlayer = None
    payload_guess = []
    initialized = 0
    def __init__(self, _pkt="", _internal=0, **fields):
        self.time  = time.time()
        self.aliastypes = [ self.__class__ ] + self.aliastypes
        self.default_fields = {}
        self.overloaded_fields = {}
        self.fields={}
        self.fieldtype={}
        self.__dict__["payload"] = NoPayload()
        for f in self.fields_desc:
            self.default_fields[f] = f.default
            self.fieldtype[f] = f
        self.initialized = 1
        if _pkt:
            self.dissect(_pkt)
            if not _internal:
                self.dissection_done(self)
        for f in fields.keys():
            self.fields[f] = self.fieldtype[f].any2i(self,fields[f])
    def dissection_done(self,pkt):
        self.post_dissection(pkt)
        self.payload.dissection_done(pkt)
    def post_dissection(self, pkt):
        pass
    def add_payload(self, payload):
        if payload is None:
            return
        elif not isinstance(self.payload, NoPayload):
            self.payload.add_payload(payload)
        else:
            if isinstance(payload, Packet):
                self.__dict__["payload"] = payload
                payload.add_underlayer(self)
                for t in self.aliastypes:
                    if payload.overload_fields.has_key(t):
                        self.overloaded_fields = payload.overload_fields[t]
                        break
            elif type(payload) is str:
                self.__dict__["payload"] = Raw(load=payload)
            else:
                raise TypeError("payload must be either 'Packet' or 'str', not [%s]" % repr(payload))
    def remove_payload(self):
        self.payload.remove_underlayer(self)
        self.__dict__["payload"] = NoPayload()
        self.overloaded_fields = {}
    def add_underlayer(self, underlayer):
        self.underlayer = underlayer
    def remove_underlayer(self,other):
        self.underlayer = None
    def copy(self):
        clone = self.__class__()
        clone.fields = self.fields.copy()
        for k in clone.fields:
            clone.fields[k]=self.fieldtype[k].do_copy(clone.fields[k])
        clone.default_fields = self.default_fields.copy()
        clone.overloaded_fields = self.overloaded_fields.copy()
        clone.overload_fields = self.overload_fields.copy()
        clone.underlayer=self.underlayer
        clone.__dict__["payload"] = self.payload.copy()
        clone.payload.add_underlayer(clone)
        return clone
    def __getattr__(self, attr):
        if self.initialized:
            fld = self.fieldtype.get(attr)
            if fld is None:
                i2h = lambda x,y: y
            else:
                i2h = fld.i2h
            for f in ["fields", "overloaded_fields", "default_fields"]:
                fields = self.__dict__[f]
                if fields.has_key(attr):
                    return i2h(self, fields[attr] )
            return getattr(self.payload, attr)
        raise AttributeError(attr)
    def __setattr__(self, attr, val):
        if self.initialized:
            if self.default_fields.has_key(attr):
                fld = self.fieldtype.get(attr)
                if fld is None:
                    any2i = lambda x,y: y
                else:
                    any2i = fld.any2i
                self.fields[attr] = any2i(self, val)
            elif attr == "payload":
                self.remove_payload()
                self.add_payload(val)
            else:
                self.__dict__[attr] = val
        else:
            self.__dict__[attr] = val
    def __delattr__(self, attr):
        if self.initialized:
            if self.fields.has_key(attr):
                del(self.fields[attr])
                return
            elif self.default_fields.has_key(attr):
                return
            elif attr == "payload":
                self.remove_payload()
                return
        if self.__dict__.has_key(attr):
            del(self.__dict__[attr])
        else:
            raise AttributeError(attr)      
    def __repr__(self):
        s = ""
        for f in self.fields_desc:
            if f in self.fields:
                val = f.i2repr(self, self.fields[f])
            elif f in self.overloaded_fields:
                val =  f.i2repr(self, self.overloaded_fields[f])
            else:
                continue
            s += " %s=%s" % (f.name, val)
        return "<%s%s |%s>"% (self.__class__.__name__,
                              s, repr(self.payload))
    def __str__(self):
        return self.__iter__().next().build()
    def __div__(self, other):
        if isinstance(other, Packet):
            cloneA = self.copy()
            cloneB = other.copy()
            cloneA.add_payload(cloneB)
            return cloneA
        elif type(other) is str:
            return self/Raw(load=other)
        else:
            return other.__rdiv__(self)
    def __rdiv__(self, other):
        if type(other) is str:
            return Raw(load=other)/self
        else:
            raise TypeError
    def __len__(self):
        return len(self.__str__())
    def do_build(self):
        p=""
        for f in self.fields_desc:
            p = f.addfield(self, p, self.__getattr__(f))
        pkt = p+self.payload.build(internal=1)
        return pkt
    def post_build(self, pkt):
        return pkt
    def build(self,internal=0):
        p = self.post_build(self.do_build())
        if not internal:
            pkt = self
            while pkt.haslayer(Padding):
                pkt = pkt.getlayer(Padding)
                p += pkt.load
                pkt = pkt.payload
        return p
    def extract_padding(self, s):
        return s,None
    def post_dissect(self, s):
        return s
    def do_dissect(self, s):
        flist = self.fields_desc[:]
        flist.reverse()
        while s and flist:
            f = flist.pop()
            s,fval = f.getfield(self, s)
            self.fields[f] = fval
        s = self.post_dissect(s)     
        payl,pad = self.extract_padding(s)
        self.do_dissect_payload(payl)
        if pad and conf.padding:
            self.add_payload(Padding(pad))
    def do_dissect_payload(self, s):
        if s:
            cls = self.guess_payload_class(s)
            try:
                p = cls(s, _internal=1)
            except:
                if conf.debug_dissector and isinstance(cls,Packet):
                    log_runtime.error("%s dissector failed" % cls.name)
                    raise
                else:
                    if conf.debug_dissector:
                        log_runtime.warning("%s.guess_payload_class() returned [%s]" % (self.__class__.__name__,repr(cls)))
                    p = Raw(s, _internal=1)
            self.add_payload(p)
    def dissect(self, s):
        return self.do_dissect(s)
    def guess_payload_class(self, payload):
        for t in self.aliastypes:
            for fval, cls in t.payload_guess:
                ok = 1
                for k in fval.keys():
                    if fval[k] != getattr(self,k):
                        ok = 0
                        break
                if ok:
                    return cls
        return self.default_payload_class(payload)
    def default_payload_class(self, payload):
        return Raw
    def hide_defaults(self):
        for k in self.fields.keys():
            if self.default_fields.has_key(k):
                if self.default_fields[k] == self.fields[k]:
                    del(self.fields[k])
        self.payload.hide_defaults()
    def __iter__(self):
        def loop(todo, done, self=self):
            if todo:
                eltname = todo.pop()
                elt = self.__getattr__(eltname)
                if not isinstance(elt, Gen):
                    if self.fieldtype[eltname].islist:
                        elt = SetGen([elt])
                    else:
                        elt = SetGen(elt)
                for e in elt:
                    done[eltname]=e
                    for x in loop(todo[:], done):
                        yield x
            else:
                if isinstance(self.payload,NoPayload):
                    payloads = [None]
                else:
                    payloads = self.payload
                for payl in payloads:
                    done2=done.copy()
                    for k in done2:
                        if isinstance(done2[k], RandField):
                            done2[k] = done2[k]*1
                    pkt = self.__class__(**done2)
                    pkt.underlayer = self.underlayer
                    pkt.overload_fields = self.overload_fields.copy()
                    if payl is None:
                        yield pkt
                    else:
                        yield pkt/payl
        return loop(map(lambda x:str(x), self.fields.keys()), {})
    def send(self, s, slp=0):
        for p in self:
            s.send(str(p))
            if slp:
                time.sleep(slp)
    def __gt__(self, other):
        if isinstance(other, Packet):
            return other < self
        elif type(other) is str:
            return 1
        else:
            raise TypeError((self, other))
    def __lt__(self, other):
        if isinstance(other, Packet):
            return self.answers(other)
        elif type(other) is str:
            return 1
        else:
            raise TypeError((self, other))
    def hashret(self):
        return self.payload.hashret()
    def answers(self, other):
        if other.__class__ == self.__class__:
            return self.payload.answers(other.payload)
        return 0
    def haslayer(self, cls):
        if self.__class__ == cls:
            return 1
        return self.payload.haslayer(cls)
    def haslayer_str(self, cls):
        if self.__class__.__name__ == cls:
            return 1
        return self.payload.haslayer_str(cls)
    def getlayer(self, cls):
        if self.__class__ == cls:
            return self
        return self.payload.getlayer(cls)
    def display(self,*args,**kargs):  # Deprecated. Use show()
        self.show(*args,**kargs)
    def show(self, lvl=0):
        print "%s---[ %s%s%s ]---%s" % (conf.color_theme.punct,
                                    conf.color_theme.layer_name,
                                    self.name,
                                    conf.color_theme.punct,
                                    conf.color_theme.normal)
        for f in self.fields_desc:
            if isinstance(f, Emph):
                ncol = conf.color_theme.emph_field_name
                vcol = conf.color_theme.emph_field_value
            else:
                ncol = conf.color_theme.field_name
                vcol = conf.color_theme.field_value
            print "%s%s%-10s%s= %s%s%s" % ("   "*lvl,
                                           ncol,
                                           f.name,
                                           conf.color_theme.punct,
                                           vcol,
                                           f.i2repr(self,self.__getattr__(f)),
                                           conf.color_theme.normal)
        self.payload.display(lvl+1)
    def show2(self):
        self.__class__(str(self)).show()
    def sprintf(self, fmt, relax=1):
        """sprintf(format, [relax=1]) -> str
where format is a string that can include directives. A directive begins and
ends by % and has the following format %[fmt[r],][cls[:nb].]field%.\n
fmt is a classic printf directive, "r" can be appended for raw substitution
(ex: IP.flags=0x18 instead of SA), nb is the number of the layer we want
(ex: for IP/IP packets, IP:2.src is the src of the upper IP layer).
Special case : "%.time%" is the creation time.
Ex : p.sprintf("%.time% %-15s,IP.src% -> %-15s,IP.dst% %IP.chksum% "
               "%03xr,IP.proto% %r,TCP.flags%")\n
Moreover, the format string can include conditionnal statements. A conditionnal
statement looks like : {layer:string} where layer is a layer name, and string
is the string to insert in place of the condition if it is true, i.e. if layer
is present. If layer is preceded by a "!", the result si inverted. Conditions
can be imbricated. A valid statement can be :
  p.sprintf("This is a{TCP: TCP}{UDP: UDP}{ICMP:n ICMP} packet")
  p.sprintf("{IP:%IP.dst% {ICMP:%ICMP.type%}{TCP:%TCP.dport%}}")\n
A side effect is that, to obtain "{" and "}" characters, you must use
"%(" and "%)".
"""
        escape = { "%": "%",
                   "(": "{",
                   ")": "}" }
        # Evaluate conditions 
        while "{" in fmt:
            i = fmt.rindex("{")
            j = fmt[i+1:].index("}")
            cond = fmt[i+1:i+j+1]
            k = cond.find(":")
            if k < 0:
                raise Exception("Bad condition in format string: [%s] (read sprintf doc!)"%cond)
            cond,format = cond[:k],cond[k+1:]
            res = False
            if cond[0] == "!":
                res = True
                cond = cond[1:]
            if self.haslayer_str(cond):
                res = not res
            if not res:
                format = ""
            fmt = fmt[:i]+format+fmt[i+j+2:]
        # Evaluate directives
        s = ""
        while "%" in fmt:
            i = fmt.index("%")
            s += fmt[:i]
            fmt = fmt[i+1:]
            if fmt[0] in escape:
                s += escape[fmt[0]]
                fmt = fmt[1:]
                continue
            try:
                i = fmt.index("%")
                sfclsfld = fmt[:i]
                fclsfld = sfclsfld.split(",")
                if len(fclsfld) == 1:
                    f = "s"
                    clsfld = fclsfld[0]
                elif len(fclsfld) == 2:
                    f,clsfld = fclsfld
                else:
                    raise Exception
                cls,fld = clsfld.split(".")
                num = 1
                if ":" in cls:
                    cls,num = cls.split(":")
                    num = int(num)
                fmt = fmt[i+1:]
            except:
                raise Exception("Bad format string [%%%s%s]" % (fmt[:25], fmt[25:] and "..."))
            else:
                if fld == "time":
                    val = time.strftime("%H:%M:%S.%%06i", time.localtime(self.time)) % int((self.time-int(self.time))*1000000)
                elif cls == self.__class__.__name__ and hasattr(self, fld):
                    if num > 1:
                        val = self.payload.sprintf("%%%s,%s:%s.%s%%" % (f,cls,num-1,fld), relax)
                        f = "s"
                    elif f[-1] == "r":  # Raw field value
                        val = getattr(self,fld)
                        f = f[:-1]
                        if not f:
                            f = "s"
                    else:
                        val = getattr(self,fld)
                        if fld in self.fieldtype:
                            val = self.fieldtype[fld].i2repr(self,val)
                else:
                    val = self.payload.sprintf("%%%s%%" % sfclsfld, relax)
                    f = "s"
                s += ("%"+f) % val
        s += fmt
        return s
    def mysummary(self):
        return ""
    def summary(self, intern=0):
        found,s,needed = self.payload.summary(intern=1)
        if s:
            s = " / "+s
        ret = ""
        if not found or self.__class__ in needed:
            ret = self.mysummary()
            if type(ret) is tuple:
                ret,n = ret
                needed += n
        if ret or needed:
            found = 1
        if not ret:
            ret = self.__class__.__name__
        ret = "%s%s" % (ret,s)
        if intern:
            return found,ret,needed
        else:
            return ret
    def lastlayer(self,layer=None):
        return self.payload.lastlayer(self)
    def decode_payload_as(self,cls):
        s = str(self.payload)
        self.payload = cls(s)
    def libnet(self):
        print "libnet_build_%s(" % self.__class__.name.lower()
        det = self.__class__(str(self))
        for f in self.fields_desc:
            val = getattr(det, f.name)
            if val is None:
                val = 0
            elif type(val) is int:
                val = str(val)
            else:
                val = '"%s"' % str(val)
            print "\t%s, \t\t/* %s */" % (val,f.name)
        print ");"



class Raw(Packet):
    name = "Raw"
    fields_desc = [ StrField("load", "") ]
    def answers(self, other):
        return 1

class Padding(Raw):
    name = "Padding"
    def build(self, internal=0):
        if internal:
            return ""
        else:
            return Raw.build(self)
            

class NoPayload(Packet,object):
    def __new__(cls, *args, **kargs):
        singl = cls.__dict__.get("__singl__")
        if singl is None:
            cls.__singl__ = singl = object.__new__(cls)
            Packet.__init__(singl, *args, **kargs)
        return singl
    def __init__(self, *args, **kargs):
        pass
    def dissection_done(self,pkt):
        return
    def add_payload(self, payload):
        raise Exception("Can't add payload to NoPayload instance")
    def remove_payload(self):
        pass
    def add_underlayer(self,underlayer):
        pass
    def remove_underlayer(self,other):
        pass
    def copy(self):
        return self
    def __repr__(self):
        return ""
    def __str__(self):
        return ""
    def build(self, internal=0):
        return ""
    def __getattr__(self, attr):
        if attr in self.__dict__:
            return self.__dict__[attr]
        elif attr in self.__class__.__dict__:
            return self.__class__.__dict__[attr]
        else:
            raise AttributeError, attr
    def hide_defaults(self):
        pass
    def __iter__(self):
        return iter([])
    def hashret(self):
        return ""
    def answers(self, other):
        return isinstance(other, NoPayload) or isinstance(other, Padding)
    def haslayer(self, cls):
        return 0
    def haslayer_str(self, cls):
        return 0
    def getlayer(self, cls):
        return None
    def show(self, lvl=0):
        pass
    def sprintf(self, fmt, relax):
        if relax:
            return "??"
        else:
            raise Exception("Format not found [%s]"%fmt)
    def summary(self, intern=0):
        return 0,"",[]
    def lastlayer(self,layer):
        return layer


class PacketList:
    res = []
    def __init__(self, res, name="PacketList", stats=None):
        if stats is None:
            stats = [ TCP,UDP,ICMP ]
        self.stats = stats
        self.res = res
        self.listname = name
    def _elt2pkt(self, elt):
        return elt
    def _elt2sum(self, elt):
        return elt.summary()
    def _elt2show(self, elt):
        return self._elt2sum(elt)
    def __repr__(self):
#        stats=dict.fromkeys(self.stats,0) ## needs python >= 2.3  :(
        stats = dict(map(lambda x: (x,0), self.stats))
        other = 0
        for r in self.res:
            f = 0
            for p in stats:
                if self._elt2pkt(r).haslayer(p):
                    stats[p] += 1
                    f = 1
                    break
            if not f:
                other += 1
        s = ""
        for p in stats:
            s += " %s:i" % (p.name,
                                     stats[p])
        s += " Other:%i" % (other)
        return "<%s:%s>" % (self.listname,
                            s)
    def __getattr__(self, attr):
        return getattr(self.res, attr)
    def __getslice__(self, *args, **kargs):
        return self.__class__(self.res.__getslice__(*args, **kargs),
                              name="mod %s"%self.listname)
    def __add__(self, other):
        return self.__class__(self.res+other.res,
                              name="%s+%s"%(self.listname,other.listname))
    def summary(self, prn=None, filter=None):
        for r in self.res:
            if filter is not None:
                if not filter(r):
                    continue
            if prn is None:
                print self._elt2sum(r)
            else:
                print prn(r)
    def nsummary(self,prn=None, filter=None):
        for i in range(len(self.res)):
            if filter is not None:
                if not filter(self.res[i]):
                    continue
            if prn is None:
                print "%04i %s" % (i,self._elt2sum(self.res[i]))
            else:
                print "%04i %s" % (i,prn(self.res[i]))
    def display(self): # Deprecated. Use show()
        self.show()
    def show(self):
        for i in range(len(self.res)):
            print "%04i %s" % (i,self._elt2show(self.res[i]))
    def filter(self, func):
        return self.__class__(filter(func,self.res),
                              name="filtered %s"%self.listname)
    def make_table(self, *args, **kargs):
        return make_table(self.res, *args, **kargs)
    def make_lined_table(self, *args, **kargs):
        return make_lined_table(self.res, *args, **kargs)
    def make_tex_table(self, *args, **kargs):
        return make_tex_table(self.res, *args, **kargs)
    def plot(self, f, **kargs):
        g=Gnuplot.Gnuplot()
        g.plot(Gnuplot.Data(map(f,self.res), **kargs))
        return g
    def hexdump(self):
        for p in self:
            hexdump(self._elt2pkt(p))
    def hexraw(self):
        for i in range(len(self.res)):
            p = self._elt2pkt(self.res[i])
            print "%04i %s %s" % (i,p.sprintf("%.time%"),self._elt2sum(self.res[i]))
            if p.haslayer(Raw):
                hexdump(p.getlayer(Raw).load)
    def padding(self, filter=None):
        for i in range(len(self.res)):
            p = self._elt2pkt(self.res[i])
            if p.haslayer(Padding):
                if not filter or filter(p):
                    print "%04i %s %s" % (i,p.sprintf("%.time%"),self._elt2sum(self.res[i]))
                    hexdump(p.getlayer(Padding).load)
    def nzpadding(self, filter=None):
        for i in range(len(self.res)):
            p = self._elt2pkt(self.res[i])
            if p.haslayer(Padding):
                pad = p.getlayer(Padding).load
                if pad == "\x00"*len(pad):
                    continue
                if not filter or filter(p):
                    print "%04i %s %s" % (i,p.sprintf("%.time%"),self._elt2sum(self.res[i]))
                    hexdump(p.getlayer(Padding).load)
    def conversations(self, getsrc=None, getdst=None,**kargs):
        if getsrc is None:
            getsrc = lambda x:x.getlayer(IP).src
        if getdst is None:
            getdst = lambda x:x.getlayer(IP).dst
        conv = {}
        for p in self.res:
            p = self._elt2pkt(p)
            try:
                c = (getsrc(p),getdst(p))
            except:
                #XXX warning()
                continue
            conv[c] = conv.get(c,0)+1
        gr = 'digraph "conv" {\n'
        for s,d in conv:
            gr += '\t "%s" -> "%s"\n' % (s,d)
        gr += "}\n"
        do_graph(gr, **kargs)
    def timeskew_graph(self, ip, **kargs):
        b = filter(lambda x:x.haslayer(IP) and x.getlayer(IP).src == ip and x.haslayer(TCP), self.res)
        c = []
        for p in b:
            opts = p.getlayer(TCP).options
            for o in opts:
                if o[0] == "Timestamp":
                    c.append((p.time,o[1][0]))
        d = map(lambda (x,y): (x%2000,((x-c[0][0])-((y-c[0][1])/1000.0))),c)
        g = Gnuplot.Gnuplot()
        g.plot(Gnuplot.Data(d,**kargs))
        return g

class DNS(Packet):
    name = "DNS"
    fields_desc = [ ShortField("id",0),
                    BitField("qr",0, 1),
                    BitEnumField("opcode", 0, 4, {0:"QUERY",1:"IQUERY",2:"STATUS"}),
                    BitField("aa", 0, 1),
                    BitField("tc", 0, 1),
                    BitField("rd", 0, 1),
                    BitField("ra", 0 ,1),
                    BitField("z", 0, 3),
                    BitEnumField("rcode", 0, 4, {0:"ok", 1:"format-error", 2:"server-failure", 3:"name-error", 4:"not-implemented", 5:"refused"}),
                    DNSRRCountField("qdcount", None, "qd"),
                    DNSRRCountField("ancount", None, "an"),
                    DNSRRCountField("nscount", None, "ns"),
                    DNSRRCountField("arcount", None, "ar"),
                    DNSQRField("qd", "qdcount"),
                    DNSRRField("an", "ancount"),
                    DNSRRField("ns", "nscount"),
                    DNSRRField("ar", "arcount",0) ]
    def mysummary(self):
        type = ["Qry","Ans"][self.qr]
        name = ""
        if self.qr:
            type = "Ans"
            if self.ancount > 0:
                name = ' "%s"' % self.an.rdata
        else:
            type = "Qry"
            if self.qdcount > 0:
                name = ' "%s"' % self.qd.qname
        return 'DNS %s%s ' % (type, name)

dnstypes = { 0:"ANY", 255:"ALL",
             1:"A", 2:"NS", 3:"MD", 4:"MD", 5:"CNAME", 6:"SOA", 7: "MB", 8:"MG",
             9:"MR",10:"NULL",11:"WKS",12:"PTR",13:"HINFO",14:"MINFO",15:"MX",16:"TXT",
             17:"RP",18:"AFSDB",28:"AAAA", 33:"SRV",38:"A6",39:"DNAME"}


dnsqtypes = {251:"IXFR",252:"AXFR",253:"MAILB",254:"MAILA",255:"ALL"}
dnsqtypes.update(dnstypes)
dnsclasses =  {1: 'IN',  2: 'CS',  3: 'CH',  4: 'HS',  255: 'ANY'}


class DNSQR(Packet):
    name = "DNS Question Record"
    fields_desc = [ DNSStrField("qname",""),
                    ShortEnumField("qtype", 1, dnsqtypes),
                    ShortEnumField("qclass", 1, dnsclasses) ]
                    
                    

class DNSRR(Packet):
    name = "DNS Resource Record"
    fields_desc = [ DNSStrField("rrname",""),
                    ShortEnumField("type", 1, dnstypes),
                    ShortEnumField("rclass", 1, dnsclasses),
                    IntField("ttl", 0),
                    RDLenField("rdlen"),
                    RDataField("rdata", "", "rdlen") ]
