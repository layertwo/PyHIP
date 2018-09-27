import types
import socket
import struct
import IPy
from Crypto.Util.number import bytes_to_long, long_to_bytes

class Memoize:
    """Memoize(fn) - an instance which acts like fn but memoizes its arguments
       Will only work on functions with non-mutable arguments
    """
    def __init__(self, fn):
        self.fn = fn
        self.memo = {}
    def __call__(self, *args):
        if not self.memo.has_key(args):
            self.memo[args] = self.fn(*args)
        return self.memo[args]

IPheader      = '!BBHHHBBH4s4s'
IPheader_len  = struct.calcsize(IPheader)

#(iph, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

## from rfc 2460
##3.  IPv6 Header Format

##   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##   |Version| Traffic Class |           Flow Label                  |
##   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##   |         Payload Length        |  Next Header  |   Hop Limit   |
##   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##   |                                                               |
##   +                                                               +
##   |                                                               |
##   +                         Source Address                        +
##   |                                                               |
##   +                                                               +
##   |                                                               |
##   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##   |                                                               |
##   +                                                               +
##   |                                                               |
##   +                      Destination Address                      +
##   |                                                               |
##   +                                                               +
##   |                                                               |
##   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

##   Version              4-bit Internet Protocol version number = 6.

##   Traffic Class        8-bit traffic class field.  See section 7.

##   Flow Label           20-bit flow label.  See section 6.

##   Payload Length       16-bit unsigned integer.  Length of the IPv6
##                        payload, i.e., the rest of the packet following
##                        this IPv6 header, in octets.  (Note that any

##                        extension headers [section 4] present are
##                        considered part of the payload, i.e., included
##                        in the length count.)

##   Next Header          8-bit selector.  Identifies the type of header
##                        immediately following the IPv6 header.  Uses the
##                        same values as the IPv4 Protocol field [RFC-1700
##                        et seq.].

##   Hop Limit            8-bit unsigned integer.  Decremented by 1 by
##                        each node that forwards the packet. The packet
##                        is discarded if Hop Limit is decremented to
##                        zero.

##   Source Address       128-bit address of the originator of the packet.
##                        See [ADDRARCH].

##   Destination Address  128-bit address of the intended recipient of the
##                        packet (possibly not the ultimate recipient, if
##                        a Routing header is present).  See [ADDRARCH]
##                        and section 4.4.


# (VersClsFlow, length, NH, ttl, saddr, daddr)
IP6Header = '!LHBB16s16s'
IP6Header_len  = struct.calcsize(IP6Header)

##def IPv6_ntoa(addr):
##    x=[]
##    for i in range(0, len(addr), 2):
##        x.append(addr[i:i+2])
##    return ':'.join(map(hexlify,x))

bytes_to_long = Memoize(bytes_to_long)
long_to_bytes = Memoize(long_to_bytes)

def IPv6_ntoa(addr):
    return str(IPy.IP(bytes_to_long(addr)))

def IPv6_aton(addr):
    i = IPy.IP(addr)
    n = 4 + (i.version()==6)*12
    return long_to_bytes(i.int(),n)

class IP:
    def __init__(self,
                 it):
        if type(it) == type(self):
            it = it.Number
        if type(it) == types.TupleType:
            it = it[0]
        try:
            self.IP = IPy.IP(it)
        except ValueError:
            self.IP = IPy.IP(bytes_to_long(it))
        self.String = str(self.IP)
        self.Number = self.IP.int()
        self.Netstring = IPv6_aton(self.Number)
        self.MaybeIPv4inv6 = ''.join(['\x00']*(16-len(self.Netstring))
                                     + [self.Netstring])
        self.Addrinfo = socket.getaddrinfo(self.String, None)[0][-1:][0]
        self.Version = self.IP.version()
        self.Reserved = 0L

        #__init__ = Memoize(__init__)

    def __cmp__(self, other):
        try:
            return self.IP.__cmp__(other.IP)
        except AttributeError:
            return cmp(self, IP(other))

    def __hash__(self):
        return hash(self.Netstring)

    def allDict(self, thing=None):
        if thing is None:
            thing = self
        return {self.String: thing,
                self.Number: thing,
                self.Netstring: thing,
                self.Addrinfo: thing,
                self: thing}
