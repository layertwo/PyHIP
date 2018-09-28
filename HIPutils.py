

from pprint import pprint
import struct
import operator
from binascii import hexlify
import types
import sha
import queue
from Crypto.Util import randpool
from Crypto.Util.number import bytes_to_long, long_to_bytes
import IPAddress

RandomPool = randpool.RandomPool()


class Memoize:
    """Memoize(fn) - an instance which acts like fn but memoizes its arguments
       Will only work on functions with non-mutable arguments
    """

    def __init__(self, fn):
        self.fn = fn
        self.memo = {}

    def __call__(self, *args):
        if args not in self.memo:
            self.memo[args] = self.fn(*args)
        return self.memo[args]

# try:
##    from psyco.classes import *
##    import psyco
# psyco.bind(randpool.RandomPool)
# except ImportError:
# pass


# try:
#    from PyrexUtils import *
# except ImportError:
from Utils import *

# IANA defines this as 'any private encryption protocol'
# which I thought was appropriate for now.
HIP_PROTO_NO = 99  # FIXME
ESP_PROTO_NO = 50
NO_PROTO = 59

HIPC_PIGGY = 0x4000
HIPC_CERT = 0x2000
HIPC_ANON = 0x0001
HIPC_ESP64 = 0x0002

HIP_I1 = 1
HIP_R1 = 2
HIP_I2 = 3
HIP_R2 = 4
HIP_NES = 5
HIP_REA = 6
HIP_BOS = 7
HIP_PAYLOAD = 64

HIP_Packets = {1: 'I1',
               2: 'R1',
               3: 'I2',
               4: 'R2',
               5: 'NES',
               6: 'REA',
               7: 'BOS',
               64: 'PAYLOAD'}


enc = 1
dec = 0


# DHGroups = {5: {'Prime': long_to_bytes(241031242692103258855207602219756607485695054850245994265416941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919),
# 'Generator': long_to_bytes(2)
# }
# }
DHGroups = {3: {'Prime': long_to_bytes(0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF),
                'Generator': long_to_bytes(2)
                }
            }


class IPhandler:
    'Class to derive things that need fragment disassembly from'
    _array_initialiser = '\x00' * 65536

    def ipinput(self, pkt, addr=None):
        # print 'ipinput:', repr(addr)
        # read the header
        # assumption: all IPv4 packets arrive here *with* headers
        if ((ord(pkt[0]) & 0xf0) == 0x40):
            (iph, tos, tot_len, id, frag, ttl, protocol, check, saddr, daddr
             ) = struct.unpack(IPheader, pkt[:IPheader_len])
            # print 'IPv4 packet (with header)'
            payload = pkt[((iph & 0xf) << 2):]
            # IPv4 fragment reassembly
            if frag & 0xbfff:
                frid = (saddr, daddr, protocol, id)
                froff = (frag & 0x1fff) << 3
                frlen = tot_len - ((iph & 0xf) << 2)
                frlast = froff + frlen - 1
                holes, frags, lens = self.holes, self.frags, self.lens
                # print 'fragment', '%x %x' % (froff, frlen), frid, froff,
                # frlast
                if frid not in frags:
                    holes[frid] = [(0, 65536)]
                    frags[frid] = array('b', self._array_initialiser)
                    lens[frid] = frlast
                for (first, last) in holes[frid][:]:
                    if froff > last:
                        continue
                    if frlast < first:
                        continue
                    holes[frid].remove((first, last))
                    if froff > first:
                        holes[frid].append((first, froff - 1))
                    if (frlast < last) and frag & 0x2000:
                        holes[frid].append((frlast + 1, last))
                frags[frid][froff:frlast + 1] = array('b', payload)
                if frlast > lens[frid]:
                    lens[frid] = frlast
                if not holes[frid]:
                    payload = ''.join(frags[frid][:lens[frid] + 1].tostring())
                    del frags[frid]
                    del holes[frid]
                    del lens[frid]
                else:
                    return (None, None, None, None)
            else:
                # at this point, we have a complete packet
                return (saddr, daddr, protocol, payload)
        # elif iph & 0xf0 == 0x60:
        elif addr and len(addr) == 4:
            # print 'IPv6 packet (no header)'
            payload = pkt
            # these don't matter, because we know which socket got it
            protocol = 0  # 'cause we don't know
            daddr = ''  # 'cause we don't know
            saddr = addr[0]
            # print hexlify(pkt)
        elif ((ord(pkt[0]) & 0xf0) == 0x60):
            # print 'IPv6 packet (with header)'
            (VersClsFlow,  # usually 0x60000000
             length,
             protocol,
             ttl,
             saddr,
             daddr) = struct.unpack(IPAddress.IP6Header,
                                    pkt[:IPAddress.IP6Header_len])
            # now what?  Should we parse it?
            payload = pkt[IPAddress.IP6Header_len:]
        else:
            # not something we know what to do with
            print("Wierd packet")
            # print hexlify(pkt)
            return (None, None, None, None)
        # at this point, we have a complete packet
        return (saddr, daddr, protocol, payload)


class Transform(object):
    def get_algorithm(self):
        return self.__algorithm

    def set_algorithm(self, string):
        self.__algorithm = string

    def del_algorithm(self):
        del self.__algorithm
    algorithm = property(get_algorithm,
                         set_algorithm,
                         del_algorithm,
                         'ESP algorithm')

    def get_keylength(self):
        try:
            return self.__keylength
        except AttributeError:
            self.__keylength = max(self.__class__.__KeyLens[self.__algorithm])
            return self.__keylength

    def __init__(self, object=None):
        self.__algorithm = None
        if object:
            # collect all the attributes
            self.__dict__.update(object.__dict__)


class HIPError(Exception):
    def __init__(self, value=None):
        self.value = value

    def __str__(self):
        return repr(self.value)


class HIPUnpackError(HIPError):
    pass


class HIPNewConnection(HIPError):
    pass

# class HIPNoPacket(HIPError):
#    pass


HIPNoPacket = queue.Empty


# just placeholders to carry attributes.
class Header:
    pass


class Body:
    pass


def curryl(*args, **create_time_kwds):
    func = args[0]
    create_time_args = args[1:]

    def curried_function(*call_time_args, **call_time_kwds):
        args = create_time_args + call_time_args
        kwds = create_time_kwds.copy()
        kwds.update(call_time_kwds)
        return func(*args, **kwds)
    return curried_function


def curryr(*args, **create_time_kwds):
    func = args[0]
    create_time_args = args[1:]

    def curried_function(*call_time_args, **call_time_kwds):
        args = call_time_args + create_time_args
        kwds = create_time_kwds.copy()
        kwds.update(call_time_kwds)
        return func(*args, **kwds)
    return curried_function


class Junkme:
    pass


def BN2nbo(n):
    if n[4] == '\x00':
        return n[5:]
    else:
        return n[4:]


def nbo2BN(n):
    return ''.join([struct.pack('!Lx', len(n) + 1), n])


def packTLVPad(length):
    if length < 4:
        return '\xff' * length
    else:
        return struct.pack('!BBH', 254, 0, length - 4) + '\x00' * (length - 4)


def packTLVC(Code, Value):
    try:
        length = len(Value)
        V = Value
    except TypeError:
        V = struct.pack('!H', Value)
        length = 2
    if length <= 2:
        return struct.pack('!H2s', Code + 0x8000, V)
    else:
        return struct.pack('!HH', Code, length) + V


def unpackTLVC(payload):
    # wierd single element tuple constructor follows...
    (code,) = struct.unpack('!H', payload[:2])
    if code > 0x8000:
        return (code - 0x8000, payload[2:4], payload[4:])
    else:
        (code, length) = struct.unpack('!HH', payload[:4])
        return (code, payload[4:4 + length], payload[4 + length:])


def hexorrep(x):
    if isinstance(x, bytes):
        return '%s (%d)' % (hexlify(x), len(x))
    elif isinstance(x, list):
        return repr(x)
    else:
        return str(x)


def keymatgen(dhkey, hitlist):
    def keymatgen1(dhkey, hitlist):
        # print 'Keymat:', hexlify(dhkey)
        # yield dhkey
        hitlist.sort()
        i = 1
        new = sha.new(''.join([dhkey]
                              + hitlist
                              + [chr(i)])).digest()
        print('Keymat:', hexlify(new))
        yield new
        while True:
            i += 1
            new = sha.new(''.join([dhkey,
                                   new,
                                   chr(i)])).digest()
            print('Keymat:', hexlify(new))
            yield new
    g = keymatgen1(dhkey, hitlist)
    while True:
        for i in next(g):
            yield i


# Priority dictionary using binary heaps
# David Eppstein, UC Irvine, 8 Mar 2002

#from __future__ import generators

class priorityDictionary(dict):
    def __init__(self):
        '''Initialize priorityDictionary by creating binary heap
of pairs (value,key).  Note that changing or removing a dict entry will
not remove the old pair from the heap until it is found by smallest() or
until the heap is rebuilt.'''
        self.__heap = []
        dict.__init__(self)

    def smallest(self):
        '''Find smallest item after removing deleted items from heap.'''
        if len(self) == 0:
            raise IndexError("smallest of empty priorityDictionary")
        heap = self.__heap
        while heap[0][1] not in self or self[heap[0][1]] != heap[0][0]:
            lastItem = heap.pop()
            insertionPoint = 0
            while True:
                smallChild = 2 * insertionPoint + 1
                if smallChild + 1 < len(heap) and \
                        heap[smallChild] > heap[smallChild + 1]:
                    smallChild += 1
                if smallChild >= len(heap) or lastItem <= heap[smallChild]:
                    heap[insertionPoint] = lastItem
                    break
                heap[insertionPoint] = heap[smallChild]
                insertionPoint = smallChild
        return heap[0][1]

    def __iter__(self):
        '''Create destructive sorted iterator of priorityDictionary.'''
        def iterfn():
            while len(self) > 0:
                x = self.smallest()
                yield x
                del self[x]
        return iterfn()

    def __setitem__(self, key, val):
        '''Change value stored in dictionary and add corresponding
pair to heap.  Rebuilds the heap if the number of deleted items grows
too large, to avoid memory leakage.'''
        dict.__setitem__(self, key, val)
        heap = self.__heap
        if len(heap) > 2 * len(self):
            self.__heap = [(v, k) for k, v in self.items()]
            self.__heap.sort()  # builtin sort likely faster than O(n) heapify
        else:
            newPair = (val, key)
            insertionPoint = len(heap)
            heap.append(None)
            while insertionPoint > 0 and \
                    newPair < heap[(insertionPoint - 1) // 2]:
                heap[insertionPoint] = heap[(insertionPoint - 1) // 2]
                insertionPoint = (insertionPoint - 1) // 2
            heap[insertionPoint] = newPair

    def setdefault(self, key, val):
        '''Reimplement setdefault to call our customized __setitem__.'''
        if key not in self:
            self[key] = val
        return self[key]

    def update(self, other):
        for key in list(other.keys()):
            self[key] = other[key]


try:
    list(map(psyco.bind, [fixULPChecksum,
                          IPAddress.IPv6_ntoa,
                          keymatgen,
                          unpackLV,
                          packLV,
                          unpackTLVC,
                          packTLVC,
                          struct,
                          IP]))
except NameError:
    pass
