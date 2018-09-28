import sha
import struct
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util import randpool
from binascii import hexlify

RandomPool = randpool.RandomPool()


class HIPCookie:
    def __init__(self, **kwargs):
        self.hits = ''
        self.__dict__.update(kwargs)

    def cookieOp(self, i, j, k):
        # takes i, j as byte strings k as number
        # returns lowest order k bits of i^j as 8 byte string
        m = (2 << (k - 1)) - 1
        r = bytes_to_long(sha.new(''.join([i, self.hits, j])).digest()) & m
        return long_to_bytes(r, 8)

    def puzzle(self, challenge):
        (self.I, self.K, c) = struct.unpack('!8s8s8s', challenge)
        i = self.I
        self.K = bytes_to_long(self.K)
        m = (1 << (self.K)) - 1
        target = bytes_to_long(c) & m
        # local symbol lookup is MUCH faster
        rb = RandomPool.get_bytes
        j = rb(8)
        while (bytes_to_long(
                sha.new(''.join([i, self.hits, j])).digest()) & m) != target:
            j = rb(8)
        return ''.join([self.I, j, c])

    def puzzle2(self, I, K, c):
        self.I, self.K = I, K
        i = self.I
        m = (1 << self.K) - 1
        target = bytes_to_long(c) & m
        # local symbol lookup is MUCH faster
        rb = RandomPool.get_bytes
        b2l = bytes_to_long
        sh = sha.new
        h = self.hits
        j = rb(8)
        while (b2l(sh(''.join([i, h, j])).digest()) & m) != target:
            j = rb(8)
        self.J = j
        self.cookie = c
        print("Cookie Puzzle:", hexlify(sh(''.join([i, h, j])).digest()), hex(
            (b2l(sh(''.join([i, h, j])).digest()) & m)), hexlify(i + j))
        return ''.join([self.I, j, c])

    def new(self):
        if self.K > 27:
            raise ValueError
        self.I = RandomPool.get_bytes(8)
        self.J = RandomPool.get_bytes(8)
        self.cookie = self.cookieOp(self.I, self.J, self.K)
        return self.cookie

    def check(self, response):
        (I, r, ook) = struct.unpack('!8s8s8s', response)
        return self.cookieOp(self.I, r, self.K) == self.cookie

    # K<64 anyway.
    def pack(self):
        return ''.join([self.I,
                        '\x00\x00\x00\x00\x00\x00\x00',
                        chr(self.K),
                        self.cookie])
