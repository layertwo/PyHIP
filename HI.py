from Crypto.PublicKey import DSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
import struct
import hashlib
import binascii
import pickle
import HIPutils
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_private_key
import asn1

class error:
    pass


zeroHIT = binascii.unhexlify('00000000000000000000000000000000')


class HI:
    HITable = {}
    Algorithm = 1  # DSA

    def callback(self, *args):
        pass

    def __init__(self, file=None, Rec=None, List=None, Size=2048):
        self.backend = default_backend()
        self.hit = None
        self.hit127 = None
        self.x = None
        self.y = None
        self.p = None
        self.g = None
        self.q = None

        if file:
            self.dsa = load_der_private_key(data=file, password=None, backend=self.backend)
        elif Rec:
            self.unpack(Rec)
        elif List:
            self.dsa = DSA.construct(List)
        else:
            self.dsa = dsa.generate_private_key(key_size=Size, backend=self.backend)
            self.priv_numbers = self.dsa.private_numbers()
            self.param_numbers = self.priv_numbers.public_numbers.parameter_numbers
            self.x = self.priv_numbers.x
            self.y = self.priv_numbers.public_numbers.y
            self.p = self.param_numbers.p
            self.g = self.param_numbers.g
            self.q = self.param_numbers.q


    @property
    def genKey(self):
        pass

    @property
    def packDSA(self):
        # RFC2536: t=len(p)/64-1
        # RFC2536: q p g y
        q = long_to_bytes(self.q)
        p = long_to_bytes(self.p)
        g = long_to_bytes(self.g)
        y = long_to_bytes(self.y)
        l = len(p)
        t = bytes(int((l - 64) / 8))
        pad = b'\x00' * (l)
        return b''.join([t, q[:l], pad[:-len(p)], p[:l], pad[:-len(g)], g[:l], pad[:-len(y)], y[:l]])

    @property
    def pack(self):
        # RFC2535: 0x0200 flags,
        #          0xff protocol (or IANA HIP value)
        #          0x03 algorithm DSA (mandatory)
        return b''.join([b'\x02\x00\xff\x03', self.packDSA])

    def unpackDSA(self, string):
        t = (ord(string[0]) * 8 + 64)
        if (len(string) != (1 + 20 + (3 * t))):
            raise ValueError('HI: got RR length %d expecting %d' %
                             (len(string), (1 + 20 + (3 * t))))
        (t, q, p, g, y) = struct.unpack('!B20s%ds%ds%ds' % (t, t, t), string)
        self.dsa = DSA.construct([bytes_to_long(y),
                                  bytes_to_long(g),
                                  bytes_to_long(p),
                                  bytes_to_long(q)])

    def unpack(self, RR):
        self.unpackDSA(RR[4:])

    def signRDATA(self, string):
        l = len(long_to_bytes(self.dsa.p))
        t = (l - 64) / 8
        sha_hash = hashlib.sha1(string.encode('utf-8'))
        r, s = self.dsa.sign(bytes_to_long(sha_hash.digest()),
                             HIPutils.RandomPool.get_bytes(
            len(long_to_bytes(self.dsa.q)) - 1))
        return ''.join([chr(t), long_to_bytes(r), long_to_bytes(s)])

    def verifyRDATA(self, string, sig):
        sha_hash = hashlib.sha1(str(string).encode('utf-8'))
        return self.dsa.verify(bytes_to_long(sha_hash.digest()),
                               (bytes_to_long(sig[1:21]),
                                bytes_to_long(sig[21:])))

    def signASN1(self, string):
        sha_hash = hashlib.sha1(str(string).encode('utf-8'))
        #t = chr((len(long_to_bytes(self.dsa.p)) / 64) - 1)
        r, s = self.dsa.sign(bytes_to_long(sha_hash.digest()),
                             HIPutils.RandomPool.get_bytes(
            len(long_to_bytes(self.dsa.q)) - 1))
        sigInfo = ''.join([asn1.INTEGER().encode(r),
                           asn1.INTEGER().encode(s)])
        return asn1.SEQUENCE(sigInfo).encode()


    def verifyASN1(self, string, sig):
        seq, rest = asn1.decode(sig)
        if rest:
            raise ValueError('HI: unpack failed')
        r, rest = asn1.decode(seq.value)
        s, rest = asn1.decode(rest)
        sha_hash = hashlib.sha1(str(string).encode('utf-8'))
        return self.dsa.verify(bytes_to_long(sha_hash.digest()),
                               (r.value, s.value))

    sign = signRDATA
    verify = verifyRDATA

    @property
    def __rawhash__(self):
        return hashlib.sha1(self.pack).digest()[-16:]

    def HIT(self, template, mask):
        if self.hit is None:
            self.hit = struct.pack(*['16B'] + list(map(lambda h, t, m: t | (h & m),
                                                       struct.unpack('16B', self.__rawhash__),
                                                       struct.unpack('16B', template),
                                                       struct.unpack('16B', mask))))
        return self.hit

    @property
    def HIT127(self):
        if self.hit127 is None:
            self.hit127 = self.HIT(binascii.unhexlify('40000000000000000000000000000000'),
                                   binascii.unhexlify('7fffffffffffffffffffffffffffffff'))
        return self.hit127

    @property
    def HITRR(self):
        return self.HIT127

    def HIT64(self, HAA):
        # HIT64 with arbitrary HAA
        return self.HIT(HAA,
                        binascii.unhexlify('0000000000000000ffffffffffffffff'))

    def HIT3041(self, prefix):
        # RFC3041 prefix
        return self.HIT(prefix,
                        binascii.unhexlify('0000000000000000fdffffffffffffff'))

    # def HITv6link(self):
    #    return self.HIT(binascii.unhexlify('fe800000000000000000000000000000'),
    #                    binascii.unhexlify('004fffffffffffffffffffffffffffff'))

    HITv6link = HIT127


if __name__ == "__main__":
    def main():
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument('-w', '--write', help='write HI to file')
        parser.add_argument('-r', '--read', help='read HI from file')
        parser.add_argument('-hk', '--hostkey', help='read HI val')

        args = parser.parse_args()

        if args.write:
            filename = args.write
            print('Writing new HI to:', filename)
            hi = HI()
            pickle.dump([hi.y,
                         hi.g,
                         hi.p,
                         hi.q,
                         hi.x], open(filename, 'wb'))
            print('HIT is {}'.format(binascii.hexlify(hi.HIT127)))
            print('RR is {}'.format(binascii.hexlify(hi.pack)))
            print('y = {}, len = {}'.format(hex(hi.y), len(long_to_bytes(hi.y))))
            print('p = {}, len = {}'.format(hex(hi.p), len(long_to_bytes(hi.p))))
            print('g = {}, len = {}'.format(hex(hi.g), len(long_to_bytes(hi.g))))
            print('q = {}, len = {}'.format(hex(hi.q), len(long_to_bytes(hi.q))))

        if args.read:
            print('Reading HI from', args.read)
            rec = open(args.read, 'rb').read()
            hi = HI(file=rec)
            print('HIT is', binascii.hexlify(hi.HIT127))
            print('RR is', binascii.hexlify(hi.pack))
            print('y = {}'.format(hi.y))
            print('p = {}'.format(hi.p))
            print('g = {}'.format(hi.g))
            print('q = {}'.format(hi.q))

        if args.hostkey:
            print('Reading HI from', args.hostkey)
            hi = HI(args.hostkey)
            print('HIT is {}'.format(binascii.hexlify(hi.HIT127)))
            print('RR is {}'.format(binascii.hexlify(hi.pack)))
            print('y = {}, len = {}'.format(hex(hi.y), len(long_to_bytes(hi.y))))
            print('p = {}, len = {}'.format(hex(hi.p), len(long_to_bytes(hi.p))))
            print('g = {}, len = {}'.format(hex(hi.g), len(long_to_bytes(hi.g))))
            print('q = {}, len = {}'.format(hex(hi.q), len(long_to_bytes(hi.q))))

    main()
