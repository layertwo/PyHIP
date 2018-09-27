#from M2Crypto import DSA
#import m2
from Crypto.PublicKey import DSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
import sha
import struct
import binascii
#import pickle
import cPickle
import HIPutils
#from pysnmp import asn1
import asn1

idDSA = asn1.OBJECTID('1.2.840.10040.4.3')

##try:
##    import psyco
##    psyco.bind(bytes_to_long)
##    psyco.bind(long_to_bytes)
###    psyco.bind(DSA)
##except ImportError:
##    pass

class error:
    pass

zeroHIT = binascii.unhexlify('00000000000000000000000000000000')

class HI:
    HITable = {}
    Algorithm = 1 # DSA
    def callback(self, *args):
        pass

    def __init__(self,file=None,Rec=None,List=None,Size=512):
        if file:
            self.dsa = DSA.construct(cPickle.load(open(file, 'rb')))
        elif Rec:
            self.unpack(Rec)
        elif List:
            self.dsa = DSA.construct(List)
        else:
            self.dsa = DSA.generate(Size, HIPutils.RandomPool.get_bytes)
##        try:
##            print 'y = ', hex(self.dsa.y), len(long_to_bytes(self.dsa.y))
##            print 'p = ', hex(self.dsa.p), len(long_to_bytes(self.dsa.p))
##            print 'g = ', hex(self.dsa.g), len(long_to_bytes(self.dsa.g))
##            print 'q = ', hex(self.dsa.q), len(long_to_bytes(self.dsa.q))
##        except:
##            pass

    def genKey(self):
        pass
        #self.dsa.generate()

    def packDSA(self):
        # RFC2536: t=len(p)/64-1
        # RFC2536: q p g y 
        q = long_to_bytes(self.dsa.q)
        p = long_to_bytes(self.dsa.p)
        g = long_to_bytes(self.dsa.g)
        y = long_to_bytes(self.dsa.y)
        l = len(p)
        t = (l-64)/8
        pad = '\x00' * (l)
        RR = ''.join([chr(t),
                      q[:l],
                      pad[:-len(p)], p[:l],
                      pad[:-len(g)], g[:l],
                      pad[:-len(y)], y[:l]])
        #print 'len RR', len(RR)
        return RR
        

    def pack(self):
        # RFC2535: 0x0200 flags,
        #          0xff protocol (or IANA HIP value)
        #          0x03 algorithm DSA (mandatory)
        RR = ''.join(['\x02\x00\xff\x03',
                      self.packDSA()])
        #print 'len RR', len(RR)
        return RR

    def unpackDSA(self, string):
        #print 'unpackDSA', len(string), binascii.hexlify(string)
        #t = 64 * (ord(string[0])+1)
        t = (ord(string[0])*8+64)
        if (len(string) != (1 + 20 + (3 * t))):
            raise ValueError, 'HI: got RR length %d expecting %d' % (len(string), (1 + 20 + (3 * t)))
        (t, q, p, g, y) = struct.unpack('!B20s%ds%ds%ds'%(t,t,t), string)
        self.dsa = DSA.construct([bytes_to_long(y),
                                  bytes_to_long(g),
                                  bytes_to_long(p),
                                  bytes_to_long(q)])

    def unpack(self, RR):
        self.unpackDSA(RR[4:])
        
    def packASN1(self):
        # yuck what a horrid library!
        dssParms = ''.join([asn1.INTEGER(x).encode()
                             for x in [self.dsa.p,
                                       self.dsa.q,
                                       self.dsa.g]])
        keyInfo = ''.join([asn1.SEQUENCE(''.join([idDSA.encode(),
                                                   asn1.SEQUENCE(dssParms).encode()])).encode(),
                            asn1.INTEGER(self.dsa.y).encode()])
        return asn1.SEQUENCE(keyInfo).encode()

    def unpackASN1(self, string):
        # yuck what a horrid library!
        seq, rest = asn1.decode(string)
        if rest: raise ValueError, 'HI: unpack failed'
        algseq, pubkey = asn1.decode(seq.value)
        oid, rest = asn1.decode(algseq.value)
        dssParmseq, junk = asn1.decode(rest)
        dssParms = dssParmseq.value
        parms = []
        while dssParms:
            p, dssParms = asn1.decode(dssParms)
            parms.append(p)
        p, rest = asn1.decode(pubkey)
        parms.append(p)
        parms = [x.value for x in parms]
        p, q, g, y = tuple(parms)
        self.dsa = DSA.construct([y, g, p, q])


    def signRDATA(self, str):
        l = len(long_to_bytes(self.dsa.p))
        t = (l-64)/8
        r, s = self.dsa.sign(bytes_to_long(sha.new(str).digest()),
                             HIPutils.RandomPool.get_bytes(
            len(long_to_bytes(self.dsa.q))-1))
##        print 'HI.sign'
##        print hexlify(long_to_bytes(r)), hexlify(long_to_bytes(s))
##        print hexlify(sha.new(str).digest())
##        print repr(self.dsa.__dict__)
##        print self.dsa.size()
        #print len(r), hexlify(r), len(s), hexlify(s)
        return ''.join([chr(t), long_to_bytes(r), long_to_bytes(s)])

    def verifyRDATA(self, str, sig):
##        print 'HI.verify'
##        print hexlify(sig[1:21]), hexlify(sig[21:])
##        print hexlify(sha.new(str).digest())
##        print repr(self.dsa.__dict__)
##        print self.dsa.size()
        return self.dsa.verify(bytes_to_long(sha.new(str).digest()),
                               (bytes_to_long(sig[1:21]),
                                bytes_to_long(sig[21:])))

    def signASN1(self, str):
        t = chr((len(long_to_bytes(self.dsa.p))/64)-1)
        r, s = self.dsa.sign(bytes_to_long(sha.new(str).digest()),
                             HIPutils.RandomPool.get_bytes(
            len(long_to_bytes(self.dsa.q))-1))
##        print 'HI.sign'
##        print binascii.hexlify(long_to_bytes(r)), binascii.hexlify(long_to_bytes(s))
##        print binascii.hexlify(sha.new(str).digest())
##        print repr(self.dsa.__dict__)
##        print self.dsa.size()
        #print len(r), binascii.hexlify(r), len(s), binascii.hexlify(s)
        sigInfo = ''.join([asn1.INTEGER().encode(r),
                           asn1.INTEGER().encode(s)])
        sig = asn1.SEQUENCE(sigInfo).encode()
##        print repr(sig)
        return sig

#    siglen = 41
#    sigpadlen = 48

    def verifyASN1(self, str, sig):
##        print 'HI.verify'
##        print repr(str), repr(sig)
##        print binascii.hexlify(sig[1:21]), binascii.hexlify(sig[21:])
##        print binascii.hexlify(sha.new(str).digest())
##        print repr(self.dsa.__dict__)
##        print self.dsa.size()
        seq, rest = asn1.decode(sig)
        if rest: raise ValueError, 'HI: unpack failed'
        r, rest = asn1.decode(seq.value)
        s, rest = asn1.decode(rest)
        return self.dsa.verify(bytes_to_long(sha.new(str).digest()),
                               (r.value, s.value))

    sign = signRDATA
    verify = verifyRDATA

    def __rawhash__(self):
        return sha.new(self.pack()).digest()[-16:]        

    def HIT(self, template, mask):
        hash=self.__rawhash__()
        self.hit = apply( struct.pack,
                          ['16B'] + map(lambda h, t, m: t | (h & m),
                                       struct.unpack('16B', hash),
                                       struct.unpack('16B', template),
                                       struct.unpack('16B', mask)
                                       ))
        return self.hit

        
    def HIT127(self):
        self.hit127 = self.HIT(binascii.unhexlify('40000000000000000000000000000000'),
                               binascii.unhexlify('7fffffffffffffffffffffffffffffff'))
        return self.hit127

    def HITRR(self):
        return self.HIT127()
        #return '\x00\x00\xff\x63' + self.HIT127()
    
        
    def HIT64(self, HAA):
        # HIT64 with arbitrary HAA
        return self.HIT(HAA,
                        binascii.unhexlify('0000000000000000ffffffffffffffff'))

    def HIT3041(self, prefix):
        # RFC3041 prefix
        return self.HIT(prefix,
                        binascii.unhexlify('0000000000000000fdffffffffffffff'))

    #def HITv6link(self):
    #    return self.HIT(binascii.unhexlify('fe800000000000000000000000000000'),
    #                    binascii.unhexlify('004fffffffffffffffffffffffffffff'))

    HITv6link = HIT127



if __name__ == "__main__":
    def main():
        from getopt import getopt
        import sys

        opts, args = getopt(sys.argv[1:],
                            'w:r:h:',
                            ['write=',
                             'read=',
                             'hostkey='])

        for opt, val in opts:
            if opt in ('-w', '--write'):
                filename = val
                print 'Writing new HI to:', filename
                hi = HI()
                print repr(hi)
                cPickle.dump([hi.dsa.y,
                              hi.dsa.g,
                              hi.dsa.p,
                              hi.dsa.q,
                              hi.dsa.x], file(filename, 'wb'))
                print 'HIT is', binascii.hexlify(hi.HIT127())
                print 'RR is', binascii.hexlify(hi.pack())
                print 'y = ', hex(hi.dsa.y), len(long_to_bytes(hi.dsa.y))
                print 'p = ', hex(hi.dsa.p), len(long_to_bytes(hi.dsa.p))
                print 'g = ', hex(hi.dsa.g), len(long_to_bytes(hi.dsa.g))
                print 'q = ', hex(hi.dsa.q), len(long_to_bytes(hi.dsa.q))
            if opt in ('-r', '--read'):
                filename = val
                print 'Reading HI from', filename
                rec = file(filename,'r').read().strip()
                hi = HI(Rec=binascii.unhexlify(rec))
                print 'HIT is', binascii.hexlify(hi.HIT127())
                print 'RR is', binascii.hexlify(hi.pack())
                print 'y = ', hi.dsa.y
                print 'p = ', hi.dsa.p
                print 'g = ', hi.dsa.g
                print 'q = ', hi.dsa.q
            if opt in ('-h', '--hostkey'):
                print 'Reading HI from', val
                hi = HI(val)
                print 'HIT is', binascii.hexlify(hi.HIT127())
                print 'RR is', binascii.hexlify(hi.pack())
                print 'y = ', hex(hi.dsa.y), len(long_to_bytes(hi.dsa.y))
                print 'p = ', hex(hi.dsa.p), len(long_to_bytes(hi.dsa.p))
                print 'g = ', hex(hi.dsa.g), len(long_to_bytes(hi.dsa.g))
                print 'q = ', hex(hi.dsa.q), len(long_to_bytes(hi.dsa.q))
        pass

    main()
