import unittest
import struct
from Crypto.PublicKey import DSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

from binascii import hexlify, unhexlify

from HI import *


class HITests(unittest.TestCase):
    def setUp(self):
        # do this so we have something constant to work with
        self.hi = HI(List=(0x4db6e03ca8bf11ba15aed05d913339d8b4824073dafc211c8f7db6d2ce48c75770a2375068da6ae878429bafa0f525cf10dcbd23f3caf396276b023803ac35a5,
                           0x00a64bc37a17edc7c2adfb7191b1890481c2aab14eadb9ef9040e14e158b026ccabfdebc4810a934ab53ea1df89df81b0c884638145985e41aa680601febe57db7,
                           0x00d0d199d0645774f2e1ff473df343adf196df57f0ef275f59cec0e129747134dc37e8cb3895bf5864c9c9d429622039291f1f2c5c46a4d2f91d781d9e7c61813d,
                           0x00963b3c5ec2880fa38feb771321dffec8156a03cf,
                           0x2d10761d29b55f5e1cfa0baf9a12286efeb0139d))

    # actually, test the test framework...
    def testNothing(self):
        pass

    def testGen(self):
        hi = HI()

#    def testFile(self):
#        hi=HI('dsa.priv.pem')

# def testListLoad(self):
# actual load is done in setUp()
##        self.failUnless( self.dsa.y == 0x4db6e03ca8bf11ba15aed05d913339d8b4824073dafc211c8f7db6d2ce48c75770a2375068da6ae878429bafa0f525cf10dcbd23f3caf396276b023803ac35a5 )
# ok, so we got the right number.


# def testBN2nbo(self):
# bn=m2.dsa_get_p(self.hi.dsa.dsa)
# Now convert it to +ve network byte order.
# just chop off first five bytes 'cause this one is positive.
##        assert( BN2nbo(bn) == bn[5:] )
# now make up a negative number
##        bn2 = "\x00\x00\x00A\xff\xd0\xd1\x99\xd0dWt\xf2\xe1\xffG=\xf3C\xad\xf1\x96\xdfW\xf0\xef\'_Y\xce\xc0\xe1)tq4\xdc7\xe8\xcb8\x95\xbfXd\xc9\xc9\xd4)b 9)\x1f\x1f,\\F\xa4\xd2\xf9\x1dx\x1d\x9e|a\x81="
# now chop off first FOUR bytes
# note this now means can't distinguish -ve from +ve w/ 1st bit set.
# must find a better way if this is ever a problem
##        assert( BN2nbo(bn2) == bn2[4:] )

    def testPack(self):
        # RFC2535: 0x0200 flags,
        #          0xff protocol (or IANA HIP value)
        #          0x03 algorithm DSA (mandatory)
        # RFC2536: t=0x00, q p g y
        RR = self.hi.pack()
        #assert( len(RR) == 4 + 1 + 20 + (64 * 3) )
        #assert( RR[:4] == '\x02\x00\xff\x03' )
        #assert( RR[4] == '\x00' )

    def testUnPack(self):
        # RFC2535: 0x0200 flags,
        #          0xff protocol (or IANA HIP value)
        #          0x03 algorithm DSA (mandatory)
        # RFC2536: t=0x00, q p g y
        RR = self.hi.pack()
        hi2 = self.hi
        hi2.unpack(RR)
        assert(hi2.dsa.y == self.hi.dsa.y)

    def testSigs(self):
        RR = self.hi.pack()
        hi2 = HI(Rec=RR)
        # hi2.genKey()
        str = 'this is a fairly long test string'
        sig = self.hi.sign(str)
        hi2.verify(str, sig)

    def testUnPackASN1(self):
        # RFC2535: 0x0200 flags,
        #          0xff protocol (or IANA HIP value)
        #          0x03 algorithm DSA (mandatory)
        # RFC2536: t=0x00, q p g y
        RR = self.hi.packASN1()
        hi2 = self.hi
        hi2.unpackASN1(RR)
        assert(hi2.dsa.y == self.hi.dsa.y)

    def testHIT127(self):
        assert(hexlify(self.hi.HIT127()) == '693b77c49c6f6964dae3f9e43a216e93')

    def testKeyGen(self):
        self.hi = HI()
        #self.failUnlessRaises( DSA.DSAError, self.hi.pack )
        # self.hi.genKey()
        self.assertTrue(self.hi.pack())

    def testSignVerify(self):
        self.hi = HI()
        self.hi.genKey()
        #str = 'stuff, stuff, and more stuff'
        str = self.hi.pack()
        sig = self.hi.sign(str)
        v = self.hi.verify(str, sig)
        self.assertTrue(v)
        str += 'gibberish'
        self.assertTrue(not self.hi.verify(str, sig))


suite = unittest.makeSuite(HITests, 'test')

if __name__ == '__main__':
    unittest.main()
