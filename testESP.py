import struct
import unittest
from binascii import hexlify, unhexlify
from ESP import *

class SPITests(unittest.TestCase):
    def setUp(self):
        self.key=unhexlify('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')
        self.authkey=unhexlify('deadbeefdeadbeefdeadbeefdeadbeefdeadbeef')
        self.iv=unhexlify('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')
        pass


    def testInit(self):
        self.iv = self.iv[:8]
        self.SPI = SPI(SPI=1234, key=self.key, iv=self.iv, authkey=self.authkey)
        self.deSPI = SPI(SPI=1234, key=self.key, iv=self.iv, authkey=self.authkey)
        assert( SPI(key=self.key, iv=self.iv) )
        assert( SPI(key=self.key, iv=self.iv).SN == 0 )
        assert( SPI(SPI=1234, key=self.key, iv=self.iv).SPI == 1234 )
        assert( SPI(SPI=1234, key=self.key, iv=self.iv).SN == 0 )
        

    def UnpackTester(self, alg):
        self.SPI = SPI(SPI=1234, key=self.key, iv=self.iv, authkey=self.authkey, algname=alg)
        #self.deSPI = SPI(SPI=1234, key=self.key, iv=self.iv, authkey=self.authkey, algname=alg)
        self.deSPI = SPI(SPI=1234, key=self.key, authkey=self.authkey, algname=alg)
        #print repr(self.SPI.__dict__)
        #print repr(self.deSPI.__dict__)
        s = 'this is some data' * 17
        p = self.SPI.pack(99,s)
        #print 'was:', hexlify(p)
        q = self.deSPI.unpack(p)
        #assert( q[:3] == (self.SPI.SPI, self.SPI.SN, s) )
        if self.authkey:
            p1 = '\xff' + p[1:]
            #print 'now:', hexlify(p1)
            self.assertRaises( ESPUnpackError, self.deSPI.unpack, p1 )
            p2 = p[:-21] + '\xff' + p[-20:]
            #print 'and:', hexlify(p2)
            self.assertRaises( ESPUnpackError, self.deSPI.unpack, p2 )
        # now test that IV's work
        p2 = self.SPI.pack(99,s)
        assert( p != p2 )
        p3 = self.SPI.pack(99,s)
        assert( p2 != p3 )
        
    def testUnpack3DES(self):
        self.iv=self.iv[:8]
        self.UnpackTester('3DES-HMAC-SHA1-96')

    def testUnpackBF(self):
        self.key=self.key[:16]
        self.iv=self.iv[:8]
        self.UnpackTester('Blowfish-HMAC-SHA1-96')

    def testUnpackAES(self):
        self.key=self.key[:16]
        self.iv=self.iv[:16]
        self.UnpackTester('AES-HMAC-SHA1-96')

    def testUnpack3DESNOAUTH(self):
        self.iv=self.iv[:8]
        self.authkey=None
        self.UnpackTester('3DES')

    def testUnpackBFNOAUTH(self):
        self.authkey=None
        self.iv=self.iv[:8]
        self.key=self.key[:16]
        self.UnpackTester('Blowfish')

    def testUnpackAESNOAUTH(self):
        self.authkey=None
        self.key=self.key[:16]
        self.iv=self.iv[:16]
        self.UnpackTester( 'AES' )


suite = unittest.makeSuite(SPITests,'test')

if __name__ == '__main__':
    unittest.main()
