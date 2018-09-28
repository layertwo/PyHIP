import libnet
import struct
import unittest
import time

from binascii import hexlify, unhexlify
import PyrexUtils
import Utils


class UtilsTests(unittest.TestCase):
    def setUp(self):
        self.pkt1 = unhexlify(
            '45000045bb0200003c0697e94223d855d2563ef80050811562e75fa4043263d08018fffffeb800000101080a006fb5cd059e94a32b4c656674506f736974696f6e2b272c73')

        self.pkt2 = unhexlify(
            '450000280000400040060f09d2563ef84223d85581150050043263d000000000500400009ab10000')
        print(len(self.pkt1), len(self.pkt2))
        pass

    def testpyrexpackTLV(self):
        self.assertTrue(PyrexUtils.packTLV(0xabcd, '1234') ==
                        '\xab\xcd\x00\x041234')
        self.assertTrue(PyrexUtils.packTLV(0xabcd, '12345') ==
                        '\xab\xcd\x00\x0512345\x00\x00\x00\x00\x00\x00\x00')

    def testpyrexunpackTLV(self):
        self.assertTrue(PyrexUtils.unpackTLV(PyrexUtils.packTLV(0xabcd, '1234')) ==
                        (0xabcd, '1234', ''))
        self.assertTrue(PyrexUtils.unpackTLV(PyrexUtils.packTLV(0xabcd, '1234') + 'xxxx') ==
                        (0xabcd, '1234', 'xxxx'))

    def testpackTLV(self):
        self.assertTrue(Utils.packTLV(0xabcd, '1234') ==
                        '\xab\xcd\x00\x041234')
        self.assertTrue(Utils.packTLV(0xabcd, '12345') ==
                        '\xab\xcd\x00\x0512345\x00\x00\x00\x00\x00\x00\x00')

    def testunpackTLV(self):
        self.assertTrue(Utils.unpackTLV(Utils.packTLV(0xabcd, '1234')) ==
                        (0xabcd, '1234', ''))
        self.assertTrue(Utils.unpackTLV(Utils.packTLV(0xabcd, '1234') + 'xxxx') ==
                        (0xabcd, '1234', 'xxxx'))

    def testpyrexpackLV(self):
        self.assertTrue(PyrexUtils.packLV('1234') ==
                        '\x00\x041234')
        self.assertTrue(PyrexUtils.packLV('12345') ==
                        '\x00\x0512345\x00\x00\x00')

    def testpyrexunpackLV(self):
        self.assertTrue(PyrexUtils.unpackLV(PyrexUtils.packLV('1234' * 1024) + 'xxxx') ==
                        ('1234' * 1024, 'xxxx'))
        self.assertTrue(PyrexUtils.unpackLV(PyrexUtils.packLV('12345' * 1024) + 'xxxx') ==
                        ('12345' * 1024, 'xxxx'))

    def testpackLV(self):
        self.assertTrue(Utils.packLV('1234') ==
                        '\x00\x041234')
        self.assertTrue(Utils.packLV('12345') ==
                        '\x00\x0512345\x00\x00\x00')

    def testunpackLV(self):
        self.assertTrue(Utils.unpackLV(Utils.packLV('1234' * 1024) + 'xxxx') ==
                        ('1234' * 1024, 'xxxx'))
        self.assertTrue(Utils.unpackLV(Utils.packLV('12345' * 1024) + 'xxxx') ==
                        ('12345' * 1024, 'xxxx'))

    def testfixULPChecksum(self):
        pkt3 = Utils.fixULPChecksum(self.pkt1)
        # print 'Utils:'
        # print hexlify(self.pkt1)
        # print hexlify(pkt2)
        print(hexlify(self.pkt1))
        print(hexlify(pkt3))
        self.assertTrue(self.pkt1 == pkt3)

# def testpyrexfixULPChecksum(self):
##        pkt3 = PyrexUtils.fixULPChecksum(self.pkt1)
# print 'PyrexUtils:'
# print hexlify(self.pkt1)
# print hexlify(pkt2)
# print hexlify(self.pkt1)
# print hexlify(pkt3)
##        self.failUnless(self.pkt1 == pkt3)
##        pkt3 = Utils.fixULPChecksum(self.pkt2)
##        pkt4 = PyrexUtils.fixULPChecksum(self.pkt2)
# print hexlify(self.pkt1)
# print hexlify(self.pkt2)
# print hexlify(pkt3)
# print hexlify(pkt4)
##        self.failUnless(pkt3 == self.pkt2)
##        self.failUnless(pkt4 == self.pkt2)

    def testSpeed(self):
        s = '1234' * 1024
        c = time.clock()
        for i in range(20000):
            Utils.unpackLV(Utils.packLV(s) + 'xxxx')
        c = time.clock() - c
        print('LV: python:', c, end=' ')
        c1 = time.clock()
        for i in range(20000):
            PyrexUtils.unpackLV(PyrexUtils.packLV(s) + 'xxxx')
        c1 = time.clock() - c1
        print('pyrex:', c1, end=' ')
        print('ratio:', c / c1)
        c = time.clock()
        for i in range(20000):
            Utils.unpackTLV(Utils.packTLV(0xabcd, s) + 'xxxx')
        c = time.clock() - c
        print('TLV: python:', c, end=' ')
        c1 = time.clock()
        for i in range(20000):
            PyrexUtils.unpackTLV(PyrexUtils.packTLV(0xabcd, s) + 'xxxx')
        c1 = time.clock() - c1
        print('pyrex:', c1, end=' ')
        print('ratio:', c / c1)
        p = self.pkt1
        f = Utils.fixULPChecksum
        c = time.clock()
        for i in range(20000):
            f(p)
        c = time.clock() - c
        print('Checksum: python:', c, end=' ')
        f = PyrexUtils.fixULPChecksum
        c1 = time.clock()
        for i in range(20000):
            f(p)
        c1 = time.clock() - c1
        print('pyrex:', c1, end=' ')
        print('ratio:', c / c1)


suite = unittest.makeSuite(UtilsTests, 'test')

if __name__ == '__main__':
    unittest.main()
