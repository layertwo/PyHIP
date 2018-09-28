import libnet
import struct
import unittest
import time

from binascii import hexlify, unhexlify

import IPAddress


class IPAddressesTests(unittest.TestCase):
    def setUp(self):
        pass

    def testIPCl(self):
        a = IPAddress.IP('192.168.1.1')
        b = IPAddress.IP('192.168.1.1')
        c = IPAddress.IP('192.168.1.2')
        self.assertTrue(a == b)
        self.assertTrue(not a == c)
        a = IPAddress.IP('fe80::dead:beef')
        self.assertTrue(not a == c)
        b = IPAddress.IP(a.Netstring)
        self.assertTrue(a == b)
        b = IPAddress.IP((a.String, 0, 0, 0))
        self.assertTrue(a == b)
        c = IPAddress.IP(a.Addrinfo)
        self.assertTrue(a == c)
        b = IPAddress.IP(a.Number)
        self.assertTrue(a == b)
        self.assertTrue({a.Netstring: a}[a.Netstring] is a)
        thedict = {}
        thedict.update(a.allDict())
        self.assertTrue(thedict[a.Netstring] is a)
        self.assertTrue(thedict[a] is a)
        self.assertTrue(thedict[b] is a)
        c = IPAddress.IP(a)
        self.assertTrue(a == c)


suite = unittest.makeSuite(IPAddressesTests, 'test')

if __name__ == '__main__':
    unittest.main()
