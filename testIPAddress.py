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
        self.failUnless( a == b ) 
        self.failUnless( not a == c )
        a = IPAddress.IP('fe80::dead:beef')
        self.failUnless( not a == c )
        b = IPAddress.IP(a.Netstring)
        self.failUnless( a == b )
        b = IPAddress.IP((a.String, 0, 0, 0))
        self.failUnless( a == b )
        c = IPAddress.IP(a.Addrinfo)
        self.failUnless( a == c ) 
        b = IPAddress.IP(a.Number)
        self.failUnless( a == b )
        self.failUnless( {a.Netstring: a}[a.Netstring] is a )
        thedict = {}
        thedict.update(a.allDict())
        self.failUnless( thedict[a.Netstring] is a )
        self.failUnless( thedict[a] is a )
        self.failUnless( thedict[b] is a )
        c = IPAddress.IP(a)
        self.failUnless( a == c ) 


suite = unittest.makeSuite(IPAddressesTests,'test')

if __name__ == '__main__':
    unittest.main()
