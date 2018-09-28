import unittest
import queue 
from HIPState import *
from HIPMessage import *
import struct
from M2Crypto import DH, Rand, DSA
import m2
from HI import *
testHI=HI('hi.priv.pem')

class junk:
    pass

class HIPTests(unittest.TestCase):
    def setUp(self):
        self.SM = StateMachine(state=E0,HI=testHI)
        self.SM.setFQDN('1234')
        self.SM.localHIT = self.SM.HI.pack()
        self.SM.remoteHIT = '\xde\xad\xbe\xef\xde\xad\xbe\xef'
        self.SM.DH = DH.load_params('dh512.pem')

    def testBN2nbo(self):
        bn=m2.dh_get_p(self.SM.DH.dh)
        # Now convert it to +ve network byte order.
        # just chop off first five bytes 'cause this one is positive.
        assert( BN2nbo(bn) == bn[5:] )
        assert( nbo2BN(BN2nbo(bn)) == bn )

##    def testPackXfrm(self):
##        self.failUnless(  hexlify(packXfrm(50, self.SM.hipXfrmList))
##                          == '3200000401070000'
##                          '32000004020300000000000403050000' )

    def testpackDH(self):
        self.SM.DH.gen_key()
        # hopeless test, but what can I do?
        assert( I1.packDH(self.SM) )

    def testFQDN(self):
        self.SM.setFQDN('1234')
        self.assertTrue( self.SM.packFQDN() == '\x00\x041234')
        self.SM.setFQDN('12345')
        self.assertTrue( self.SM.packFQDN() == '\x00\x0512345\x00\x00\x00')

    def testpackTLV(self):
        self.assertTrue( packTLV((1, 2), '1234') ==
                         '\x01\x02\x00\x041234\x00\x00\x00\x00')
        self.assertTrue( packTLV((255, 3), '12345') ==
                         '\xff\x03\x00\x0512345\x00\x00\x00')

    def testunpackTLV(self):
        self.assertTrue( unpackTLV(packTLV((1,2),'1234')) ==
                         ((1, 2), '1234', '') )
        self.assertTrue( unpackTLV(packTLV((1,2),'1234')+'xxxx') ==
                         ((1, 2), '1234', 'xxxx') )

    def testpackTLVC(self):
        self.assertTrue( packTLVC(0x102, '12') ==
                         '\x81\x0212')
        self.assertTrue( packTLVC(0x103, '12345') ==
                         '\x01\x03\x00\x0512345')

    def testunpackTLVC(self):
        self.assertTrue( unpackTLVC(packTLVC(0x102, '12') + 'xxxx') ==
                         (0x102, '12', 'xxxx') )
        self.assertTrue( unpackTLVC(packTLVC(0x102, '12345') + 'xxxx') ==
                         (0x102, '12345', 'xxxx') )

    def testpackLV(self):
        self.assertTrue( packLV('1234') ==
                         '\x00\x041234')
        self.assertTrue( packLV('12345') ==
                         '\x00\x0512345\x00\x00\x00')

    def testunpackLV(self):
        self.assertTrue( unpackLV(packLV('1234') + 'xxxx') ==
                         ('1234', 'xxxx') )
        self.assertTrue( unpackLV(packLV('12345') + 'xxxx') ==
                         ('12345', 'xxxx') )


    def packetIntegTest(self, result):
        (h, rest) = unpackHeader(result, junk())
        #print len(result), hexlify(result)
        print()
        print(hexlify(result[:HIP_HEADER_LEN]), h.fqdn)
        for i in range(0, len(rest), 32):
            print('%4d' % i, hexlify(rest[i:i+32]))
                       
        print()
        print(repr(h.__dict__))
        print('type is', HIP_Packets[h.type])
        n = 0
        b = 0
        l=[]
        while rest:
            n += 1
            (t, v, rest) = unpackTLV(rest)
            ops = [((HIP_RR_OPT, HIP_OPT_IDENT_HIP_TRANSFORM), unpackXfrm),
                   ((HIP_RR_OPT, HIP_OPT_IDENT_ESP_TRANSFORM), unpackXfrm),
                   ((HIP_RR_OPT, HIP_OPT_IDENT_ENCRYPTED),
                    lambda x: I1.unpackEncrypted(self.SM, x)),
                   ]
            try:
                v2 = [x[1] for x in ops if x[0] == (t)][0](*[v])
            except IndexError:
                v2 = hexlify(v)
            l.append((t, v2))
            b += len(v) + 4
        for (t, v) in l:
            if (t) == (HIP_RR_OPT, HIP_OPT_IDENT_ENCRYPTED):
                v2 = '['
                for (nt, nv) in v:
                     v2 += '('+HIP_RECs[nt]+', '+hexorrep(nv)+'), '
                v2 += ']'
            else:
                v2=v
            print(HIP_RECs[t], repr(v2))
        print(h.length, h.rcount, b, n)
        if len([x for x in l if x[:2] == (HIP_RR_SIG, 0)]):
            ver = verifypacket(result, self.SM.HI)
            # excessive, I know, but hey, signature checks are cheap
            # have to miss the padding after the signature,
            # because it isn't checked
            for i in range(0, len(result)-9, 7):
                try:
                    # change one bit
                    r2 = result[:i] + struct.pack('B', struct.unpack('B', result[i])[0] ^ 0x08) + result[i+1:]
                except IndexError:
                    break
                ver = verifypacket(r2, self.SM.HI)
                assert( ver == 0 )
        print()

        self.assertTrue( b <= h.length<<3 )
        self.assertTrue( n == h.rcount )



    def testPackI1(self):
        self.SM.localHIT = '\xab\xcd\xab\xcd\xab\xcd\xab\xcd'
        result = I1.pack(self.SM)
        self.packetIntegTest(result)

    def testExistsR1(self):
        self.assertTrue( R1 )
        self.assertTrue( R1.code == 2 )

    def testPackR1(self):
        # precompute this
        self.SM.DH.gen_key()
        self.SM.Cookie.new()
        result = R1.pack(self.SM)
        self.packetIntegTest(result)


    def testExistsI2(self):
        self.assertTrue( I2 )
        self.assertTrue( I2.code == 3 )

    def testPackI2(self):
        # precompute this
        self.SM.DH.gen_key()
        self.SM.Cookie.new()
        self.SM.Cookie.stored=self.SM.Cookie.pack()
        self.SM.ESPXfrm=self.SM.ESPXfrmList[0]
        self.SM.hipXfrm=self.SM.hipXfrmList[0]
        self.SM.remoteLSI='\x0a\x00\x00\xf0'
        self.SM.remoteSPI='\x00\x00\x00\xf0'
        self.SM.hipkey=unhexlify('deadbeefdeadbeefdeadbeefdeadbeef')
        self.SM.remotehipkey=unhexlify('deadbeefdeadbeefdeadbeefdeadbeef')
        result = I2.pack(self.SM)
        self.packetIntegTest(result)


    def testExistsR2(self):
        self.assertTrue( R2 )
        self.assertTrue( R2.code == 4 )

    def testPackR2(self):
        # precompute this
        self.SM.DH.gen_key()
        self.SM.Cookie.new()
        self.SM.ESPXfrm=self.SM.ESPXfrmList[0]
        self.SM.hipXfrm=self.SM.hipXfrmList[1]
        self.SM.remoteLSI='\x0a\x00\x00\xf0'
        self.SM.remoteSPI='\x00\x00\x00\xf0'
        self.SM.hipkey=unhexlify('deadbeefdeadbeefdeadbeefdeadbeef')
        result = R2.pack(self.SM)
        self.packetIntegTest(result)
        result = R2.pack(self.SM)


    def testExistsREA(self):
        self.assertTrue( REA )
        self.assertTrue( REA.code == 6 )

##    def testPackREA(self):
##        # precompute this
##        self.SM.DH.gen_key()
##        self.SM.Cookie.new()
##        self.SM.ESPXfrm=self.SM.ESPXfrmList[0]
##        self.SM.hipXfrm=self.SM.hipXfrmList[1]
##        self.SM.remoteLSI='\x0a\x00\x00\xf0'
##        self.SM.remoteSPI='\x00\x00\x00\xf0'
##        self.SM.hipkey=unhexlify('deadbeefdeadbeefdeadbeefdeadbeef')
##        result = REA.pack(self.SM, unhexlify('deadbeef'), unhexlify('0a000001'), (unhexlify('0a000101'), unhexlify('fe800000000000000220e0fffe67a4bf')), 'eth0')
##        self.packetIntegTest(result)
##        # v6 addr one byte too short, failUnlessRaises is a mess here
##        dontfail=0
##        try:
##            result = REA.pack(self.SM,
##                              unhexlify('deadbeef'),
##                              unhexlify('0a000001'),
##                              (unhexlify('0a000101'),
##                               unhexlify('fe8000000000000220e0fffe67a4bf')
##                               ), 1)
##        except ValueError:
##            dontfail=1
##        self.failUnless( dontfail )

    def testExistsBOS(self):
        self.assertTrue( BOS )
        self.assertTrue( BOS.code == 10 )

    def testPackBOS(self):
        result = BOS.pack(self.SM)
        self.packetIntegTest(result)

    def testExistsNES(self):
        self.assertTrue( NES )
        self.assertTrue( NES.code == 5 )

##    def testPackNES(self):
##        # precompute this
##        self.SM.DH.gen_key()
##        self.SM.Cookie.new()
##        self.SM.ESPXfrm=self.SM.ESPXfrmList[0]
##        self.SM.hipXfrm=self.SM.hipXfrmList[1]
##        self.SM.remoteLSI='\x0a\x00\x00\xf0'
##        self.SM.remoteSPI='\x00\x00\x00\xf0'
##        self.SM.hipkey=unhexlify('deadbeefdeadbeefdeadbeefdeadbeef')
##        result = NES.pack(self.SM, unhexlify('deadbeef'), unhexlify('0a000001'), unhexlify('0a000101'), 1)
##        self.packetIntegTest(result)




        
suite = unittest.makeSuite(HIPTests,'test')

if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1)
    unittest.main()

