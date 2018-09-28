try:
    from psyco.classes import *
except ImportError:
    pass

import unittest
import queue 
from HIPState import *
from HIPOptMessage import *
import HIPCookie
import struct
import DH
from HI import *

from testlib import ifdict

testHI=HI(List=(0x4db6e03ca8bf11ba15aed05d913339d8b4824073dafc211c8f7db6d2ce48c75770a2375068da6ae878429bafa0f525cf10dcbd23f3caf396276b023803ac35a5,
                0x00a64bc37a17edc7c2adfb7191b1890481c2aab14eadb9ef9040e14e158b026ccabfdebc4810a934ab53ea1df89df81b0c884638145985e41aa680601febe57db7,
                0x00d0d199d0645774f2e1ff473df343adf196df57f0ef275f59cec0e129747134dc37e8cb3895bf5864c9c9d429622039291f1f2c5c46a4d2f91d781d9e7c61813d,
                0x00963b3c5ec2880fa38feb771321dffec8156a03cf,
                0x2d10761d29b55f5e1cfa0baf9a12286efeb0139d))



class junk:
    pass

class HIPOptMessageTests(unittest.TestCase):
    def setUp(self):
        self.SM = StateMachine(state=E0,HI=testHI)
        self.SM.setFQDN('1234')
        self.SM.localHIT = self.SM.HI.HIT127()
        self.SM.remoteHIT = '\xde\xad\xbe\xef\xde\xad\xbe\xef' '\xde\xad\xbe\xef\xde\xad\xbe\xef'
        self.SM.DH = DH.construct((0x00f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fabd00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e92f78c7,
                                   2,
                                   0x5a84f4b9704f010705aaf17cb14b718ad484c253bae508685583276d22e4a089bcb4e35067386250a1462a529073820f3effdc5edc39107198429fbc482c79ab07df798bc23c7517740974c542aec2b1666b59f48d06684e855e32d2e761dc8c482be9aba1bc65cbf84c6b42a11eda1a511f402c17407a31ecfeead7b48054ff,
                                   0x15ae0584d67460bcec34efe7c32bf298a62adad0f53a00db896239e3f8949845064dcef1ad434f24237cac1ae1ea137ab6ad0234e7c742390f8d4c9f6cd8994154ba9c9b9bde38670952b5ab776c137dca1f0bdea0e951b996403fb5452b074987c6272c5099ffb97c8c87abf3f61ba346d122472e45d05f4072d8437da13bb))

##    def testBN2nbo(self):
##        bn=m2.dh_get_p(self.SM.DH.dh)
##        # Now convert it to +ve network byte order.
##        # just chop off first five bytes 'cause this one is positive.
##        assert( BN2nbo(bn) == bn[5:] )
##        assert( nbo2BN(BN2nbo(bn)) == bn )

##    def testPackXfrm(self):
##        self.failUnless(  hexlify(packXfrm(50, self.SM.HIPXfrmList))
##                          == '3200000401070000'
##                          '32000004020300000000000403050000' )

    def testpackDH(self):
        pass
        # hopeless test, but what can I do?
        assert( I1.packDH(self.SM) )

    def testFQDN(self):
        self.SM.setFQDN('1234')
        self.assertTrue( self.SM.packFQDN() == '\x00\x041234')
        self.SM.setFQDN('12345')
        self.assertTrue( self.SM.packFQDN() == '\x00\x0512345\x00\x00\x00')

    def testpackTLV(self):
        self.assertTrue( packTLV(0xabcd, '1234') ==
                         '\xab\xcd\x00\x041234')
        self.assertTrue( packTLV(0xabcd, '12345') ==
                         '\xab\xcd\x00\x0512345\x00\x00\x00\x00\x00\x00\x00')

    def testunpackTLV(self):
        self.assertTrue( unpackTLV(packTLV(0xabcd,'1234')) ==
                         (0xabcd, '1234', '') )
        self.assertTrue( unpackTLV(packTLV(0xabcd,'1234')+'xxxx') ==
                         (0xabcd, '1234', 'xxxx') )

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

    def testHIPHeader(self):
        h = HIPHeader(len=0x1f3,
                   type=1,
                   control=0,
                   sourceHIT=self.SM.localHIT,
                   remoteHIT=self.SM.remoteHIT)
        s = h.pack()
        self.assertTrue( len(s) == HIP_HEADER_LEN )
        h2 = HIPHeader(string=s)
        self.assertTrue( h2.len == 0xf3 )
        self.assertTrue( h2.type == 1 )
        self.assertTrue( h2.control == 0 )
        self.assertTrue( h2.sourceHIT == self.SM.localHIT )
        self.assertTrue( h2.remoteHIT == self.SM.remoteHIT )

    def testHIPRec(self):
        # test basic record class
        r = HIPRec(type = 1, name = 'Test', format = "!\nRes: B", Res=0x3e)
        s = HIPRec(type = 1, name = 'Test2', format = "!\nRes: B", Res=0x3e)
        self.assertTrue( str(r) == 'Test' )
        self.assertTrue( r == s )
        x = {r: 1}
        self.assertTrue( x[s] == 1 )
        self.assertTrue( r.pack() == '\x00\x01\x00\x01\x3e\x00\x00\x00' )
        self.assertTrue( r.pack() == s.pack() )
        r = HIP_REC_SPI_LSI(SPI=1234, LSI=12345678)
        s = HIPRec().unpack(r.pack())
        self.assertTrue( s[1].LSI == r.LSI )

    def testHIP_REC_DH_FULL(self):
        # unique encoding
        r = HIP_REC_DH_FULL(GroupID=129,
                            Prime=unhexlify('12345678'),
                            Generator=unhexlify('87654321'),
                            Public=unhexlify('122178876776'))
        s = HIPRec().unpack(r.pack() + '\xff')
        self.assertTrue( s[1].pack() == r.pack() )
        self.assertTrue( s[1].Public == r.Public )

    def testHIP_REC_HI_FQDN(self):
        # unique encoding
        r = HIP_REC_HI_FQDN(Algorithm=129,
                            Identity=unhexlify('12345678'),
                            FQDN='www.test.co.nz')
        s = HIPRec().unpack(r.pack() + '\xff')
        self.assertTrue( s[1].pack() == r.pack() )
        self.assertTrue( s[1].FQDN == r.FQDN )

    def testHIP_REC_DH(self):
        # tests all HIPIdVal based types
        r = HIP_REC_DH(GroupID=129,
                       Public=unhexlify('122178876776'))
        s = HIPRec().unpack(r.pack() + '\xff')
        self.assertTrue( s[1].pack() == r.pack() )
        self.assertTrue( s[1].Public == r.Public )

    def testHIP_REC_HIP_TRANSFORM(self):
        # actually tests all transforms
        r = HIP_REC_HIP_TRANSFORM(HIPXfrm=[ENCR_AES_128, ENCR_3DES])
        s = HIPRec().unpack(r.pack() + '\xff')
        self.assertTrue( s[1].pack() == r.pack() )

    def testHIP_REC_HMAC(self):
        r = HIP_REC_HMAC(HMAC='12345678901234567890')
        s = HIPRec().unpack(r.pack() + '\xff')
        self.assertTrue( s[1].pack() == r.pack() )

    def testHIP_REC_REA_INFO(self):
        r = HIP_REC_REA_INFO(Interface=2,
                             SPI=1234,
                             RevSPI=1324,
                             NewSPI=2345,
                             interfaces=ifdict,
                             REAID=123,
                             KeyInd=512)
        s = HIPRec().unpack(r.pack() + '\xff')
        self.assertTrue( s[1].pack() == r.pack() )

    def testHIP_REC_ENCRYPTED(self):
        r = HIP_REC_ENCRYPTED(Encrypted=unhexlify('122178876776'))
        s = HIPRec().unpack(r.pack() + '\xff')
        self.assertTrue( s[1].pack() == r.pack() )
        self.assertTrue( s[1].Encrypted == r.Encrypted )

    def packetIntegTest(self, result):
        (h, rest) = (HIPHeader(string=result), result[HIPHeader.size:])
        #print len(result), hexlify(result)
        print()
        print(hexlify(result[:HIP_HEADER_LEN]))
        for i in range(0, len(rest), 32):
            print('%4d' % i, hexlify(rest[i:i+32]))
                       
        print()
        print('type is', HIP_Packets[h.type])
        if h.type in [1, 64]: return
        n = 0
        b = 0
        l=[]
        while rest:
            n += 1
            (t, v, rest) = HIPRec().unpack(rest)
            l.append(v)
            print(str(v), '\n ', '\n  '.join(map(lambda x,y: ' = '.join([x,y]),
                                       list(v.__dict__.keys()),
                                       list(map(hexorrep, list(v.__dict__.values()))))))
        if [x in l for x in [HIP_REC_SIG, HIP_REC_SIG2]]:
            sigrec = [x for x in l if x.name[:3] == 'SIG'][0]
            ver = verifypacket(result, self.SM.HI, sigrec, h)
##            # excessive, I know, but hey, signature checks are cheap
##            # have to miss the padding after the signature,
##            # because it isn't checked
##            for i in range(0, len(result)-9, 7):
##                try:
##                    # change one bit
##                    r2 = result[:i] + struct.pack('B', struct.unpack('B', result[i])[0] ^ 0x08) + result[i+1:]
##                except IndexError:
##                    break
##                ver = verifypacket(r2, self.SM.HI, sigrec, h)
##                assert( ver == 0 )
        print()

    def testPackI1(self):
        self.SM.localHIT = '\xab\xcd\xab\xcd\xab\xcd\xab\xcd'
        result = I1.pack(self.SM)
        self.packetIntegTest(result)

    def testPackR1(self):
        self.SM.Cookie.new()
        result = R1.pack(self.SM)
        self.packetIntegTest(result)

    def testPackI2(self):
        self.SM.Cookie.new()
        self.SM.Cookie.stored=HIPCookie.HIPCookie()
        self.SM.Cookie.stored.K = 6
        self.SM.Cookie.stored.new()
        self.SM.ESPXfrm=self.SM.ESPXfrmList[0]
        self.SM.HIPXfrm=self.SM.HIPXfrmList[0]
        self.SM.remoteLSI=0xa0000f0
        self.SM.remoteSPI=0xf0
        self.SM.hipkey=unhexlify('deadbeefdeadbeefdeadbeefdeadbeef')
        self.SM.remotehipkey=unhexlify('deadbeefdeadbeefdeadbeefdeadbeef')
        result = I2.pack(self.SM)
        self.packetIntegTest(result)

    def testPackR2(self):
        self.SM.Cookie.new()
        self.SM.ESPXfrm=self.SM.ESPXfrmList[0]
        self.SM.HIPXfrm=self.SM.HIPXfrmList[0]
        self.SM.remoteLSI=0xa0000f0
        self.SM.remoteSPI=0xf0
        self.SM.hipkey=unhexlify('deadbeefdeadbeefdeadbeefdeadbeef')
        result = R2.pack(self.SM)
        self.packetIntegTest(result)
        result = R2.pack(self.SM)


    def testExistsREA(self):
        self.assertTrue( REA )
        self.assertTrue( REA.code == 6 )

    def testPackREA(self):
        class dummyESP:
            SPI=12
            SN=42
        self.SM.Cookie.new()
        self.SM.ESPXfrm=self.SM.ESPXfrmList[0]
        self.SM.HIPXfrm=self.SM.HIPXfrmList[0]
        self.SM.remoteLSI='\x0a\x00\x00\xf0'
        self.SM.remoteSPI='\x00\x00\x00\xf0'
        self.SM.remoteESP=dummyESP()
        self.SM.localESP=dummyESP()
        self.SM.hipkey=unhexlify('deadbeefdeadbeefdeadbeefdeadbeef')
        self.SM.localIPs=[(10, 1, 6, '', ('fe80::202:b3ff:fe07:aa16', 0, 0, 0))]
        self.SM.interfaces = ifdict
        self.SM.Interface = 2
        self.SM.nextkeyind = 3
        self.SM.nextreaid = 4
        self.SM.newspi = 5421
        result = REA.pack(self.SM)
        self.packetIntegTest(result)

    def testExistsBOS(self):
        self.assertTrue( BOS )
        self.assertTrue( BOS.code == 7 )

    def testPackBOS(self):
        result = BOS.pack(self.SM)
        self.packetIntegTest(result)

    def testExistsNES(self):
        self.assertTrue( NES )
        self.assertTrue( NES.code == 5 )

    def testPackNES(self):
        class dummyESP:
            SPI=12
            SN=42
        self.SM.Cookie.new()
        self.SM.ESPXfrm=self.SM.ESPXfrmList[0]
        self.SM.HIPXfrm=self.SM.HIPXfrmList[0]
        self.SM.remoteLSI=0xa0000f0
        self.SM.remoteSPI=0xf0
        self.SM.remoteESP=dummyESP()
        self.SM.localESP=dummyESP()
        self.SM.hipkey=unhexlify('deadbeefdeadbeefdeadbeefdeadbeef')
        result = NES.pack(self.SM)
        self.packetIntegTest(result)

    def testPackPAYLOAD(self):
        self.SM.localHIT = '\xab\xcd\xab\xcd\xab\xcd\xab\xcd'
        result = PAYLOAD.pack(self.SM)
        self.packetIntegTest(result)



        
suite = unittest.makeSuite(HIPOptMessageTests,'test')

if __name__ == '__main__':
    unittest.main()

