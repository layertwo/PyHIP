import unittest
import Queue 
from HIPState import *
from HIPOptMessage import *
import struct
from HI import *
testHI=HI(List=(0x4db6e03ca8bf11ba15aed05d913339d8b4824073dafc211c8f7db6d2ce48c75770a2375068da6ae878429bafa0f525cf10dcbd23f3caf396276b023803ac35a5,
                0x00a64bc37a17edc7c2adfb7191b1890481c2aab14eadb9ef9040e14e158b026ccabfdebc4810a934ab53ea1df89df81b0c884638145985e41aa680601febe57db7,
                0x00d0d199d0645774f2e1ff473df343adf196df57f0ef275f59cec0e129747134dc37e8cb3895bf5864c9c9d429622039291f1f2c5c46a4d2f91d781d9e7c61813d,
                0x00963b3c5ec2880fa38feb771321dffec8156a03cf,
                0x2d10761d29b55f5e1cfa0baf9a12286efeb0139d))

class junk:
    pass

class HIPTests(unittest.TestCase):
    def setUp(self):
        self.SM = StateMachine(state=E0,HI=testHI)
        self.SM.setFQDN('1234')
        self.SM.localHIT = self.SM.HI.pack()
        self.SM.remoteHIT = '\xde\xad\xbe\xef\xde\xad\xbe\xef'
        self.SM.DH = DH.construct((0x00f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fabd00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e92f78c7,
                                   2,
                                   0x5a84f4b9704f010705aaf17cb14b718ad484c253bae508685583276d22e4a089bcb4e35067386250a1462a529073820f3effdc5edc39107198429fbc482c79ab07df798bc23c7517740974c542aec2b1666b59f48d06684e855e32d2e761dc8c482be9aba1bc65cbf84c6b42a11eda1a511f402c17407a31ecfeead7b48054ff,
                                   0x15ae0584d67460bcec34efe7c32bf298a62adad0f53a00db896239e3f8949845064dcef1ad434f24237cac1ae1ea137ab6ad0234e7c742390f8d4c9f6cd8994154ba9c9b9bde38670952b5ab776c137dca1f0bdea0e951b996403fb5452b074987c6272c5099ffb97c8c87abf3f61ba346d122472e45d05f4072d8437da13bb))



##    def testCookieOp(self):
##        self.failUnless( HIPCookie().cookieOp('\x00\x00\x00\x00\x00\x00\x00\x00','\xff\xff\xff\xff\xff\xff\xff\xff',10) == '\x00\x00\x00\x00\x00\x00\x03\xff' )
        
    def testMakeCookieAndCheekCookie(self):
        # note: sign means 27 is the right place to stop
        for i in range(3,27):
            self.SM.Cookie.K = i
            r = self.SM.Cookie.new()
            self.failUnless( (struct.unpack('!L',r[-4:])[0]) < ((2<<self.SM.Cookie.K+1)) )
        self.SM.Cookie.K = 28
        self.failUnlessRaises( ValueError, self.SM.Cookie.new )

    def testCookiePuzzle(self):
            self.SM.Cookie.K = 9
            self.SM.Cookie.new()
            c = self.SM.Cookie.pack()
            r = self.SM.Cookie.puzzle(c)
            self.failUnless( self.SM.Cookie.check(r) )


    def testExistsE0(self):
        self.failUnless( E0 )

    def testExistsE1(self):
        self.failUnless( E1 )

    def testExistsE2(self):
        self.failUnless( E2 )

    def testExistsE3(self):
        self.failUnless( E3 )

    def testExistsI1(self):
        self.failUnless( I1 )
        self.failUnless( I1.code == 1 )

    def packetIntegTest(self, result):
        (h, rest) = unpackHeader(result, junk())
        #print len(result), hexlify(result)
        print
        print hexlify(result[:HIP_HEADER_LEN]), h.fqdn
        for i in range(0, len(rest), 32):
            print '%4d' % i, hexlify(rest[i:i+32])
                       
        print
        print repr(h.__dict__)
        print 'type is', HIP_Packets[h.type]
        n = 0
        b = 0
        l=[]
        while rest:
            n += 1
            (t, v, rest) = unpackTLV(rest)
            ops = [((HIP_RR_OPT, HIP_OPT_IDENT_HIP_TRANSFORM), unpackXfrm),
                   ((HIP_RR_OPT, HIP_OPT_IDENT_ESP_TRANSFORM), unpackXfrm),
                   ((HIP_RR_OPT, HIP_OPT_IDENT_ENCRYPTED), self.SM.unpackEncrypted),
                   ]
            try:
                v2 = apply([x[1] for x in ops if x[0] == (t)][0], [v])
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
            print HIP_RECs[t], repr(v2)
        print h.length, h.rcount, b, n
        if len(filter(lambda x: x[:2] == (HIP_RR_SIG, 0), l)):
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
        print

        self.failUnless( b <= h.length<<3 )
        self.failUnless( n == h.rcount )



    def testSetState(self):
        self.SM.setstate(E1)
        self.failUnless( self.SM.state == E1 )

    def testE0getsI1(self):
        result=self.SM.next(I1)
        self.failUnless( self.SM.state == E0 )
        self.failUnless( self.SM.emit()[0] == R1 )

    def testE0getsI2(self):
        message=I2
        message.valid=1
        result=self.SM.next(message)
        self.failUnless( self.SM.state == E3 )
        self.failUnless( self.SM.emit()[0] == R2 )
        self.SM.setstate(E0)
        message.valid=None
        result=self.SM.next(message)
        self.failUnless( self.SM.state == E0 )
        self.failUnless(self.SM.OutQueue.queue.empty()==1)

    def testE0getsESP(self):
        result=self.SM.next(ESPM)
        self.failUnless( self.SM.state == E0 )
        self.failUnless( self.SM.emit()[0] == R1 )

    def testE0getsOther(self):
        list = [
            R1,
            R2,
            REA,
            BOS,
            NES
            ]
        for i in list:
            result=self.SM.next(i)
            self.failUnless( self.SM.state == E0 )
            self.failUnless(self.SM.OutQueue.queue.empty()==1)

    def testE1getsR1(self):
        self.SM.setstate(E1)
        message=R1
        message.valid=1
        result=self.SM.next(message)
        self.failUnless( self.SM.state == E2 )
        self.failUnless( self.SM.emit()[0] == I2 )
        self.SM.setstate(E1)
        message.valid=None
        result=self.SM.next(message)
        self.failUnless( self.SM.state == EFail )
        self.failUnless(self.SM.OutQueue.queue.empty()==1)


    def testE1getsOther(self):
        self.SM.setstate(E1)
        list = [
            I1,
            I2,
            R2,
            REA,
            BOS,
            NES,
            ESPM
            ]
        for i in list:
            result=self.SM.next(i)
            self.failUnless( self.SM.state == E1 )
        self.failUnless(self.SM.OutQueue.queue.empty()==1)

    def testE2getsR2(self):
        self.SM.setstate(E2)
        message=R2
        message.valid=1
        result=self.SM.next(message)
        self.failUnless( self.SM.state == E3 )
        self.failUnless(self.SM.OutQueue.queue.empty()==1)
        self.SM.setstate(E2)
        message.valid=None
        result=self.SM.next(message)
        self.failUnless( self.SM.state == EFail )
        self.failUnless(self.SM.OutQueue.queue.empty()==1)


    def testE2getsOther(self):
        self.SM.setstate(E2)
        list = [
            I1,
            I2,
            R1,
            REA,
            BOS,
            NES,
            ESPM
            ]
        for i in list:
            result=self.SM.next(i)
            self.failUnless( self.SM.state == E2 )
            self.failUnless(self.SM.OutQueue.queue.empty()==1)

##    def testE3getsNES(self):
##        self.SM.setstate(E3)
##        message=NES
##        message.valid=1
##        result=self.SM.next(message)
##        self.failUnless( self.SM.state == E3 )
##        self.failUnless( self.SM.emit()[0] == NES )
##        message.valid=None
##        result=self.SM.next(message)
##        self.failUnless( self.SM.state == E3 )
##        self.failUnless(self.SM.OutQueue.queue.empty()==1)

    def testE3getsI2(self):
        self.SM.setstate(E3)
        message=I2
        message.valid=1
        result=self.SM.next(message)
        self.failUnless( self.SM.state == E3 )
        self.failUnless( self.SM.emit()[0] == R2 )
        # incomplete: drop SA
        self.SM.setstate(E3)
        message.valid=None
        result=self.SM.next(message)
        self.failUnless( self.SM.state == E3 )
        self.failUnless(self.SM.OutQueue.queue.empty()==1)


    def testE3getsR1(self):
        self.SM.setstate(E3)
        message=R1
        message.valid=1
        result=self.SM.next(message)
        self.failUnless( self.SM.state == E2 )
        self.failUnless( self.SM.emit()[0] == I2 )
        # incomplete: piggyback ESP
        # incomplete: drop SA
        self.SM.setstate(E3)
        message.valid=None
        result=self.SM.next(message)
        self.failUnless( self.SM.state == E3 )
        self.failUnless(self.SM.OutQueue.queue.empty()==1)


    def testE3getsREA(self):
        self.SM.setstate(E3)
        message=REA
        message.valid=1
        result=self.SM.next(message)
        self.failUnless( self.SM.state == E3 )
        self.failUnless(self.SM.OutQueue.queue.empty()==1)
        # incomplete: REA worked (test here at all?)
        message.valid=None
        result=self.SM.next(message)
        self.failUnless( self.SM.state == E3 )
        self.failUnless(self.SM.OutQueue.queue.empty()==1)


    def testE3getsI1(self):
        self.SM.setstate(E3)
        message=I1
        message.valid=1
        result=self.SM.next(message)
        self.failUnless( self.SM.state == E3 )
        self.failUnless( self.SM.emit()[0] == R1 )
        message.valid=None
        result=self.SM.next(message)
        self.failUnless( self.SM.state == E3 )
        self.failUnless(self.SM.OutQueue.queue.empty()==1)


    def testE3getsESP(self):
        self.SM.setstate(E3)
        message=ESPM
        message.valid=1
        result=self.SM.next(message)
        self.failUnless( self.SM.state == E3 )
        self.failUnless(self.SM.OutQueue.queue.empty()==1)
        message.valid=None
        result=self.SM.next(message)
        self.failUnless( self.SM.state == E3 )
        self.failUnless(self.SM.OutQueue.queue.empty()==1)

    def testE3getsR2(self):
        self.SM.setstate(E3)
        message=R2
        message.valid=1
        result=self.SM.next(message)
        self.failUnless( self.SM.state == E3 )
        self.failUnless(self.SM.OutQueue.queue.empty()==1)
        # incomplete: drop
        self.SM.setstate(E3)
        message.valid=None
        result=self.SM.next(message)
        self.failUnless( self.SM.state == E3 )
        self.failUnless(self.SM.OutQueue.queue.empty()==1)


        
suite = unittest.makeSuite(HIPTests,'test')

if __name__ == '__main__':
    unittest.main()

