import profile
import pstats
from pprint import pformat
from HIPState import *
from HIPOptMessage import *
import DH
from HI import *
import ESP
from binascii import hexlify, unhexlify
import unittest

from testlib import ifdict


class ConversationTests(unittest.TestCase):

    def testConversation(self):
        hi1 = HI()
        hi2 = HI()

        hi1.genKey()
        hi2.genKey()

        HI.HITable[hi1.HIT127()] = hi1
        HI.HITable[hi2.HIT127()] = hi2

        sm1 = StateMachine(HI=hi1)
        sm2 = StateMachine(HI=hi2)

        def smsetup(sm):
            # this is Oakley group 5, actually.
            sm.DH = DH.construct((241031242692103258855207602219756607485695054850245994265416941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919,
                                  2))
            sm.DH.gen_key(RandomPool.get_bytes)
            sm.DH.groupid = 3
            sm.localHIT = sm.HI.HIT127()
            sm.trace = 1

        sm1.remoteHIT = unhexlify('00000000000000000000000000000000')
        sm2.remoteHIT = unhexlify('00000000000000000000000000000000')
        smsetup(sm1)
        smsetup(sm2)
        sm1.setstate(E0)
        sm2.setstate(E1)
        # sm1 needs to derive this.
        # sm1.remoteHIT=sm2.localHIT
        # use this if we have it - but we don't
        # sm2.remoteHIT=sm1.localHIT
        sm1.setFQDN('1.test.com')
        sm2.setFQDN('2.test.net')

        sm1.rekeying = 0
        sm2.rekeying = 0

        # send a BOS

        p1 = []
##        p2 = [(BOS, None)]
# p2 = [(I1, None)]

# while p1 or p2:
# while p2:
# p=p2.pop(0)[0]
# pkt2=p.pack(sm2)
# print "sm2", sm2.FQDN, 'sent', str(p), "state", str(sm2.state)
# print hexlify(pkt2)
# packetDump(pkt2)
# sm1.input(pkt2)
# try:
# p1=[sm1.emit()]
# except:
# p1=[]
# try:
# while 1:
# p1.append(sm1.emit())
# except:
# pass
# while p1:
# p=p1.pop(0)[0]
# pkt1=p.pack(sm1)
# print "sm1", sm1.FQDN, 'sent', str(p), "state", str(sm1.state)
# print hexlify(pkt1)
# packetDump(pkt1)
# sm2.input(pkt1)
# try:
# p2=[sm2.emit()]
# except:
##                p2 = []
# try:
# while 1:
# p2.append(sm2.emit())
# except:
# pass
# print "sm2", sm2.FQDN, "state", str(sm2.state)

##        self.failUnless( sm2.state == E1 )

        # Standard 4-packet exchange

        p2 = [(I1, None)]

        while p1 or p2:
            while p2:
                print(p2)
                p = p2.pop(0)[0]
                pkt2 = p.pack(sm2)
                print("sm2", sm2.FQDN, 'sent', str(p), "state", str(sm2.state))
                print(hexlify(pkt2))
                packetDump(pkt2)
                sm1.input(pkt2)
            try:
                p1 = [sm1.emit()]
            except BaseException:
                p1 = []
            try:
                while True:
                    p1.append(sm1.emit())
            except BaseException:
                pass
            while p1:
                p = p1.pop(0)[0]
                pkt1 = p.pack(sm1)
                print("sm1", sm1.FQDN, 'sent', str(p), "state", str(sm1.state))
                print(hexlify(pkt1))
                packetDump(pkt1)
                sm2.input(pkt1)
            try:
                p2 = [sm2.emit()]
            except BaseException:
                p2 = []
            try:
                while True:
                    p2.append(sm2.emit())
            except BaseException:
                pass
        print("sm2", sm2.FQDN, "state", str(sm2.state))
        print("sm1:", pformat(sm1.__dict__))
        print("sm2:", pformat(sm2.__dict__))

        self.assertTrue(sm2.state == E3)

# test REA

##        p2=[(REA, None)]
# sm2.localIPs = [(10, 1, 6, '', ('fe80::220:e0ff:fe67:a4bf', 0, 0, 2))]
##        sm2.interfaces = ifdict
##        sm2.Interface = 2
# sm2.newspi=1234
##        sm2.nextkeyind = 3
##        sm2.nextreaid = 4


# while p1 or p2:
# while p2:
# print p2
# p=p2.pop(0)[0]
# pkt2=p.pack(sm2)
# print "sm2", sm2.FQDN, 'sent', str(p), "state", str(sm2.state)
# print hexlify(pkt2)
# packetDump(pkt2)
# sm1.input(pkt2)
# try:
# p1=[sm1.emit()]
# except:
# p1=[]
# try:
# while 1:
# p1.append(sm1.emit())
# except:
# pass
# while p1:
# p=p1.pop(0)[0]
# pkt1=p.pack(sm1)
# print "sm1", sm1.FQDN, 'sent', str(p), "state", str(sm1.state)
# print hexlify(pkt1)
# packetDump(pkt1)
# sm2.input(pkt1)
# try:
# p2=[sm2.emit()]
# except:
##                p2 = []
# try:
# while 1:
# p2.append(sm2.emit())
# except:
# pass
# print "sm2", sm2.FQDN, "state", str(sm2.state)

##        self.failUnless( sm1.remoteESP.SNCallbacks )

        # test NES

        p2 = [(NES, None)]
        sm2.rekeying = 1
        savedkey = sm2.ESPkey
        smsetup(sm1)
        smsetup(sm2)

        while p1 or p2:
            while p2:
                print(p2)
                p = p2.pop(0)[0]
                pkt2 = p.pack(sm2)
                print("sm2", sm2.FQDN, 'sent', str(p), "state", str(sm2.state))
                print(hexlify(pkt2))
                packetDump(pkt2)
                sm1.input(pkt2)
            try:
                p1 = [sm1.emit()]
            except BaseException:
                p1 = []
            try:
                while True:
                    p1.append(sm1.emit())
            except BaseException:
                pass
            while p1:
                p = p1.pop(0)[0]
                pkt1 = p.pack(sm1)
                print("sm1", sm1.FQDN, 'sent', str(p), "state", str(sm1.state))
                print(hexlify(pkt1))
                packetDump(pkt1)
                sm2.input(pkt1)
            try:
                p2 = [sm2.emit()]
            except BaseException:
                p2 = []
            try:
                while True:
                    p2.append(sm2.emit())
            except BaseException:
                pass
        print("sm2", sm2.FQDN, "state", str(sm2.state))

        self.assertTrue(sm2.rekeying == 0)
        self.assertTrue(sm2.ESPkey != savedkey)


suite = unittest.makeSuite(ConversationTests, 'test')

if __name__ == '__main__':
    unittest.main()

#profile.run('[main() for i in range(300)]','blargh.profile')
# profile.run('[main()]','blargh.profile')

# stats=pstats.Stats('blargh.profile')
# stats.sort_stats('cumulative')
# stats.sort_stats('calls')
# stats.print_stats()
