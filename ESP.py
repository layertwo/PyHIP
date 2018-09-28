#from psyco.classes import *

import struct
from types import LongType
#from M2Crypto import EVP
from Crypto.Cipher import AES, DES3, Blowfish
from Crypto.Util.number import bytes_to_long, long_to_bytes

import hmac
import sha
import md5
from binascii import hexlify, unhexlify
import weakref

import HIPutils
import IPAddress

import threading
import libnet
import os
import socket
import queue


enc = 1
dec = 0
padblock = ''.join(map(chr, list(range(1, 200))))


def ESPparams(payload):
    return struct.unpack('!LL', payload[:8])


class ESPError(Exception):
    pass


class ESPHeld(ESPError):
    pass


class ESPUnpackError(ESPError):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class ESPTransform(HIPutils.Transform):
    pass

# (alg, keyoct, blocksize, authalg, authoct, authlen) tuples


ESPAlgTable = {'AES': (AES, 16, 16, None, 0, 12),
               '3DES': (DES3, 24, 8, None, 0, 12),
               'Blowfish': (Blowfish, 16, 8, None, 0, 12),
               '3DES-HMAC-SHA1-96': (DES3, 24, 8, sha, 20, 12),
               '3DES-HMAC-MD5': (DES3, 24, 8, md5, 16, 16),
               'Blowfish-HMAC-SHA1-96': (Blowfish, 16, 8, sha, 20, 12),
               'AES-HMAC-SHA1-96': (AES, 16, 16, sha, 20, 12)}

# The following Suite-IDs are defined ([IKEv2],[JFK]):

# Suite-ID                          Value

# RESERVED                          0
# ESP-AES-CBC with HMAC-SHA1        1
# ESP-3DES-CBC with HMAC-SHA1       2
# ESP-3DES-CBC with HMAC-MD5        3
# ESP-BLOWFISH-CBC with HMAC-SHA1   4
# ESP-NULL with HMAC-SHA1           5
# ESP-NULL with HMAC-MD5            6


class InputEngine(HIPutils.IPhandler):
    Engines = {}

    def setEngine(cls, IP, handler):
        cls.Engines.update(IP.allDict(handler))

    setEngine = classmethod(setEngine)

    def findHandler(cls, IP):
        return cls.Engines[IP]

    def handleTun(cls, Socket):
        try:
            pkt = os.read(Socket, 70000)
        except OSError:
            return
        #c = time.time()
        try:
            # print "Tunnel gave:", hexlify(pkt)
            saddr, daddr, protocol, payload = self.ipinput(pkt)
            if payload is None:
                return
            # print "tunnel:", repr(Host.IPtable), repr(daddr), repr(daddr)
            handler = SPI.findHandler(payload)
            # print "Handler is:", handler
            handler.lastused = time.time()
            if handler.piggy:
                handler.piggy.send(HIPMessage.PAYLOAD,
                                   piggy=handler.piggy.remoteESP.pack(
                                       protocol, payload),
                                   piggybackProtocol=ESP_PROTO_NO)
            else:
                Socket.sendto(
                    (handler.remoteESP.pack(protocol, payload),
                     handler.remoteIP))
        except (KeyError, ESP.ESPHeld):
            # print 'Error'
            pass
        # print '!!!!!', time.time() - c, 'for ESP send'

    handleTun = classmethod(handleTun)

    def deliverESP(cls, Socket, OutQueue):
        try:
            pkt = os.read(Socket, 70000)
        except OSError:
            return
        try:
            #c = time.time()
            try:
                handler = SPI.findHandler(payload)
                R, L = handler.libnetLSIs
            except KeyError:
                # print 'KeyError finding ESP handler'
                # print hexlify(payload)
                return
            except AttributeError:
                # print '! no cached names'
                R = libnet.name_resolve(
                    socket.inet_ntoa(
                        struct.pack(
                            '!L',
                            handler.machine.remoteLSI)),
                    0)
                L = libnet.name_resolve(
                    socket.inet_ntoa(
                        struct.pack(
                            '!L',
                            handler.machine.localLSI)),
                    0)
                handler.libnetLSIs = (R, L)
            # print repr(map(curryl(getattr, handler), ['SPI', 'alg', 'key',
            # 'authkey', 'iv']))
            (rSPI, rSN, rdata, nextheader) = handler.unpack(payload)
            # print "------>", time.time() - c, 'for ESP find and unpack'
            # print 'ESP:', rSPI, rSN, hexlify(rdata), nextheader
            if nextheader == 60:
                # print 'unpacking IPv6 packet'
                # IPv6, has to be
                # remove the padding destopt we put in
                if rdata[2] == '\x01':
                    nextheader = ord(rdata[0])
                    optlen = (ord(rdata[1]) + 1) * 8
                    rdata = rdata[optlen:]
                header = struct.pack(IP6Header,
                                     0x60000000,
                                     len(rdata),
                                     nextheader,
                                     63,
                                     handler.remoteIPv6addr,
                                     handler.localIPv6addr)
                pkt2 = ''.join([header, rdata])
            else:
                # IPv4
                #c = time.time()
                p = libnet.packet()
                p.payload = rdata
                p.build_ip(len(p),
                           0,
                           1,
                           0,
                           255,
                           nextheader,
                           R,
                           L)
                p.do_checksum(libnet.IPPROTO_IP, libnet.IP_H)
                # print "delivering", hexlify(p.getvalue())
                pkt2 = repr(p)
                if nextheader in [6, 17]:  # need to fix the checksum
                    pkt2 = HIPUtils.fixULPChecksum(pkt2)
                # print "--->", time.time() - c, 'for ESP deliver construction'
            # print "delivering", hexlify(pkt2)
            OutQueue.put(pkt2)
        except ESP.ESPUnpackError as x:
            print('Unpack error:', x)
        except KeyError:
            # traceback.print_exc()
            # print 'nope. Not our packet...'
            pass

    def __init__(self, localIP=None, OutQueue=None):
        self.OutQueue = OutQueue
        self.Socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_ESP)
        self.Socket.bind((localIP, 50))
        self.Socket.setblocking(1)
        self.setEngine(IPAddress.IP(localIP), self)

    def start():
        thread = threading.Thread(target=self.deliverESP,
                                  args=(self.Socket, self.OutQueue))
        thread.setDaemon(1)
        thread.start()


class SPI:
    # do this so when SPIs go away we have a
    # reference that we once knew about them
    SPItable = weakref.WeakValueDictionary({})

    def findHandler(cls, payload):
        try:
            rv = cls.SPItable[payload[:4]]
        except BaseException:
            # print "KeyError finding SPI?!", hexlify(payload[:4])
            # for i in cls.SPItable.keys():
            #    print hexlify(i), repr(cls.SPItable[i])
            raise
        return rv

    findHandler = classmethod(findHandler)

    "Implementation of RFC 2406 and friends"

    def __init__(self, SPI,
                 algname='3DES-HMAC-SHA1-96',
                 key='',
                 authkey=None,
                 iv=None,
                 piggy=None,
                 localIP=None,
                 IPv6=None):
        self.IPv6 = IPv6
        self.piggy = piggy
        self.localIP = localIP
        self.SN = 0
        self.SPI = SPI
        self.SPItable[long_to_bytes(SPI)] = self
        self.key = key
        self.authkey = authkey
        self.packcount = 0
        self.unpackcount = 0
        self.SNCallbacks = {}
        (self.alg,
         self.keyoct,
         self.blocksize,
         self.authalg,
         self.authoct,
         self.authlen) = ESPAlgTable[algname]
        self.pack = self.packPyCrypt
        self.unpack = self.unpackPyCrypt
        if iv is None:
            iv = RandomPool.get_bytes(self.blocksize)
        # print 'SPI:', hex(self.SPI)
        # print 'Algorithm:', algname
        # print 'Key:', hexlify(self.key), len(self.key), self.keyoct
        # if self.authkey: print 'Authkey:', hexlify(self.authkey),
        # len(self.authkey), self.authoct
        if len(key) != self.keyoct:
            raise ValueError
        if self.authkey and len(authkey) != self.authoct:
            raise ValueError
# if self.alg is DES3:
##            k1, k2, k3 = self.key[:8], self.key[8:16], self.key[16:]
##            self.key = ''.join([k2, k1, k3])
        self.cipher = self.alg.new(self.key,
                                   self.alg.MODE_CBC,
                                   iv)

    def __str__(self): return self.SPI

    def __cmp__(self, other):
        return cmp(self.SPI, other.SPI)

    # Necessary when __cmp__ or __eq__ is defined
    # in order to make this class usable as a
    # dictionary key:
    def __hash__(self):
        return hash(self.SPI)

    def hold(self, holdlist):
        # we pass this in, because it isn't going to be
        # this instance that is unheld.  Callback has a
        # reference to it
        self.holdlist = holdlist
        self.pack = self.packHeld

    def unhold(self, holdlist):
        #heldData = map(lambda x: apply(self.pack, x), holdlist)
        heldData = [self.pack(*x) for x in holdlist]
        return heldData

    def packHeld(self, nextHeader, data):
        self.holdlist.append((nextHeader, data))
        raise ESPHeld

    def packPyCrypt(self, nextHeader, data):
        # pre-increment SN (rfc2406)
        self.SN += 1
        try:
            x = self.SNCallbacks[self.SN]
            x()
            del self.SNCallbacks[self.SN]
        except KeyError:
            pass
# try:
##            x = self.SNCallbacks.smallest()
# while x <= self.SN:
# self.SNCallbacks[x]()
##                del self.SNCallbacks[x]
##                x = self.SNCallbacks.smallest()
# except IndexError:
# pass
#        cipher=EVP.Cipher(self.alg, self.key, self.iv, enc)
        padlen = self.blocksize - ((len(data) + 2) % self.blocksize)
        # print "pack: padlength:", padlen, len(data), padlen + len(data), (padlen + len(data)) % self.blocksize
        #padfmt = '!%dB' % padlen
        plaintext = ''.join([data,
                             padblock[:padlen],
                             chr(padlen),
                             chr(nextHeader)])
        # print 'pack:', hexlify(plaintext), hex(self.SPI), hexlify(self.key), hexlify(self.authkey)
        # print 'pack: Encoded:', len(plaintext), len(plaintext) %
        # self.blocksize
        ciphertext = ''.join([struct.pack('!LL', self.SPI, self.SN),
                              self.cipher.IV,
                              self.cipher.encrypt(plaintext)])
        self.cipher.IV = ciphertext[-self.blocksize:]
        # authorisation not optional any more
        # if self.authkey:
        ciphertext += hmac.new(self.authkey,
                               ciphertext,
                               self.authalg).digest()[:self.authlen]
        # print "pack: made (auth):", len(ciphertext), len(ciphertext) % self.blocksize
        # print "pack:", hexlify(ciphertext[:8])
        # print "pack:", hexlify(ciphertext[8:-self.authlen])
        # print "pack:", hexlify(ciphertext[-self.authlen:])
        self.packcount += 1
        return ciphertext

    def unpackPyCrypt(self, payload):
        (SPI, SN) = ESPparams(payload)
        # print 'unpack: payload of:', len(payload), hexlify(payload)
        try:
            x = self.SNCallbacks[SN]
            x()
            del self.SNCallbacks[SN]
        except KeyError:
            pass
# try:
##            x = self.SNCallbacks.smallest()
# while x <= SN:
# self.SNCallbacks[x]()
##                del self.SNCallbacks[x]
##                x = self.SNCallbacks.smallest()
# except IndexError:
# pass
        # if self.authkey:
        authlen = self.authlen
        macdata = payload[-authlen:]
        ciphertext = payload[self.blocksize + 8:-authlen]
        # print 'unpack', hex(self.SPI), hexlify(self.key), hexlify(self.authkey)
        # print 'hmac of', hexlify(ciphertext)
        testdata = hmac.new(self.authkey,
                            payload[:-authlen],
                            self.authalg).digest()[:authlen]
        # print 'testing', hexlify(testdata), hexlify(macdata)
        if testdata != macdata:
            #    print 'Authentification failed'
            raise ESPUnpackError('Authentification Failed: %s != %s'
                                 % (testdata,
                                    macdata))
        # else:
        #    ciphertext = payload[self.blocksize+8:]
        #    macdata=''
        # print 'unpack: ciphertext of:', len(ciphertext),
        # len(ciphertext)%self.blocksize
        self.cipher.IV = payload[8:self.blocksize + 8]
        plaintext = self.cipher.decrypt(ciphertext)
        # print 'unpack:', hexlify(plaintext)
        # print 'unpack: Plain was:', len(plaintext),  len(plaintext) %
        # self.blocksize
        padlen, nexthead = ord(plaintext[-2]), ord(plaintext[-1])
        # print "unpack: padlength", padlen, len(pad), len(data), hexlify(data)
        if padblock[:padlen] != plaintext[(-2 - padlen):(-2)]:
            # print 'Apparently incorrect padding'
            raise ESPUnpackError(' '.join(['Padding Incorrect: ',
                                           str(padlen),
                                           str(nexthead),
                                           hexlify(pad),
                                           hexlify(padblock[:padlen]),
                                           hexlify(payload)]))
        self.unpackcount += 1
        return ((SPI, SN, plaintext[:(-2 - padlen)], nexthead))

# try:
##    import psyco
# psyco.bind(struct)
# psyco.bind(hmac)
# psyco.bind(sha)
# psyco.bind(weakref)
# psyco.bind(SPI.packPyCrypt)
# psyco.bind(SPI.unpackPyCrypt)
# except ImportError:
# pass
