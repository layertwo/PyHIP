from __future__ import generators

##try:
##    from psyco.classes import *
##except ImportError:
##    pass

import Queue
import traceback
import weakref
from types import *
import struct
import string
from array import array

LARGE=pow(2,31)-1

from binascii import unhexlify, hexlify
from time import time

import HI
from HIPutils import *
import HIPOptMessage
import HIPCookie
import ESP
from Crypto.Util.number import bytes_to_long, long_to_bytes

class Output:
    queue=Queue.Queue()
    #def __init__(self):
    #    self.queue=[]
    def send(self, message, machine):
        Output.queue.put((message, machine))
    def emit(self):
        return Output.queue.get_nowait()


OutQueue=Output()



class _StateMachine:
    canpiggyback = 1
    def __init__(self, state, HI):
        self.setstate( state )
        self.OutQueue = OutQueue
        self.__HIPmagic = 0x10
        self.Cookie = HIPCookie.HIPCookie()
        self.Cookie.K = 6
        self.HI = HI
        self.piggyback = 0
        self.piggybackProtocol = NO_PROTO
        #self.controls = HIPC_PIGGY | HIPC_ANON
        #self.controls = HIPC_PIGGY
        #self.controls = HIPC_ANON
        self.controls = 0
        self.callbacks = {}
        self.HIPXfrmList = [#HIPOptMessage.ENCR_3DES,
                            HIPOptMessage.ENCR_Blowfish,
                            HIPOptMessage.ENCR_AES_128,
                            HIPOptMessage.ENCR_NULL
                            ]
        self.ESPXfrmList = [HIPOptMessage.ESP_AES_CBC_HMAC_SHA1,
                            #HIPOptMessage.ESP_3DES_CBC_HMAC_SHA1,
                            #HIPOptMessage.ESP_3DES_CBC_HMAC_MD5,
                            HIPOptMessage.ESP_BLOWFISH_CBC_HMAC_SHA1,]

    def setFQDN(self, FQDN):
        self.FQDNlength       = len(FQDN)
        self.FQDN             = FQDN
        # calculate padding to build format string
        (self.FQDNpaddedlength, pad) = divmod(len(FQDN), 4)
        if pad != 0:
            self.FQDNpaddedlength += 1
        self.FQDNpaddedlength     *= 4
        self.FQDNformatstring = '!H%ds' % self.FQDNpaddedlength
        self.FQDNpacked = struct.pack(self.FQDNformatstring,
                                        self.FQDNlength, self.FQDN)

    def input(self, packet, h=None, rest=None):
        if not h:
            (h, rest) = (HIPOptMessage.HIPHeader(string=packet),
                         packet[HIPOptMessage.HIPHeader.size:])
        self.piggyback = h.control & HIPC_PIGGY and self.canpiggyback
        try:
            if self.remoteHIT == HI.zeroHIT:
                raise AttributeError
        except AttributeError:
            self.remoteHIT = h.sourceHIT
        # shortcut.  Is this warranted?
        if h.type == HIP_PAYLOAD:
            return
        if hasattr(self, 'trace'):
            print self.FQDN, 'Received:', HIP_Packets[h.type]
        n = 0
        b = 0
        l=[]
        while rest:
            n += 1
            (t, v, rest) = HIPOptMessage.HIPRec().unpack(rest)
            l.append(v)
        if hasattr(self, 'trace'):
            print self.FQDN, 'Parsed:', HIP_Packets[h.type]
        ver = 1
        if (not h.type in [HIP_BOS, HIP_I1, HIP_PAYLOAD, HIP_I2]):
            sigrec = [x for x in l if x.name[:3] == 'SIG'][0]
            try:
                ver = HIPOptMessage.verifypacket(
                    packet,
                    HI.HI.HITable[h.sourceHIT],
                    sigrec,
                    h)
            except KeyError:
                ver = 1
            if not ver:
                print 'Verify Failed', ver, hexlify(packet) #, repr(HI.HI.HITable[h.sourceHIT])
            else:
                if hasattr(self, 'trace'):
                    print self.FQDN, 'Verified:', HIP_Packets[h.type]
        m = HIPOptMessage.Message.dispatchlist[h.type]
        m.input(self, h, l)
        m.valid = ver
        if h.type in [HIP_BOS, HIP_I2]:
            sigrec = [x for x in l if x.name[:3] == 'SIG'][0]
            try:
                ver = HIPOptMessage.verifypacket(
                    packet,
                    HI.HI.HITable[h.sourceHIT],
                    sigrec,
                    h)
            except KeyError:
                ver = 1
            if not ver:
                print 'BOS Verify Failed', ver, hexlify(packet) #, repr(HI.HITable[h.sourceHIT])
            else:
                if hasattr(self, 'trace'):
                    print self.FQDN, 'Verified:', HIP_Packets[h.type]
        print 'Valid?', m.valid
        if not m.valid:
            print "assuming valid anyway!!!"
            m.valid = 1
        next = self.next(m)
        try:
            self.callbacks[m](self)
        except KeyError:
            pass
        except:
            traceback.print_exc()
        if hasattr(self, 'trace'): print self.FQDN, 'Transition:', next
        self.setstate(next)
        try:
            self.callbacks[self.state](self)
        except KeyError:
            pass
        except:
            traceback.print_exc()
        return next
        
    def packFQDN(self):
        return self.FQDNpacked

    def setstate(self, state):
        self.state = state
        
    def send(self, message):
        if hasattr(self, 'trace'): print self.FQDN, repr(self.state), 'Sending:', message
        message.valid=1
        self.OutQueue.send(message, self)

    def emit(self):
        return self.OutQueue.emit()

    def next(self, message):
        self.state = self.state.next(self, message)
        return self.state

    def __getattr__(self, name):
        return getattr(self.state, name)

    def drawkey(self, keylen):
        return ''.join(map(apply,
                           [self.keygenerator.next]
                           *keylen))

    def drawHIPkeys(self, keylen, initiator):
        self.remotehipkey = self.drawkey(keylen)
        self.hipkey = self.drawkey(keylen)
        print "drawHIPkeys:", hexlify(self.remotehipkey), hexlify(self.hipkey)
        if initiator:
            # swap the keys
            (self.hipkey,
             self.remotekey) = (self.remotehipkey,
                                self.hipkey)

    def drawESPkeys(self, keylen, authkeylen, initiator):
        self.remoteESPkey = self.drawkey(keylen)
        self.remoteESPauthkey = self.drawkey(authkeylen)
        self.ESPkey = self.drawkey(keylen)
        self.ESPauthkey = self.drawkey(authkeylen)
        if not initiator:
            # swap the keys
            (self.remoteESPkey,
             self.ESPkey) = (self.ESPkey,
                             self.remoteESPkey)
            (self.remoteESPauthkey,
             self.ESPauthkey) = (self.ESPauthkey,
                                 self.remoteESPauthkey)

    def makeLocalSPI(self, blocksize):
        self.localESP = ESP.SPI(SPI=self.localSPI,
                                   key=self.ESPkey,
                                   iv=RandomPool.get_bytes(blocksize),
                                   authkey=self.ESPauthkey,
                                   algname=self.ESPalg)
        self.localESP.machine = weakref.proxy(self)

    def makeRemoteSPI(self, blocksize):
        self.remoteESP = ESP.SPI(SPI=self.remoteSPI,
                                    key=self.remoteESPkey,
                                    iv=RandomPool.get_bytes(blocksize),
                                    authkey=self.remoteESPauthkey,
                                    algname=self.ESPalg)
        self.remoteESP.machine = weakref.proxy(self)


class State:
  def __init__(self, name): 
    self.name = name

  def __str__(self): return self.name 

  def __cmp__(self, other):
    return cmp(self.name, other.name)

  # Necessary when __cmp__ or __eq__ is defined
  # in order to make this class usable as a
  # dictionary key:
  def __hash__(self): 
    return hash(self.name)



#    def __str__(self): return self.__name__ 


class E0State(State):
    '''
    8.5.2. HLP State Processes

    +---------+
    |    E0   |  Start state
    +---------+

    Datagram to send, send I1 and go to E1
    Receive I1, send R1 and stay at E0
    Receive I2, process
         if successful, send R2 and go to E3
         if fail, stay at E0
    Receive ESP for unknown SA, send R1 and stay at E0
    Receive ANYOTHER, drop and stay at E0
    '''
    def __init__(self):
        State.__init__(self, 'E0 Start state')
    def next(self, machine, message):
        if message == HIPOptMessage.I1:
            machine.Cookie.hits = ''.join([machine.remoteHIT,
                                           machine.localHIT])
            machine.Cookie.new()
            machine.send(HIPOptMessage.R1)
            return E0
        if message == HIPOptMessage.I2:
            if message.valid:
                machine.send(HIPOptMessage.R2)
                return E3
            else:
                return E0
        if message == HIPOptMessage.ESPM:
            machine.Cookie.hits = ''.join([machine.remoteHIT,
                                           machine.localHIT])
            machine.Cookie.new()
            machine.send(HIPOptMessage.R1)
            return E0
        # Evil hack, make opportunistic work (this is WRONG)
        if message == HIPOptMessage.R1:
            if message.valid:
                machine.send(HIPOptMessage.I2)
                return E2
            else:
                return EFail
        # drop
        return E0

class E1State(State):
    '''
    8.5.2. HLP State Processes

    +---------+
    |    E1   |  Initiating HLP
    +---------+

    Receive R1, process
        if successful, send I2 and go to E2
        if fail, go to E-FAILED
    Receive ANYOTHER, drop and stay at E1
    Timeout, up timeout counter
        If counter is less than N, send I1 and stay at E1
        If counter is greater than N, Go to E-FAILED
    '''
    def __init__(self):
        State.__init__(self, 'E1 Initiating HLP')
    def next(self, machine, message):
        if message == HIPOptMessage.R1:
            if message.valid:
                machine.send(HIPOptMessage.I2)
                return E2
            else:
                return EFail
        # drop
        return E1

class E2State(State):
    '''
    8.5.2. HLP State Processes

    +---------+
    |    E2   | Waiting to finish HLP
    +---------+

    Receive R2, process
        if successful, go to E3
        if fail, go to E-FAILED
    Receive ANYOTHER, drop and stay at E2
    '''
    def __init__(self):
        State.__init__(self, 'E2 Waiting to finish HLP')
    def next(self, machine, message):
        if message == HIPOptMessage.R2:
            if message.valid:
                return E3
            else:
                return EFail
        # drop
        return E2


class E3State(State):
    '''
    8.5.2. HLP State Processes

    +---------+
    |    E3   | HIP SA established
    +---------+

    Receive NAS, process
        if successful, send NAS and stay at E3
        if failed, stay at E3
    Receive REA, process and stay at E3
    Receive I1, send R1 and stay at E3
    Receive I2, process with Birthday check
        if successful, send R2, drop old SA and cycle at E3
        if fail, stay at E3
    Receive R1, process with Birthday check
        if successful, send I2 with last datagram, drop old SA
                and go to E2
        if fail, stay at E3
    Receive ESP for SA, process and stay at E3
    Receive R2, drop and stay at E3
    '''
    def __init__(self):
        State.__init__(self, 'E3 HIP SA established')
    def next(self, machine, message):
        if message in (HIPOptMessage.REA, HIPOptMessage.ESPM):
            # process
            return E3
        elif message == HIPOptMessage.I1:
            if message.valid:
                machine.Cookie.hits = ''.join([machine.remoteHIT,
                                               machine.localHIT])
                machine.Cookie.new()
                machine.send(HIPOptMessage.R1)
                return E3
            else:
                return E3            
        elif message == HIPOptMessage.R2:
            # drop flag
            return E3
        elif message == HIPOptMessage.NES:
            if message.valid:
                # do this elsewhere (see NESMessage.input)!
                #machine.send(NES)
                return E3
            else:
                return E3            
        elif message == HIPOptMessage.I2:
            if message.valid:
                # birthday
                # drop SA
                machine.send(HIPOptMessage.R2)
                return E3
            else:
                return E3            
        elif message == HIPOptMessage.R1:
            if message.valid:
                # birthday
                machine.send(HIPOptMessage.I2)
                # piggyback
                # drop SA
                return E2
            else:
                return E3            
        return E3


class EFailState(State):
    '''
    Go here if we fail to negotiate
    '''
    def __init__(self):
        State.__init__(self, 'EFail Failed to negotiate')
    pass


E0=E0State()
E1=E1State()
E2=E2State()
E3=E3State()
EFail=EFailState()



class StateMachine(_StateMachine):
    birthday = long(time())
    def LSIgen(b):
        i = b
        while 1:
            #print 'lsigen:', hex(i)
            #yield 0x0a000000 ^ i & 0x00ffffff
            yield 0x01000000 ^ i & 0x00ffffff
            i += 1

    def SPIgen(b):
        i=b
        while 1:
            r = i & 0xffffffff
            # don't output IANA reserved range
            if r > 255:
                #print '*****--> spigen:', hex(i)
                yield r
            i += 1

    def GroupIDgen():
        i=0
        while 1:
            #print 'spigen:', hex(i)
            yield (i % 0x7f) + 129
            i += 1

    SPIgen=SPIgen(struct.unpack('!L', RandomPool.get_bytes(4))[0])
    LSIgen=LSIgen(struct.unpack('!L', RandomPool.get_bytes(4))[0])
    GroupIDgen=GroupIDgen()

    def __init__(self, state=E0, HI=None):
        _StateMachine.__init__(self, state, HI)

#    def __del__(self):
#        print 'Deleting:', repr(self)

# add this to the message module namespace as well
HIPOptMessage.StateMachine = StateMachine
