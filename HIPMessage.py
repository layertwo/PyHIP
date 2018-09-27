import weakref
from types import *
from struct import *
import string
from array import array

LARGE=pow(2,31)-1
from M2Crypto import DH, EVP, Rand, DSA
# Danger!  Accessing private C code of extension modules is bad!
# but there is no (working) exported API to some of the DSA accessors
import m2
#from aes.aes import aes

from binascii import unhexlify, hexlify
from time import time

from HI import *
from HIPutils import *
import ESP


HIP_HEADER_FMT = '!BBBB16sH'
HIP_HEADER_SFMT = '''
                  !
                  nh:B
                  length:B
                  type:B
                  magic:B
                  hit:16s
                  rcount:H
                  '''
HIP_HEADER_LEN = calcsize(HIP_HEADER_FMT)

HIP_RR_A               =  1
HIP_RR_SIG             = 24
HIP_RR_KEY             = 25
HIP_RR_AAAA            = 28
HIP_RR_OPT             = 41

HIP_RRs = {
    1: 'A',
    24: 'SIG',
    25: 'KEY',
    28: 'AAAA',
    41: 'OPT',
    255: 'PAD1',
    254: 'PAD'}

# I know, the last two aren't for real.

HIP_OPT_IDENT_HIT           =  1
HIP_OPT_IDENT_HIP_CNTLS     =  2
HIP_OPT_IDENT_HIP_COOKIE    =  3
HIP_OPT_IDENT_HIP_TRANSFORM =  4
HIP_OPT_IDENT_ESP_TRANSFORM =  5
HIP_OPT_IDENT_ENCRYPTED     =  6
HIP_OPT_IDENT_BIRTHDAY      =  7
HIP_OPT_IDENT_LSI           =  8
HIP_OPT_IDENT_SPI           =  9
HIP_OPT_IDENT_ID            = 10
HIP_OPT_IDENT_ESP_SN        = 11

HIP_RROpts = { 0: '',
               1: 'HIT',
               2: 'HIP_CNTLS',
               3: 'HIP_COOKIE',
               4: 'HIP_TRANSFORM',
               5: 'ESP_TRANSFORM',
               6: 'ENCRYPTED',
               7: 'BIRTHDAY',
               8: 'LSI',
               9: 'SPI',
              10: 'ID',
              11: 'ESP_SN'}


HIP_REC_A             = (HIP_RR_A, 0)
HIP_REC_SIG           = (HIP_RR_SIG, 0)
HIP_REC_KEY           = (HIP_RR_KEY, 0)
HIP_REC_AAAA          = (HIP_RR_AAAA, 0)
HIP_REC_HIT           = (HIP_RR_OPT, HIP_OPT_IDENT_HIT)
HIP_REC_HIP_CNTLS     = (HIP_RR_OPT, HIP_OPT_IDENT_HIP_CNTLS)
HIP_REC_HIP_COOKIE    = (HIP_RR_OPT, HIP_OPT_IDENT_HIP_COOKIE)
HIP_REC_HIP_TRANSFORM = (HIP_RR_OPT, HIP_OPT_IDENT_HIP_TRANSFORM)
HIP_REC_ESP_TRANSFORM = (HIP_RR_OPT, HIP_OPT_IDENT_ESP_TRANSFORM)
HIP_REC_ENCRYPTED     = (HIP_RR_OPT, HIP_OPT_IDENT_ENCRYPTED)
HIP_REC_BIRTHDAY      = (HIP_RR_OPT, HIP_OPT_IDENT_BIRTHDAY)
HIP_REC_LSI           = (HIP_RR_OPT, HIP_OPT_IDENT_LSI)
HIP_REC_SPI           = (HIP_RR_OPT, HIP_OPT_IDENT_SPI)
HIP_REC_ID            = (HIP_RR_OPT, HIP_OPT_IDENT_ID)
HIP_REC_ESP_SN        = (HIP_RR_OPT, HIP_OPT_IDENT_ESP_SN)

HIP_RECs = {HIP_REC_A: 'A',
            HIP_REC_SIG: 'SIG',
            HIP_REC_KEY: 'KEY',
            HIP_REC_AAAA: 'AAAA',
            HIP_REC_HIT: 'HIT',
            HIP_REC_HIP_CNTLS: 'HIP_CNTLS',
            HIP_REC_HIP_COOKIE: 'HIP_COOKIE',
            HIP_REC_HIP_TRANSFORM: 'HIP_TRANSFORM',
            HIP_REC_ESP_TRANSFORM: 'ESP_TRANSFORM',
            HIP_REC_ENCRYPTED: 'ENCRYPTED',
            HIP_REC_BIRTHDAY: 'BIRTHDAY',
            HIP_REC_LSI: 'LSI',
            HIP_REC_SPI: 'SPI',
            HIP_REC_ID: 'ID',
            HIP_REC_ESP_SN: 'ESP_SN'}

XFRM_HIP_ENC       =  1
XFRM_ESP_ENC       =  2
XFRM_ESP_AUTH      =  3

# IANA values from RFC2407 + friends


XFRM_SA_LIFE_TYPE  = 1
XFRM_SA_DURATION   = 2
XFRM_SA_GROUP      = 3
XFRM_SA_ENCAP_MODE = 4
XFRM_SA_AUTH_ALG   = 5
XFRM_SA_KEY_LENGTH = 6
XFRM_SA_KEY_ROUNDS = 7
XFRM_ESP_MODE_TRANSPORT = 2

XFRM_HIP_DES_CBC               =  1
XFRM_HIP_IDEA_CBC              =  2
XFRM_HIP_Blowfish_CBC          =  3
XFRM_HIP_RC5_R16_B64_CBC       =  4
XFRM_HIP_3DES_CBC              =  5
XFRM_HIP_CAST_CBC              =  6
XFRM_HIP_AES_CBC               =  7

XFRM_ESP_DES_IV64          =  1
XFRM_ESP_DES               =  2
XFRM_ESP_3DES              =  3
XFRM_ESP_RC5               =  4
XFRM_ESP_IDEA              =  5
XFRM_ESP_CAST              =  6
XFRM_ESP_BLOWFISH          =  7
XFRM_ESP_3IDEA             =  8
XFRM_ESP_DES_IV32          =  9
XFRM_ESP_RC4               =  10
XFRM_ESP_NULL              =  11
XFRM_ESP_AES_128           =  12

XFRM_AUTH_NONE                  =  0
XFRM_AUTH_MD5                   =  2
XFRM_AUTH_SHA                   =  3
XFRM_AUTH_DES                   =  4


def packTLV(Tag, Value):
    Code, Ident = Tag
    try:
        length=len(Value)
    except TypeError:
        Value=pack('B', Value)
        length=1
    return (pack('!BBH', Code, Ident, length)
            + Value + '\x00'*((8-length&7)&7))

def unpackTLV(payload):
    if payload[0] == '\xff':
        return (255, 0, '', payload[1:])
    (code, ident, length) = unpack('!BBH', payload[:4])
    paddedlength = length + ((8-length&7)&7)
    return ((code, ident),
            payload[4:4+length],
            payload[4+paddedlength:])

def packHeader(NextHeader, Length, Type, RCount, localHIT, FQDN):
    return pack(HIP_HEADER_FMT,
                NextHeader,
                (Length + 8 - ((Length&7)&7))>>3,
                Type,
                0x10,
                localHIT,
                RCount) + FQDN


def unpackHeader(payload, object=None):
    # wierd single element tuple constructor follows...
    (length,) = unpack('!H', payload[HIP_HEADER_LEN:HIP_HEADER_LEN+2])
    (paddedlength, pad) = divmod(length, 4)
    if pad != 0:
        paddedlength += 1
    paddedlength     *= 4
    result = sstruct.unpack(HIP_HEADER_SFMT, payload[:HIP_HEADER_LEN], object)
    if object is None:
        result['fqdn'] = payload[HIP_HEADER_LEN+2:HIP_HEADER_LEN+2+length]
    else:
        result.fqdn = payload[HIP_HEADER_LEN+2:HIP_HEADER_LEN+2+length]
    return (result, payload[HIP_HEADER_LEN+2+paddedlength:])

def signpacket(head, tail, hi):
    headlist = list(unpack(HIP_HEADER_FMT, head[:HIP_HEADER_LEN]))
    testsig = packTLV(HIP_REC_SIG, ''.join(['x'] * hi.siglen))
    headlist[1] = (len(head) + len(tail) + len(testsig) - HIP_HEADER_LEN)>>3
    headlist[5] += 1
    newhead = apply(pack,
                    (HIP_HEADER_FMT,)
                    + tuple(headlist)) + head[HIP_HEADER_LEN:]
    sdata = ''.join([newhead, tail, testsig])
    sig = packTLV(HIP_REC_SIG, hi.sign(sdata[:-hi.sigpadlen]))
    return ''.join([newhead, tail, sig])

def verifypacket(packet, hi):
    return hi.verify(packet[:-hi.sigpadlen],
                     packet[-hi.sigpadlen:-(hi.sigpadlen-hi.siglen)])

def packetDump(packet):
    (dict, rest) = unpackHeader(packet, Junkme())
    (nexthdr, paylen, type, magic, hit, rcount, fqdn) = [getattr(dict,x) for x in     ('nh', 'length', 'type', 'magic', 'hit', 'rcount', 'fqdn')]
    #print len(packet), hexlify(packet)
    print
    print hexlify(packet[:HIP_HEADER_LEN]), fqdn
    for i in range(0, len(rest), 32):
        print '%4d' % i, hexlify(rest[i:i+32])

    print
    print repr((nexthdr, paylen, HIP_Packets[type], magic, hit, rcount, len(rest)))
    n = 0
    b = 0
    l=[]
    while rest:
        n += 1
        (t, v, rest) = unpackTLV(rest)
        ops = [(HIP_REC_HIP_TRANSFORM, unpackXfrm),
               (HIP_REC_ESP_TRANSFORM, unpackXfrm),
               (HIP_REC_ENCRYPTED, hexlify),
               ]
        try:
            v2 = apply([x[1] for x in ops if x[0] == t][0], [v])
        except IndexError:
            v2 = hexlify(v)
        l.append((t, v2))
        b += len(v) + 4
    for (t, v) in l:
        print HIP_RECs[t], repr(v)
    print paylen, rcount, b, n

def packXfrm(type, list):
    def packXfrmEl(x, i, n):
        (t, a)=x
        if a <> 0:
            s=packTLVC(XFRM_SA_AUTH_ALG,a)
        else:
            s=''
        nxt = n
        plen = len(s) + 4
        s2 = ''.join([pack('!BxHBBxx', nxt, plen, i, t), s])
        return s2
    return reduce(operator.add, map(packXfrmEl,
                                    list,
                                    range(1,len(list)+1),
                                    [type] * (len(list)-1) + [0]))

def unpackXfrm(payload):
    pl=payload
    l=[]
    while pl:
        (nxt, plen, i, t) = unpack('!BxHBBxx', pl[:8])
        a = []
        rest = pl[8:plen+4]
        pl = pl[plen+4:]
        while rest:
            (code, val, rest) = unpackTLVC(rest)
            a.append((code, val))
        # this may look strange, but it's for symmetry
        # could argue this is just wrong
        if len(a):
            auth = unpack('!H',a[0][1])[0]
        else:
            auth = 0
        l.append((i, (t, auth)))
    return l
                
def packRRset(RRset):
    #pprint(RRset)
    tail = reduce(operator.add, [apply(packTLV, RR) for RR in RRset])
    return tail

def extractRRset(RRset, t):
    return [x[1] for x in RRset if x[1] == t]

def RRsetToAttrs(RRset, list, object):
    '''
    deep magic.  Takes an RRset, a list of (code, ident, attribute name)
    tuples and an object and assigns attributes of the object to lists of
    values from matching (code, ident, value) tuples in the RRset.
    The magic is how.
    '''
    object.__dict__.update(dict([(attr,
                                  [x[1] for x in RRset if x[0] == t])
                                 for (t, attr) in list]))
    return object


class Message:
  def __init__(self, action, code): 
      self.action = action
      self.code = code
  def __str__(self): return self.action
  def __cmp__(self, other):
      return cmp(self.action, other.action)
  # Necessary when __cmp__ or __eq__ is defined
  # in order to make this class usable as a
  # dictionary key:
  def __hash__(self): 
      return hash(self.action)


  def packDH(self, machine):
      # RFC2535: 0x0200 flags,
      #          0xff protocol (or IANA HIP value)
      #          0x02 algorithm DH (mandatory)
      # RFC2539: t=0x00
      RR = '\x02\x00\xff\x02\x00'
      # RFC2539: p g pub, each with length
      RR += packLV(BN2nbo(m2.dh_get_p(machine.DH.dh)))
      RR += packLV(BN2nbo(m2.dh_get_g(machine.DH.dh)))
      RR += packLV(BN2nbo(m2.dh_get_pub(machine.DH.dh)))
      return RR

  def unpackDH(self, machine, RR, hit1, hit2, mode):
      if RR[:5] <> '\x02\x00\xff\x02\x00':
          raise ValueError
      (p, rest) = unpackLV(RR[5:])
      (g, rest) = unpackLV(rest)
      (pub, rest) = unpackLV(rest)
      if mode:
          machine.DH = DH.set_params(nbo2BN(p), nbo2BN(g))
          machine.DH.gen_key()
      machine.dhkey = machine.DH.compute_key(nbo2BN(pub))
      return keymatgen(machine.dhkey, [hit1, hit2])

  def packEncryptedAES(self, machine, payload):
      iv = Rand.rand_bytes(16)
      #cipher=aes(key=machine.hipkey, mode='CBC', IV=iv)
      return '%s%s' % (iv, cipher.encrypt(payload))

  def packEncryptedM2(self, machine, payload, alg):
      m2alg={XFRM_HIP_DES_CBC:      ('des_ede3_cbc', 24, 64),
             XFRM_HIP_Blowfish_CBC: ('bf_cbc', 16, 64)
             }[alg]
      iv = Rand.rand_bytes(m2alg[2])
      cipher=EVP.Cipher(m2alg[0], machine.hipkey, iv, enc)
      plaintext = cipher.update(payload)
      plaintext += cipher.final()
      return '%s%s' % (iv, plaintext)

  def packEncrypted(self, machine, payload):
      alg = machine.hipXfrm[0]
      if alg in [XFRM_HIP_AES_CBC]:
          return self.packEncryptedAES(machine, payload)
      else:
          return self.packEncryptedM2(machine, payload, alg)

  def unpackEncryptedAES(self, machine, payload):
      iv = payload[:16]
      #cipher=aes(key=machine.remotehipkey, mode='CBC', IV=iv)
      return cipher.decrypt(payload[16:])

  def unpackEncryptedM2(self, machine, payload, alg):
      m2alg={XFRM_HIP_DES_CBC:      ('des_ede3_cbc', 24, 64),
             XFRM_HIP_Blowfish_CBC: ('bf_cbc', 16, 64)
             }[alg]
      iv = payload[:m2alg[2]]
      cipher=EVP.Cipher(m2alg[0], machine.remotehipkey, iv, dec)
      plaintext = cipher.update(payload[m2alg[2]:])
      plaintext += cipher.final()
      return plaintext

  def unpackEncryptedPl(self, machine, payload):
      alg = machine.hipXfrm[0]
      if alg in [XFRM_HIP_AES_CBC]:
          return self.unpackEncryptedAES(machine, payload)
      else:
          return self.unpackEncryptedM2(machine, payload, alg)

  def unpackEncrypted(self, machine, payload):
      rest = self.unpackEncryptedPl(machine, payload)
      l=[]
      while rest:
          (t, v, rest) = unpackTLV(rest)
          ops = [(HIP_REC_HIP_TRANSFORM, unpackXfrm),
                 (HIP_REC_ESP_TRANSFORM, unpackXfrm),
                 ]
          try:
              v = apply([x[1] for x in ops if x[0] == t][0], [v])
          except IndexError:
              pass
          l.append((t, v))
      return l





class I1Message(Message):
    def __init__(self):
        Message.__init__(self, 'I1', 1)
    def pack(self, machine):
        RRset = [(HIP_REC_KEY, machine.remoteHIT)]
        tail = packRRset(RRset)
        head = packHeader(0, len(tail), self.code, 1, machine.localHIT, machine.packFQDN())
        return head + tail
    def input(self, machine, header, RRset):
        if extractRRset(RRset, HIP_REC_KEY) <> machine.localHIT:
            raise HIPUnpackError, 'Not local HIT'
        if hasattr(machine, 'remoteHIT') and header.hit <> machine.remoteHIT:
            raise HIPNewConnection, header.hit
        machine.remoteHIT=header.hit
        return 1
        


class R1Message(Message):
    def __init__(self):
        Message.__init__(self, 'R1', 2)
    def pack(self, machine):
        RRset = [(HIP_REC_HIP_CNTLS, machine.controls()),
                 (HIP_REC_KEY, machine.HI.pack()),
                 (HIP_REC_KEY, self.packDH(machine)),
                 (HIP_REC_BIRTHDAY,
                  pack('!L', StateMachine.birthday)),
                 (HIP_REC_HIP_TRANSFORM,
                  packXfrm(HIP_OPT_IDENT_HIP_TRANSFORM,
                           machine.hipXfrmList)),
                 (HIP_REC_ESP_TRANSFORM,
                  packXfrm(HIP_OPT_IDENT_ESP_TRANSFORM,
                           machine.ESPXfrmList)),
                 (HIP_REC_HIP_COOKIE,
                  machine.Cookie.pack())]
        head = packHeader(0, 0, self.code, len(RRset), machine.localHIT, machine.packFQDN())
        tail = packRRset(RRset)
        return signpacket(head, tail, machine.HI)
    def input(self, machine, header, RRset):
        bod = RRsetToAttrs(RRset,
                           [(HIP_REC_HIP_COOKIE, 'cookie'),
                            (HIP_REC_HIP_CNTLS, 'controls'),
                            (HIP_REC_BIRTHDAY, 'birthday'),
                            (HIP_REC_HIP_TRANSFORM,
                             'hipXfrmList'),
                            (HIP_REC_ESP_TRANSFORM,
                             'ESPXfrmList'),
                            # we're going to get a two element list
                            (HIP_REC_KEY, 'keylist')
                            ],
                           Body())
        # todo: handle controls
        machine.remoteHI = HI(Rec=bod.keylist.pop(0))
        machine.Cookie.stored = bod.cookie.pop()
        remoteBirthday = unpack('!L', bod.birthday.pop())[0]
        if hasattr(machine,'remoteBirthday'):
            if machine.remoteBirthday <> remoteBirthday:
                # it rebooted, bang it on the head
                # not right.
                #machine.send(I2)
                pass
        machine.remoteBirthday = remoteBirthday
        # in both cases, take the first we support
        try:
            machine.hipXfrm = [x[1]
                               for x in bod.hipXfrmList.pop()
                               if x[1] in machine.hipXfrmList][0]
            machine.ESPXfrm = [x[1]
                               for x in bod.ESPXfrmList.pop()
                               if x[1] in machine.ESPXfrmList][0]
        except IndexError:
            raise HIPUnpackError, 'Remote requested unsupported transform'
        # allocate LSI
        machine.remoteLSI = pack('!L', StateMachine.LSIgen.next())
        # allocate SPI
        machine.remoteSPI = pack('!L', StateMachine.SPIgen.next())
        # Extract HIP keymat.  We're initiator.
        machine.keygenerator=self.unpackDH(machine,
                                           bod.keylist.pop(0),
                                           machine.localHIT,
                                           machine.remoteHIT,
                                           1)
        kl = machine.hipXfrmKeyLens[machine.hipXfrm]
        machine.hipkey = ''.join(map(apply,
                                     [machine.keygenerator.next]*kl))
        machine.remotehipkey = ''.join(map(apply,
                                           [machine.keygenerator.next]*kl))
        # extract ESP keys and set up SA
        machine.ESPalg = machine.ESPalgTags[machine.ESPXfrm]
        (alg, keylen, blocksize,
         authalg, authkeylen, authlen) = ESP.ESPAlgTable[machine.ESPalg]
        machine.ESPkey = ''.join(map(apply,
                                     [machine.keygenerator.next]*keylen))
        machine.ESPauthkey = ''.join(map(apply,
                                         [machine.keygenerator.next]*authkeylen))
        machine.remoteESPkey = ''.join(map(apply,
                                           [machine.keygenerator.next]*keylen))
        machine.remoteESPauthkey = ''.join(map(apply,
                                               [machine.keygenerator.next]*authkeylen))
        machine.remoteESP = ESP.SPI(SPI=machine.remoteSPI,
                                    key=machine.remoteESPkey,
                                    iv=Rand.rand_bytes(blocksize),
                                    authkey=machine.remoteESPauthkey,
                                    algname=machine.ESPalg)
        machine.remoteESP.machine = weakref.proxy(machine)
        return 1

class I2Message(Message):
    def __init__(self):
        Message.__init__(self, 'I2', 3)
    def pack(self, machine):
        encRRset = [(HIP_REC_ESP_TRANSFORM,
                     packXfrm(HIP_OPT_IDENT_ESP_TRANSFORM,
                                      [machine.ESPXfrm])),
                    (HIP_REC_KEY, machine.HI.pack())]
        RRset = [(HIP_REC_HIP_CNTLS, machine.controls()),
                 (HIP_REC_KEY, machine.HI.HITRR()),
                 (HIP_REC_BIRTHDAY,
                  pack('!L', StateMachine.birthday)),
                 (HIP_REC_HIP_COOKIE,
                  machine.Cookie.puzzle(machine.Cookie.stored)),
                 (HIP_REC_LSI,
                  machine.remoteLSI),
                 (HIP_REC_SPI,
                  machine.remoteSPI),
                 (HIP_REC_KEY, self.packDH(machine)),
                 (HIP_REC_HIP_TRANSFORM,
                  packXfrm(HIP_OPT_IDENT_HIP_TRANSFORM,
                                   [machine.hipXfrm])),
                 (HIP_REC_ENCRYPTED,
                  self.packEncrypted(machine, packRRset(encRRset)))]
        head = packHeader(0, 0, self.code, len(RRset), machine.localHIT, machine.packFQDN())
        tail = packRRset(RRset)
        return signpacket(head, tail, machine.HI)
    def input(self, machine, header, RRset):
        bod = RRsetToAttrs(RRset,
                           [(HIP_REC_HIP_COOKIE, 'cookie'),
                            (HIP_REC_HIP_CNTLS, 'controls'),
                            (HIP_REC_BIRTHDAY, 'birthday'),
                            (HIP_REC_HIP_TRANSFORM,
                             'hipXfrmList'),
                            # we're going to get a two element list
                            (HIP_REC_KEY, 'keylist'),
                            (HIP_REC_ENCRYPTED,
                             'encrypted'),
                            (HIP_REC_LSI, 'lsi'),
                            (HIP_REC_SPI, 'spi')
                            ],
                           Body())
        # todo: handle controls
        if hasattr(machine,'remoteBirthday'):
            if machine.remoteBirthday <> remoteBirthday:
                # it rebooted, bang it on the head
                # todo
                pass
        if machine.remoteHIT <> bod.keylist.pop(0):
            # we just got to check this under the sig
            raise HIPUnpackError, 'remote gave us inconsistent HIT'
        if not machine.Cookie.check(bod.cookie.pop(0)):
            raise HIPUnpackError, 'Bad Cookie'
        # blow up if we don't support initiator's choice
        try:
            machine.hipXfrm = [x[1]
                               for x in bod.hipXfrmList.pop()
                               if x[1] in machine.hipXfrmList][0]
        except IndexError:
            # this isn't right
            raise HIPUnpackError, 'Remote requested only unsupported transforms'
        machine.localLSI = bod.lsi.pop()
        machine.localSPI = bod.spi.pop()
        # allocate LSI
        machine.remoteLSI = pack('!L', StateMachine.LSIgen.next())
        if hasattr(machine, 'LSIcallback') and callable(machine.LSIcallback):
            machine.LSIcallback(machine)
        # allocate SPI
        machine.remoteSPI = pack('!L', StateMachine.SPIgen.next())
        # extract HIP keymat.  We're rESPonder.
        machine.keygenerator=self.unpackDH(machine,
                                           bod.keylist.pop(0),
                                           machine.localHIT,
                                           machine.remoteHIT,
                                           0)
        kl = machine.hipXfrmKeyLens[machine.hipXfrm]
        machine.remotehipkey = ''.join(map(apply,
                                           [machine.keygenerator.next]*kl))
        machine.hipkey = ''.join(map(apply,
                                     [machine.keygenerator.next]*kl))
        # now unpack the encrypted record
        RRsetToAttrs(self.unpackEncrypted(machine, bod.encrypted.pop()),
                     [(HIP_REC_ESP_TRANSFORM,
                       'ESPXfrmList'),
                      (HIP_REC_KEY, 'ekey')
                      ],
                     bod)
        # blow up if we don't support initiator's choice
        try:
            machine.ESPXfrm = [x[1]
                               for x in bod.ESPXfrmList.pop()
                               if x[1] in machine.ESPXfrmList][0]
        except IndexError:
            # this isn't right
            raise HIPUnpackError, 'Remote requested only unsupported transforms'
        # extract ESP keys and set up SA
        machine.ESPalg = machine.ESPalgTags[machine.ESPXfrm]
        (alg, keylen, blocksize,
         authalg, authkeylen, authlen) = ESP.ESPAlgTable[machine.ESPalg]
        machine.remoteESPkey = ''.join(map(apply,
                                           [machine.keygenerator.next]*keylen))
        machine.remoteESPauthkey = ''.join(map(apply,
                                               [machine.keygenerator.next]*authkeylen))
        machine.ESPkey = ''.join(map(apply,
                                     [machine.keygenerator.next]*keylen))
        machine.ESPauthkey = ''.join(map(apply,
                                         [machine.keygenerator.next]*authkeylen))
        machine.remoteESP = ESP.SPI(SPI=machine.remoteSPI,
                                    key=machine.remoteESPkey,
                                    iv=Rand.rand_bytes(blocksize),
                                    authkey=machine.remoteESPauthkey,
                                    algname=machine.ESPalg)
        machine.remoteESP.machine = weakref.proxy(machine)
        machine.localESP = ESP.SPI(SPI=machine.localSPI,
                                   key=machine.ESPkey,
                                   iv=Rand.rand_bytes(blocksize),
                                   authkey=machine.ESPauthkey,
                                   algname=machine.ESPalg)
        machine.localESP.machine = weakref.proxy(machine)
        return 1
        

class R2Message(Message):
    def __init__(self):
        Message.__init__(self, 'R2', 4)
    def pack(self, machine):
        RRset = [(HIP_REC_HIP_CNTLS, machine.controls()),
                 (HIP_REC_LSI,
                  machine.remoteLSI),
                 (HIP_REC_SPI,
                  machine.remoteSPI)]         
        head = packHeader(0, 0, self.code, len(RRset), machine.localHIT, machine.packFQDN())
        tail = packRRset(RRset)
        return signpacket(head, tail, machine.HI)
    def input(self, machine, header, RRset):
        bod = RRsetToAttrs(RRset,
                           [(HIP_REC_SPI, 'spi'),
                            (HIP_REC_HIP_CNTLS, 'controls'),
                            (HIP_REC_LSI, 'lsi'),
                            ],
                           Body())
        # todo: handle controls
        machine.localLSI = bod.lsi.pop()
        machine.localSPI = bod.spi.pop()
        if hasattr(machine, 'LSIcallback') and callable(machine.LSIcallback):
            machine.LSIcallback(machine)
        machine.ESPalg = machine.ESPalgTags[machine.ESPXfrm]
        (alg, keylen, blocksize,
         authalg, authkeylen, authlen) = ESP.ESPAlgTable[machine.ESPalg]
        machine.localESP = ESP.SPI(SPI=machine.localSPI,
                                   key=machine.ESPkey,
                                   iv=Rand.rand_bytes(blocksize),
                                   authkey=machine.ESPauthkey,
                                   algname=machine.ESPalg)
        machine.localESP.machine = weakref.proxy(machine)
        return 1
        
class BOSMessage(Message):
    def __init__(self):
        Message.__init__(self, 'BOS', 10)
    def pack(self, machine):
        RRset = [(HIP_REC_HIP_CNTLS, machine.controls()),
                 (HIP_REC_KEY, machine.HI.HITRR()),
                 (HIP_REC_KEY, machine.HI.pack())]
        head = packHeader(0, 0, self.code, len(RRset), machine.localHIT, machine.packFQDN())
        tail = packRRset(RRset)
        return signpacket(head, tail, machine.HI)
    def input(self, machine, header, RRset):
        bod = RRsetToAttrs(RRset,
                           [(HIP_REC_KEY, 'keylist'),
                            (HIP_REC_HIP_CNTLS, 'controls'),
                            ],
                           Body())
        newHIT = bod.keylist.pop(0)
        newHI = HI(Rec=bod.keylist.pop(0))
        if newHI.HIT127() == newHIT:
            HI.HITable[newHIT] = newHI

class REAMessage(Message):
    def __init__(self):
        Message.__init__(self, 'REA', 6)
    def pack(self, machine, ID=None):
        SN = pack('!L', machine.remoteESP.SN)
        SPI = machine.remoteESP.SPI
        Alist = machine.localIPs
        def packA(A):
            if len(A)==4:
                return((HIP_REC_A, A))
            elif len(A)==16:
                return((HIP_REC_AAAA, A))
            else:
                raise ValueError
        RRset = [(HIP_REC_ESP_SN,
                  SN),
                 (HIP_REC_SPI,
                  SPI)]         
        if ID:
            RRset.append((HIP_REC_ID, ID))
        RRset += map(packA, Alist)
        head = packHeader(0, 0, self.code, len(RRset), machine.localHIT, machine.packFQDN())
        tail = packRRset(RRset)
        return signpacket(head, tail, machine.HI)
    def input(self, machine, header, RRset):
        bod = RRsetToAttrs(RRset,
                           [(HIP_REC_ESP_SN,
                             'SN'),
                            (HIP_REC_A, 'IPs'),
                            (HIP_REC_AAAA, 'IP6s')],
                           Body())
        def REASNCallback():
            print 'SNCallback'
            machine.setRemoteIPs(bod.IPs)
        SN = unpack('!L', bod.SN.pop(0))[0]
        machine.localESP.SNCallbacks[SN] = REASNCallback
        machine.remoteESP.SNCallbacks[SN] = REASNCallback


class NESMessage(Message):
    def __init__(self):
        Message.__init__(self, 'NES', 5)
    def pack(self, machine):
        # assume ESP is held when we get here
        # or that we're turning around
        # also assume DH key was regenerated elsewhere
        # SN is preincrement
        SN = pack('!L', machine.remoteESP.SN + 1)
        machine.remoteSPI =  pack('!L', StateMachine.SPIgen.next())
        RRset = [(HIP_REC_ESP_SN,
                  SN),
                 (HIP_REC_SPI,
                  machine.localESP.SPI),
                 (HIP_REC_SPI,
                  machine.remoteSPI)]
        RRset.append((HIP_REC_KEY, self.packDH(machine)))
        head = packHeader(0, 0, self.code, len(RRset), machine.localHIT, machine.packFQDN())
        tail = packRRset(RRset)
        return signpacket(head, tail, machine.HI)
    def input(self, machine, header, RRset):
        bod = RRsetToAttrs(RRset,
                           [(HIP_REC_ESP_SN,
                             'SN'),
                            (HIP_REC_KEY, 'keylist'),
                            (HIP_REC_SPI,
                             'SPI')],
                           Body())
        SN = unpack('!L', bod.SN.pop(0))[0]
        #machine.remoteSPI
        junk = bod.SPI.pop(0)
        machine.localSPI = bod.SPI.pop(0)
        try:
            # extract HIP keymat.
            machine.keygenerator=self.unpackDH(machine,
                                               bod.keylist.pop(0),
                                               machine.localHIT,
                                               machine.remoteHIT,
                                               0)
            DHpassed = 1
        except IndexError:
            # Ok, we were not passed a DH, therefore we already have
            # the keymat. note that I think we have a bug here; is this
            # correct when we generated a new DH key when sending?
            machine.dhkey = machine.DH.compute_key(nbo2BN(pub))
            machine.keygenerator = keymatgen(machine.dhkey,
                                             [machine.localHIT,
                                              machine.remoteHIT])
            DHpassed = 0
            pass
        if machine.rekeying:
            pass
        else:
            # unsolicited NES, must reply
            # always do this
            machine.DH.gen_key()
            pass
        # OK, we've got our reply
        # keygen is primed, so here we go
        (alg, keylen, blocksize,
         authalg, authkeylen, authlen) = ESP.ESPAlgTable[machine.ESPalg]
        machine.remoteESPkey = ''.join(map(apply,
                                           [machine.keygenerator.next]
                                           *keylen))
        machine.remoteESPauthkey = ''.join(map(apply,
                                               [machine.keygenerator.next]
                                               *authkeylen))
        machine.ESPkey = ''.join(map(apply,
                                     [machine.keygenerator.next]
                                     *keylen))
        machine.ESPauthkey = ''.join(map(apply,
                                         [machine.keygenerator.next]
                                         *authkeylen))
        if machine.rekeying:
            # swap the keys
            (machine.ESPkey,
             machine.remoteESPkey) = (machine.remoteESPkey,
                                      machine.ESPkey)
            (machine.ESPauthkey,
             machine.remoteESPauthkey) = (machine.remoteESPauthkey,
                                          machine.ESPauthkey)
            machine.rekeying = 0
        else:
            # do this here, NOT in the states!
            machine.send(NES)
        machine.localESP = ESP.SPI(SPI=machine.localSPI,
                                   key=machine.ESPkey,
                                   iv=Rand.rand_bytes(blocksize),
                                   authkey=machine.ESPauthkey,
                                   algname=machine.ESPalg)
        machine.localESP.machine = weakref.proxy(machine)
        machine.remoteESP = ESP.SPI(SPI=machine.remoteSPI,
                                    key=machine.remoteESPkey,
                                    iv=Rand.rand_bytes(blocksize),
                                    authkey=machine.remoteESPauthkey,
                                    algname=machine.ESPalg)
        machine.remoteESP.machine = weakref.proxy(machine)
                 


class ESPMessage(Message):
    def __init__(self):
        Message.__init__(self, 'ESP', 0)


I1 = I1Message()
R1 = R1Message()
I2 = I2Message()
R2 = R2Message()
REA = REAMessage()
BOS = BOSMessage()
NES = NESMessage()
ESPM = ESPMessage()

Message.dispatchlist = {1: I1,
                     2: R1,
                     3: I2,
                     4: R2,
                     5: NES,
                     6: REA,
                     10: BOS}
