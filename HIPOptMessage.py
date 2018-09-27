##try:
##    from psyco.classes import *
##except ImportError:
##    pass

import weakref
from types import *
import struct
import sstruct
import string
from pprint import pprint
from array import array

LARGE=pow(2,31)-1
from Crypto.Cipher import AES, DES3, Blowfish
from Crypto.Util.number import bytes_to_long, long_to_bytes
import DH

from binascii import unhexlify, hexlify
from time import time

import HI
from HIPutils import *
import HIPCookie
import HIPState
import ESP
import IPAddress

##    HIP Header

##    0                   1                   2                   3
##    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
##   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##   | Payload Proto | Header Length |  Packet Type  |  VER. |  RES. |
##   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##   |          Control              |           Checksum            |
##   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##   |                Sender's Host Identity Tag (HIT)               |
##   |                                                               |
##   |                                                               |
##   |                                                               |
##   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##   |               Receiver's Host Identity Tag (HIT)              |
##   |                                                               |
##   |                                                               |
##   |                                                               |
##   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##   |                                                               |
##   /                        HIP Parameters                         /
##   /                                                               /
##   |                                                               |
##   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

HIP_HEADER_FMT = '!BBBBHH16s16s'
# (nh, len, type, magic, control, csum, s-HIT, r-HIT)
HIP_HEADER_SFMT = '''
                  !
                  nh:B
                  len:B
                  type:B
                  magic:B
                  control:H
                  csum:H
                  sourceHIT:16s
                  remoteHIT:16s
                  '''
HIP_HEADER_LEN = struct.calcsize(HIP_HEADER_FMT)

##def packHeader(NextHeader, Length, Type, LocalHIT, RemoteHIT):
##    return pack(HIP_HEADER_FMT,
##                NextHeader,
##                Length>>3,
##                Type,
##                0x10,
##                LocalHIT,
##                RemoteHIT)


def unpackHeader(payload, object=None):
    result = sstruct.unpack(HIP_HEADER_SFMT, payload[:HIP_HEADER_LEN], object)
    return (result, payload[HIP_HEADER_LEN:])

class HIPHeader:
    magic = 0x10
    format = HIP_HEADER_SFMT
    size = HIP_HEADER_LEN
    def __init__(self, string='', **values):
        if string:
            Body = self.unpack(string)
            self.__dict__.update(Body)
        else:
            # defaults
            self.__dict__.update({'csum': 0,
                                  'nh': NO_PROTO,
                                  'control': HIPC_ANON | HIPC_PIGGY,
                                  'magic': 0x10})
            self.__dict__.update(values)
    def pack(self):
        return sstruct.pack(self.format,
                            self.__dict__)
    def unpack(self, string):
        return sstruct.unpack(self.format, string[:self.size])

class Body:
    def __init__(self, RRset):
        d = dict([(x.name, x) for x in RRset])
        self.__dict__.update(d)
        
##   The following encryption algorithms are defined.

##      Transform-ID             Values

##      RESERVED                    0
##      ENCR_NULL                   1
##      ENCR_3DES                   2
##      ENCR_AES_128                3

ENCR_NULL = 1
ENCR_3DES = 2
ENCR_AES_128 = 3
ENCR_Blowfish = 4

# tuples (name, ciphermodule, keylength, blocksize)

HIPXfrmTable = {ENCR_NULL: ('NULL', None, 0, 1),
                ENCR_3DES: ('3DES', DES3, 24, 8),
                ENCR_AES_128: ('AES-128', AES, 16, 16),
                ENCR_Blowfish: ('Blowfish', Blowfish, 16, 8)}

##   The following Suite-IDs are defined ([IKEv2],[JFK]):

##      Suite-ID                          Value

##      RESERVED                          0
##      ESP-AES-CBC with HMAC-SHA1        1
##      ESP-3DES-CBC with HMAC-SHA1       2
##      ESP-3DES-CBC with HMAC-MD5        3
##      ESP-BLOWFISH-CBC with HMAC-SHA1   4
##      ESP-NULL with HMAC-SHA1           5
##      ESP-NULL with HMAC-MD5            6

ESP_AES_CBC_HMAC_SHA1 = 1
ESP_3DES_CBC_HMAC_SHA1 = 2
ESP_3DES_CBC_HMAC_MD5 = 3
ESP_BLOWFISH_CBC_HMAC_SHA1 = 4
ESP_NULL_HMAC_SHA1 = 5
ESP_NULL_HMAC_MD5 = 6

# look these up in ESP.py's ESPAlgTable for parameters

ESPXfrmTable = {1: 'AES-HMAC-SHA1-96',
                2: '3DES-HMAC-SHA1-96',
                3: '3DES-HMAC-MD5',
                4: 'Blowfish-HMAC-SHA1-96',
                5: 'NULL-HMAC-SHA1-96',
                6: 'NULL-HMAC-MD5'}

# IANA values from RFC2407 + friends

# from IKEv2

##Appendix A

##   Attribute Assigned Numbers

##   Certain transforms negotiated in an SA payload can have associated
##   attributes. Attribute types can be either Basic (B) or Variable-
##   length (V). Encoding of these attributes is defined as Type/Value
##   (Basic) and Type/Length/Value (Variable).  See section 7.3.3.

##   Attributes described as basic MUST NOT be encoded as variable.
##   Variable length attributes MUST NOT be encoded as basic even if their
##   value can fit into two octets. NOTE: This is a change from IKEv1,
##   where increased flexibility may have simplified the composer of
##   messages but certainly complicated the parser.

##   Attribute Classes

##          class                         value              type
##      --------------------------------------------------------------
##      RESERVED                           0-5
##      Group Prime/Irreducible Polynomial  6                 V
##      Group Generator One                 7                 V
##      Group Generator Two                 8                 V
##      Group Curve A                       9                 V
##      Group Curve B                      10                 V
##      RESERVED                          11-13
##      Key Length                         14                 B
##      Field Size                         15                 B
##      Group Order                        16                 V
##      Block Size                         17                 B

##XFRM_SA_KEY_LENGTH = 14
##XFRM_SA_BLOCK_SIZE = 17


##XFRM_HIP_DES_CBC               =  1
##XFRM_HIP_IDEA_CBC              =  5
##XFRM_HIP_Blowfish_CBC          =  7
##XFRM_HIP_RC5_R16_B64_CBC       =  4
##XFRM_HIP_3DES_CBC              =  3
##XFRM_HIP_CAST_CBC              =  6
##XFRM_HIP_NULL                  =  11
##XFRM_HIP_AES_CBC               =  12

##XFRM_ESP_DES_IV64          =  1
##XFRM_ESP_DES               =  2
##XFRM_ESP_3DES              =  3
##XFRM_ESP_RC5               =  4
##XFRM_ESP_IDEA              =  5
##XFRM_ESP_CAST              =  6
##XFRM_ESP_BLOWFISH          =  7
##XFRM_ESP_3IDEA             =  8
##XFRM_ESP_DES_IV32          =  9
##XFRM_ESP_RC4               =  10
##XFRM_ESP_NULL              =  11
##XFRM_ESP_AES_128           =  12

##XFRM_AUTH_NONE                  =  0
##XFRM_AUTH_MD5                   =  2
##XFRM_AUTH_SHA                   =  3
##XFRM_AUTH_DES                   =  4


class HIPRec:
    def __init__(self, string=None, **values):
        # string may be passed in but null or None
        if string:
            Body = self.unpackBody(string)
            self.__dict__.update(Body)
        elif values:
            # default reserved fields to zero
            self.__dict__.update({'Res': 0})
            self.__dict__.update(values)
    def __str__(self):
        return self.name
    def __cmp__(self, other):
        return cmp(self.type, other.type)
    def __hash__(self):
        return hash(self.type)
    def packBody(self):
        return sstruct.pack(self.format,
                            self.__dict__)
    def unpackBody(self, string):
        return sstruct.unpack(self.format, string)
    def pack(self):
        return packTLV(self.type,
                       self.packBody())
    def unpack(self, string):
        (Tag, Body, Rest) = unpackTLV(string)
        try:
            Body = HIP_RECs[Tag](Body)
        except KeyError:
            print KeyError, 'Odd record of type ' + str(Tag) + ' ' + repr(self.__dict__) + ' ' + repr(string)
        return (Tag, Body, Rest)

class HIP_REC_PAD(HIPRec):
    type = 0
    name = 'PAD'
    def packBody(self):
        return '\x00' * self.Res
    def unpackBody(self, string):
        i = 0
        for i in range(len(string)):
            if string[i]:
                break
        self.Res = i
        return None


class HIP_REC_SPI_LSI(HIPRec):
    '''
    3.4.1 SPI_LSI

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Type              |             Length            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                           Reserved                            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                              SPI                              |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                              LSI                              |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Type         1
        Length       12
        Reserved     Zero when sent, ignored when received
        SPI          Security Parameter Index
        LSI          Local Scope Identifier
    '''
    type = 1
    name = 'SPI_LSI'
    format = '''
    !
    Res: L
    SPI: L
    LSI: L
    '''

class HIP_REC_BIRTHDAY_COOKIE_R1(HIPRec):
    '''
    3.4.2 BIRTHDAY_COOKIE

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             Type              |             Length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           Reserved                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Birthday, 8 bytes                                             |
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Random # I, 8 bytes                                           |
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Random # J or K, 8 bytes                                      |
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Hash Target, 8 bytes                                          |
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

       Type         2 (in R1) or 3 (in I2)
       Length       36
       Reserved     Zero when sent, ignored when received
       Birthday     System boot counter
       Random # I   random number
       K or         K is the number of verified bits (in R1 packet)
       Random # J   random number (in I2 packet)
       Hash Target  calculated hash value

    '''
    type = 2
    name = 'BIRTHDAY_COOKIE'
    format = '''
    !
    Res: L
    Birthday: Q
    I: 8s
    JK: 8s
    Target: 8s
    '''
    
class HIP_REC_BIRTHDAY_COOKIE_I2(HIPRec):
    '''
    3.4.2 BIRTHDAY_COOKIE

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             Type              |             Length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           Reserved                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Birthday, 8 bytes                                             |
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Random # I, 8 bytes                                           |
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Random # J or K, 8 bytes                                      |
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Hash Target, 8 bytes                                          |
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

       Type         2 (in R1) or 3 (in I2)
       Length       36
       Reserved     Zero when sent, ignored when received
       Birthday     System boot counter
       Random # I   random number
       K or         K is the number of verified bits (in R1 packet)
       Random # J   random number (in I2 packet)
       Hash Target  calculated hash value

    '''
    type = 3
    name = 'BIRTHDAY_COOKIE'
    format = '''
    !
    Res: L
    Birthday: Q
    I: 8s
    JK: 8s
    Target: 8s
    '''
    
class HIP_REC_DH_FULL(HIPRec):
    '''
    DELETED in draft-01
    '''
    type = 5
    name = 'DH_FULL'
    def packBody(self):
        return ''.join([chr(self.__dict__['GroupID']),
                        struct.pack('!H', len(self.__dict__['Prime'])),
                        self.__dict__['Prime'],
                        struct.pack('!H', len(self.__dict__['Generator'])),
                        self.__dict__['Generator'],
                        struct.pack('!H', len(self.__dict__['Public'])),
                        self.__dict__['Public']])
    def unpackBody(self, string):
        Body = {'GroupID': ord(string[0])}
        Rest = string[1:]
        for i in ['Prime', 'Generator', 'Public']:
            (len_next,) = struct.unpack('!H', Rest[:2])
            Body.update({i: Rest[2:2+len_next]})
            Rest = Rest[2+len_next:]
        return Body

class HIPIdVal:
    def packBody(self):
        return ''.join([chr(self.__dict__[self.__id__]),
                        self.__dict__[self.__val__]])
    def unpackBody(self, string):
        return {self.__id__: ord(string[0]),
                self.__val__: string[1:]}

        
class HIP_REC_DH(HIPIdVal, HIPRec):
    '''
    3.4.3 DIFFIE_HELLMAN

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             Type              |             Length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Group ID    |               public value                    /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       /                               |            padding            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

       Type         6
       Length       length in octets, excluding T and L fields and padding
       Group ID     defines values for p and g
       public value

       The following Group IDs have been defined:

       Group                            Value
        Reserved                         0
        OAKLEY well known group 1        1
        OAKLEY well known group 2        2
        1536-bit MODP group              3
        2048-bit MODP group              4 
        3072-bit MODP group              5
        4096-bit MODP group              6
        6144-bit MODP group              7
        8192-bit MODP group              8

     MODP Diffie-Hellman groups are defined in [14]. OAKLEY groups are
     defined in [7]. The OAKLEY well known group 5 is the same as 1536-bit
     MODP group.
    '''
    type = 6
    name = 'DIFFIE_HELLMAN'
    __id__ = 'GroupID'
    __val__ = 'Public'

class HIPTransformRec:
    def packBody(self):
        # enforce the transmission of no more than __xfrm_limit__ transforms
        xfrms = getattr(self, self.__transformType__)
        return packXfrm(xfrms[:self.__xfrm_limit__])
    def unpackBody(self, string):
        try:
            if not string: raise ValueError
            trans = {self.__transformType__: unpackXfrm(string)}
        except:
            trans = {self.__transformType__: self.defaultXfrm}
        return trans
    
class HIP_REC_HIP_TRANSFORM(HIPTransformRec, HIPRec):
    '''
    3.4.4 HIP_TRANSFORM

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             Type              |             Length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |          Transform-ID #1      |       Transform-ID #2         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |          Transform-ID #n      |             Padding           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

       Type         16
       Length       length in octets, excluding T and L fields and padding
       Transform-ID Defines the HIP Transform to be used

       The following encryption algorithms are defined.

          Transform-ID             Values

          RESERVED                    0
          ENCR_NULL                   1
          ENCR_3DES                   2
          ENCR_AES_128                3

       There MUST NOT be more than three (3) HIP Transform-IDs in one HIP
       transform TLV. The limited number of transforms sets the maximum
       size of HIP_TRANSFORM TLV. The HIP_TRANSFORM TLV MUST contain at
       least one of the mandatory Transform-IDs.

       Mandatory implementations: ENCR_3DES and ENCR_NULL
    '''
    type = 16
    name = 'HIP_TRANSFORM'
    __transformType__ = 'HIPXfrm'
    __xfrm_limit__ = 3
    defaultXfrm = [ENCR_3DES]
    
class HIP_REC_ESP_TRANSFORM(HIPTransformRec, HIPRec):
    '''
    3.4.5 ESP_TRANSFORM

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             Type              |             Length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |          Suite-ID #1          |           Suite-ID #2         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |          Suite-ID #n          |             Padding           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

       Type         18
       Length       length in octets, excluding T and L fields and padding
       Suite-ID     Defines the ESP Suite to be used

       The following Suite-IDs are defined ([IKEv2],[JFK]):

          Suite-ID                          Value

          RESERVED                          0
          ESP-AES-CBC with HMAC-SHA1        1
          ESP-3DES-CBC with HMAC-SHA1       2
          ESP-3DES-CBC with HMAC-MD5        3
          ESP-BLOWFISH-CBC with HMAC-SHA1   4
          ESP-NULL with HMAC-SHA1           5
          ESP-NULL with HMAC-MD5            6

       There MUST NOT be more than six (6) ESP Suite-IDs in one
       ESP_TRANSFORM TLV. The limited number of Suite-IDs sets the maximum
       size of ESP_TRANSFORM TLV. The ESP_TRANSFORM MUST contain at least
       one of the mandatory Suite-IDs.

       Mandatory implementations: ESP-3DES-CBC with HMAC-SHA1 and ESP-NULL
       with HMAC-SHA1
    '''
    type = 18
    name = 'ESP_TRANSFORM'
    __transformType__ = 'ESPXfrm'
    __xfrm_limit__ = 6
    defaultXfrm = [ESP_3DES_CBC_HMAC_SHA1]
    
class HIP_REC_HI(HIPIdVal, HIPRec):
    '''
    3.4.6 HOST_ID

       When the host sends a Host Identity to a peer, it MAY send the
       identity without any verification information or use certificates to
       proof the HI. If certificates are sent, they are sent in a separate
       HIP packet (CER).

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             Type              |             Length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Algorithm    |               Host Identity                   /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       /                                               |   padding     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

       Type           32
       Length         length in octets, excluding T and L fields and padding
       Algorithm      Host Identity algorithm
       Host Identity

       The following algorithms are defined:

       Algorithm      value
       RESERVED       0
       DSA            1

       The encoding format for DSA keys is defined in FIPS 186 and ANSI
       X9.30 standard.
    '''
    type = 32
    name = 'HOST_ID'
    __id__ = 'Algorithm'
    __val__ = 'Identity'

class HIP_REC_HI_FQDN(HIPRec):
    '''
    3.4.7 HOST_ID_FQDN

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             Type              |             Length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Algorithm    |          HI Length            |               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       /              Host Identity                                    /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       /               |         FQDN Length           |               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       /                   FQDN                        |    Padding    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

       Type           33
       Length         length in octets, excluding T and L fields and padding
       Algorithm      Host Identity algorithm, defined in HOST_ID TLV
       Host Identity
       length         length of the HI
       Host Identity
       FQDN length    length of the FQDN
       FQDN           Fully Qualified Domain Name

       If there is no FQDN, the HOST_ID TLV is sent instead. The
       algorithms are the same as defined in 3.4.6.
    '''
    type = 33
    name = 'HOST_ID_FQDN'
    def packBody(self):
        return ''.join([chr(self.__dict__['Algorithm']),
                        struct.pack('!H', len(self.__dict__['Identity'])),
                        self.__dict__['Identity'],
                        struct.pack('!H', len(self.__dict__['FQDN'])),
                        self.__dict__['FQDN']])
    def unpackBody(self, string):
        Body = {'Algorithm': ord(string[0])}
        Rest = string[1:]
        for i in ['Identity', 'FQDN']:
            (len_next,) = struct.unpack('!H', Rest[:2])
            Body.update({i: Rest[2:2+len_next]})
            Rest = Rest[2+len_next:]
        return Body
    
##HIP_REC_CERT = 64

class HIP_REC_SIG(HIPIdVal, HIPRec):
    '''
    3.4.9 HIP_SIGNATURE

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             Type              |             Length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |    SIG alg    |                  Signature                    /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       /                               |             padding           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

       Type         65534 (2^16-2)
       Length       length in octets, excluding T and L fields and padding
       SIG alg      Signature algorithm
       Signature    the signature is calculated over the HIP packet,
                    excluding the HIP_SIGNATURE TLV field. The checksum
                    field MUST be set to zero and the HIP header length in
                    the HIP common header MUST be calculated to the
                    beginning of the HIP_SIGNATURE TLV when the signature is
                    calculated.
    '''
    type = 65534
    name = 'SIG'
    __id__ = 'Algorithm'
    __val__ = 'Sig'

class HIP_REC_SIG2(HIPIdVal, HIPRec):
    '''
    3.4.10 HIP_SIGNATURE_2

       The TLV structure is the same as in 3.4.9. The fields are:

       Type         65533 (2^16-3)
       Length       length in octets, excluding T and L fields and padding
       SIG alg      Signature algorithm
       Signature    the signature is calculated over the R1 packet,
                    excluding the HIP_SIGNATURE_2 TLV field. Initiators HIT
                    and Checksum field MUST be set to zero and the HIP
                    packet length in the HIP header MUST be calculated to
                    the beginning of the HIP_SIGNATURE_2 TLV when the
                    signature is calculated.
    '''
    type = 65533
    name = 'SIG2'
    __id__ = 'Algorithm'
    __val__ = 'Sig'

class HIP_REC_HMAC(HIPIdVal, HIPRec):
    '''
    6.1.1.2 HMAC

       The HMAC SHA-1 is used to verify a received packet.

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             Type              |             Length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       /                           HMAC data                           /
       /                                                               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+



          Type         65532
          Length       Length in octets, excluding Type and Length fields
          HMAC data    20 bytes of HMAC SHA-1 data

    '''
    type = 65532
    name = 'HMAC'
    def packBody(self):
        return self.HMAC
    def unpackBody(self, string):
        return {'HMAC': string}

##class HIP_REC_REA_INFO(HIPRec):
##    '''
##    3.4.11 REA_INFO

##        0                   1                   2                   3
##        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
##       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##       |             Type              |             Length            |
##       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##       |                      ESP sequence number                      |
##       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##       |                          current SPI                          |
##       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##       |                            Reserved                           |
##       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##       |                              ID                               |
##       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##       |                           Lifetime                            |
##       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##       |                            Address                            |
##       |                                                               |
##       |                                                               |
##       |                                                               |
##       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##       .                                                               .
##       .                                                               .
##       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##       |                              ID                               |
##       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##       |                           Lifetime                            |
##       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
##       |                            Address                            |
##       |                                                               |
##       |                                                               |
##       |                                                               |
##       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


##       Type         128
##       Length       length in octets, excluding T and L fields
##       ESP sequence the ESP sequence number from the last sent ESP packet
##       number
##       Current SPI  the SPI used for ESP
##       Reserved     zero when sent, ignored when received
##       ID           Interface ID, local to the host
##       Lifetime     Address lifetime
##       Address      IPv6 or IPv4-in-IPv6 format [RFC2373]

##       The <ID, Lifetime, Address> triplet may be repeated several times.
##       The maximum header size gives the limit how many triplets may be
##       included in a single packet.
##    '''
##    type = 128
##    name = 'REA_INFO'
##    format = '''
##    !
##    ESP_SN: L
##    SPI: L
##    Res: L
##    '''
##    len_format = sstruct.calcsize(format)
##    format2 = '''
##    ID: L
##    Lifetime: L
##    Address: 16s
##    '''
##    len_format2 = sstruct.calcsize(format2)
##    def packBody(self):
##        # fun with lists and map
##        # Addrs is ID -> {ID, Lifetime, Address} dict mapping
##        # IDs contains IDs to be in this packet
##        return ''.join(map(sstruct.pack,
##                           [self.format]
##                           + [self.format2] * len(self.IDs),
##                           [self.__dict__]
##                           + [x
##                              for x in self.Addrs
##                              if x['ID'] in self.IDs]))
##    def unpackBody(self, string):
##        Rest = string[self.len_format:]
##        Addrs = []
##        while Rest:
##            Rec = sstruct.unpack(self.format2, Rest[:self.len_format2])
##            Addrs.append(Rec)
##            Rest = Rest[self.len_format2:]
##        Body = {'Addrs': Addrs,
##                'IDs': [x['ID']
##                        for x in Addrs]}
##        Body.update(sstruct.unpack(self.format,
##                                   string[:self.len_format]))
##        return Body

class HIP_REC_REA_INFO(HIPRec):
    '''
        6.1.1.1 REA_INFO payload

       Note that the REA_INFO payload is a kind of "expanded" NES.

       XXX (Pekka): Note that I have, for the time being, removed the old
       ESP sequence number.  Firstly, it may be hard to acquire reliably in
       some implemtations (ours included).  Secondly, we now have a REA ID
       field, which is basically a REA sequence number.

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             Type              |             Length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Interface ID                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                 Current SPI in reverse direction              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                          Current SPI                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                            New SPI                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |       Keymaterial index       |             REA ID            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                       Address Lifetime                        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           Reserved                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                            Address                            |
       |                                                               |
       |                                                               |
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       .                                                               .
       .                                                               .
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                       Address Lifetime                        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           Reserved                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                            Address                            |
       |                                                               |
       |                                                               |
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

      Type               128
      Length             Length in octets, excluding Type and Length
                         fields
      Interface ID       Interface ID, as defined by the sending host
      Current SPI rev.   The current SPI used in the reverse direction
      Current SPI        The current SPI used for receiving ESP on this
                         interface
      New SPI            The new SPI used for receiving ESP on this
                         interface
      Keymaterial index  A bit index to the KEYMAT, where to pick up
                         the keying material for the new SA.
      REA ID             A 16-bit sequence number of nonce, used to
                         match the REA packet to the corresponding AC
                         packet.
      Address Lifetime   Address lifetime
      Reserved           Zero when sent, ignored when received
      Address            An IPv6 address or an IPv4-in-IPv6 format
                         IPv4 address
    '''
    type = 128
    name = 'REA_INFO'
    format = '''
    !
    Interface: L
    SPI: L
    RevSPI: L
    NewSPI: L
    KeyInd: H
    REAID: H
    '''
    len_format = sstruct.calcsize(format)
    # note: See IPAddress.py and initialisation of interface list
    # for why the odd names.
    format2 = '''
    !
    Lifetime: L
    Reserved: L
    MaybeIPv4inv6: 16s
    '''
    len_format2 = sstruct.calcsize(format2)
    def packBody(self):
        # fun with lists and map
        # self.interfaces is dict of list of IPAddress objects
        # self.Interface is key (ID of interface)
        return ''.join(map(sstruct.pack,
                           [self.format]
                           + [self.format2] * len(self.interfaces[self.Interface]),
                           [self] + self.interfaces[self.Interface]))
    def unpackBody(self, string):
        Rest = string[self.len_format:]
        Addrs = []
        while Rest:
            Rec = sstruct.unpack(self.format2, Rest[:self.len_format2])
            Addrs.append(Rec)
            Rest = Rest[self.len_format2:]
        for i in range(len(Addrs)):
            a = IPAddress.IP(Addrs[i]['MaybeIPv4inv6'])
            a.__dict__.update(Addrs[i])
            Addrs[i] = a
        Body = sstruct.unpack(self.format,
                                   string[:self.len_format])
        Body['interfaces'] = {Body['Interface']: Addrs}
        return Body


class HIP_REC_AC_INFO(HIPRec):
    '''
    6.1.2.1 AC_INFO payload

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             Type              |             Length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             AC ID             |            REA ID             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                        RTT timestamp                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           Reserved                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


          Type           129
          Length         Length in octets, excluding Type and Length
                         fields
          AC ID          A 16-bit sequence number of nonce, used to match
                         the AC packet to the corresponding ACR packet.
          REA ID         A 16-bit sequence number of nonce, used to match
                         the REA packet to the corresponding AC packet.
          RTT timestamp  A timestamp field which may be used for RTT
                         estimation
          Reserved       Zero when sent, ignored when received
    '''
    type = 129
    name = 'AC_INFO'
    format = '''
    !
    ACID: H
    REAID: H
    Timestamp: L
    Res: L
    '''

class HIP_REC_NEW_SPI(HIPRec):
    '''
    3.4.12 NEW_SPI

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             Type              |             Length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      ESP sequence number                      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                            Old SPI                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                            New SPI                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

       Type         4
       Length       length in octets, excluding T and L fields
       ESP sequence
       number
       Old SPI
       New SPI
    '''
    type = 4
    name = 'NEW_SPI'
    format = '''
    !
    ESP_SN: L
    OldSPI: L
    NewSPI: L
    '''

class HIP_REC_ENCRYPTED(HIPRec):
    '''
    3.4.13 ENCRYPTED

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             Type              |             Length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           Reserved                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                              IV                               |
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                        Encrypted data                         /
       /                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

       Type         20
       Length       length in octets, excluding T and L fields
       Reserved     zero when sent, ignored when received
       IV           Initialization vector, if needed, zero otherwise
       Encrypted    the data is encrypted using an encryption algorithm as
       data         defined in HIP transform

       The encrypted data is in TLV format itself. Consequently, the first
       fields in the contents are Type and Length.
    '''
    type = 20 
    name = 'Encrypted'
    def packBody(self):
        return '\x00\x00\x00\x00' + self.__dict__['Encrypted']
    def unpackBody(self, string):
        r = {'Encrypted': string[4:], 'Res:': string[:4]}
        return r

HIP_RECs = {
    HIP_REC_PAD.type: HIP_REC_PAD,
    HIP_REC_SPI_LSI.type: HIP_REC_SPI_LSI,
    HIP_REC_BIRTHDAY_COOKIE_R1.type: HIP_REC_BIRTHDAY_COOKIE_R1,
    HIP_REC_BIRTHDAY_COOKIE_I2.type: HIP_REC_BIRTHDAY_COOKIE_I2,
    HIP_REC_DH_FULL.type: HIP_REC_DH_FULL,
    HIP_REC_DH.type: HIP_REC_DH,
    HIP_REC_HIP_TRANSFORM.type: HIP_REC_HIP_TRANSFORM,
    HIP_REC_ESP_TRANSFORM.type: HIP_REC_ESP_TRANSFORM,
    HIP_REC_HI.type: HIP_REC_HI,
    HIP_REC_HI_FQDN.type: HIP_REC_HI_FQDN,
##    HIP_REC_CERT.type: HIP_REC_CERT,
    HIP_REC_SIG.type: HIP_REC_SIG,
    HIP_REC_SIG2.type: HIP_REC_SIG2,
    HIP_REC_HMAC.type: HIP_REC_HMAC,
    HIP_REC_REA_INFO.type: HIP_REC_REA_INFO,
    HIP_REC_NEW_SPI.type: HIP_REC_NEW_SPI,
    HIP_REC_ENCRYPTED.type: HIP_REC_ENCRYPTED
    }

##3.4.9 HIP_SIGNATURE


##   Signature calculation and verification process:

##   Packet sender:

##        1. Create the HIP packet without the HIP_SIGNATURE TLV
##        2. Calculate the length field in the HIP header
##        3. Compute the signature
##        4. Add the HIP_SIGNATURE TLV to the packet
##        5. Recalculate the length field in the HIP header

##   Packet receiver:

##        1. Verify the HIP header length field
##        2. Save the HIP_SIGNATURE TLV and remove it from the packet
##        3. Recalculate the HIP packet length in the HIP header and
##           zero checksum field.
##        4. Compute the signature and verify it against the received
##           signature

##   The signature algorithms are defined in 3.4.6.

##   The verification can use either the HI received from a HIP packet or
##   the HI from a DNS query, if the FQDN has been received either in the
##   HOST_ID_FQDN or in the CER packet.

def makesig(head, tail, hi, recclass):
    head.csum = 0
    head.len = (head.size - 8 + len(tail))>>3
    sdata = ''.join([head.pack(), tail])
    sig = recclass(Algorithm=hi.Algorithm,
                      Sig=hi.sign(sdata)).pack()
    head.len = (head.size - 8 + len(tail) + len(sig))>>3
    return sig

def signpacket(head, tail, hi):
    #print 'signpacket'
    #print hexlify(sdata)
    sig = makesig(head, tail, hi, HIP_REC_SIG)
    #print 's', repr(sig)
    return ''.join([head.pack(), tail, sig])

##3.4.10 HIP_SIGNATURE_2

##   Zeroing the Initiator's HIT makes it possible to create R1 packets
##   beforehand to minimize the effects of possible DoS attacks.

##   Signature calculation and verification process: see the process in
##   3.4.9 HIP_SIGNATURE. Just replace the HIP_SIGNATURE with
##   HIP_SIGNATURE_2 and zero Initiator's HIT at the receiver's
##   end-point.

def signpacket2(head, tail, hi):
    head.remoteHIT, remoteHIT = '', head.remoteHIT
    #print 'signpacket2'
    #print hexlify(sdata)
    sig = makesig(head, tail, hi, HIP_REC_SIG2)
    #print 's2', repr(sig)
    head.remoteHIT = remoteHIT
    return ''.join([head.pack(), tail, sig])

def verifypacket(packet, hi, sigrec, head):
    print 'verifypacket'
    print hexlify(sigrec.pack()), sigrec.__dict__, repr(hi)
    h2 = head
    siglen = len(sigrec.pack())
    h2.len -= ((siglen+7)/8)
    if sigrec.__class__ == HIP_REC_SIG2:
        h2.remoteHIT = '\x00' * 16
    head = h2.pack()
    sdata = ''.join([head,
                     packet[len(head):-siglen]])
    print hexlify(sdata)
    v = hi.verify(sdata,sigrec.Sig)
    print "verifypacket:", v
    
    return v

def packetDump(result):
        (h, rest) = (HIPHeader(string=result), result[HIPHeader.size:])
        #print len(result), hexlify(result)
        print
##        print hexlify(result[:HIP_HEADER_LEN])
##        for i in range(0, len(rest), 32):
##            print '%4d' % i, hexlify(rest[i:i+32])
                       
##        print
        print 'nh:', h.nh
        print 'length:', h.len
        print 'type:', HIP_Packets[h.type]
        print 'magic:', h.magic
        print 'control:', h.control
        print 'csum:', h.csum
        print 'srcHIT:', hexlify(h.sourceHIT)
        print 'dstHIT:', hexlify(h.remoteHIT)
        if h.type in [1, 64]: return
        n = 0
        b = 0
        l=[]
        while rest:
            n += 1
            (t, v, rest) = HIPRec().unpack(rest)
            l.append(v)
            print str(v), '\n ', '\n  '.join(map(lambda x,y: ' = '.join([x,y]),
                                       v.__dict__.keys(),
                                       map(hexorrep, v.__dict__.values())))

def packXfrm(xfrms):
    return ''.join(map(lambda x: struct.pack('!H', x), xfrms))

def unpackXfrm(payload):
    return list(struct.unpack('!%dH' % (len(payload)>>1), payload))
                
def packRRset(RRset):
    RRset.sort()
    #pprint(RRset)
    tail = ''.join([RR.pack() for RR in RRset])
    return tail

def extractRRset(RRset, t):
    return [x[1] for x in RRset if x[1] == t]

def RRsetToAttrs(RRset, list, object):
    '''
    deep magic.  Takes an RRset, a list of (tag, attribute name)
    tuples and an object and assigns attributes of the object to lists of
    values from matching tuples in the RRset.
    The magic is how. (almost a metaclass hack)
    '''
    object.__dict__.update(dict([(attr,
                                  [x[1] for x in RRset if x[0] == t])
                                 for (t, attr) in list]))
    return object


class Message:
  def __init__(self, action, code): 
      self.action = action
      self.code = code
      self.controls = 0
  def __str__(self): return self.action
  def __cmp__(self, other):
      return cmp(self.action, other.action)
  # Necessary when __cmp__ or __eq__ is defined
  # in order to make this class usable as a
  # dictionary key:
  def __hash__(self): 
      return hash(self.action)


  ## TODO: refactor these into state machine.

  def DHdict(self, machine):
      if not(hasattr(machine.DH,'groupid')):
          machine.DH.groupid = machine.GroupIDgen.next()
##      print repr({'GroupID': machine.DH.groupid,
##                  'Prime': long_to_bytes(machine.DH.p),
##                  'Generator': long_to_bytes(machine.DH.g),
##                  'Public': long_to_bytes(machine.DH.y)})
      return {'GroupID': machine.DH.groupid,
              'Prime': long_to_bytes(machine.DH.p),
              'Generator': long_to_bytes(machine.DH.g),
              'Public': long_to_bytes(machine.DH.y)}

  def unDHdict(self, machine, dict, hit1, hit2, mode):
      if mode:
          machine.DH = DH.construct((bytes_to_long(dict['Prime']),
                                     bytes_to_long(dict['Generator'])))
          machine.DH.gen_key(RandomPool.get_bytes)
          machine.DH.groupid = dict['GroupID']
      machine.dhkey = long_to_bytes(
          machine.DH.decrypt((bytes_to_long(dict['Public']))))
      print 'unDHdict', mode, hexlify(machine.dhkey), hexlify(hit1), hexlify(hit2)
      return keymatgen(machine.dhkey, [hit1, hit2])

  def packDH(self, machine):
      # RFC2535: 0x0200 flags,
      #          0xff protocol (or IANA HIP value)
      #          0x02 algorithm DH (mandatory)
      # RFC2539: t=0x00
      RR = '\x02\x00\xff\x02\x00'
      # RFC2539: p g pub, each with length
      RR += packLV(long_to_bytes(machine.DH.p))
      RR += packLV(long_to_bytes(machine.DH.g))
      RR += packLV(long_to_bytes(machine.DH.y))
      return RR

  def unpackDH(self, machine, RR, hit1, hit2, mode):
      if RR[:5] <> '\x02\x00\xff\x02\x00':
          raise ValueError
      (p, rest) = unpackLV(RR[5:])
      (g, rest) = unpackLV(rest)
      (pub, rest) = unpackLV(rest)
      if mode:
          machine.DH = DH.construct((bytes_to_long(dict['Prime']),
                                     bytes_to_long(dict['Generator'])))
          machine.DH.gen_key(RandomPool.get_bytes)
      machine.dhkey = long_to_bytes(
          machine.DH.decrypt((bytes_to_long(dict['Public']))))
      return keymatgen(machine.dhkey, [hit1, hit2])

  def packEncrypted(self, machine, payload):
      if machine.HIPXfrm == ENCR_NULL:
          return payload
      (name, cipher, keylen, blocksize) = HIPXfrmTable[machine.HIPXfrm]
      print "HIP encrypt:", repr(cipher)
      print hexlify(payload)
      iv = RandomPool.get_bytes(blocksize)
      print "HIP encrypt:", hexlify(iv), hexlify(machine.hipkey)
      print "HIP encrypt:", hexlify(machine.remotehipkey)
      pad = '\00' * (blocksize - (len(payload)%blocksize))
      C=cipher.new(machine.hipkey, cipher.MODE_CBC, iv)
      r = ''.join([iv, C.encrypt(''.join((payload,pad)))])
      print hexlify(r)
      return r

  def unpackEncryptedPl(self, machine, payload):
      if machine.HIPXfrm == ENCR_NULL:
          return payload
      (name, cipher, keylen, blocksize) = HIPXfrmTable[machine.HIPXfrm]
      print "HIP decrypt:", repr(cipher)
      print hexlify(payload)
      iv = payload[:blocksize]
      print "HIP decrypt:", hexlify(iv), hexlify(machine.remotehipkey)
      print "HIP decrypt:", hexlify(machine.hipkey)
      C=cipher.new(machine.remotehipkey, cipher.MODE_CBC, iv)
      r = C.decrypt(payload[blocksize:])
      print hexlify(r)
      return r

  def unpackEncrypted(self, machine, payload):
      rest = self.unpackEncryptedPl(machine, payload)
      l=[]
      while rest:
          (t, v, rest) = unpackTLV(rest)
          ops = [(HIP_REC_HIP_TRANSFORM, unpackXfrm),
                 (HIP_REC_ESP_TRANSFORM, unpackXfrm)
                 #(HIP_REC_ESP_AUTH_TRANSFORM, unpackXfrm)
                 ]
          try:
              v = apply([x[1] for x in ops if x[0] == t][0], [v])
          except IndexError:
              pass
          l.append((t, v))
      return l





class I1Message(Message):
    '''
    4.1. I1 - the HIP Initiator packet

       +----------------------+
       | Fixed Header         |
       +----------------------+

       Header:
         Packet Type = 1
    '''
    def __init__(self):
        Message.__init__(self, 'I1', 1)
    def pack(self, machine):
        head = HIPHeader(nh=machine.piggybackProtocol,
                         len=4,
                         type = self.code,
                         control=machine.controls,
                         sourceHIT = machine.localHIT,
                         remoteHIT = machine.remoteHIT)
        return head.pack()
    def input(self, machine, header, RRset):
        #machine.remoteHIT = header.sourceHIT
        if header.remoteHIT == HI.zeroHIT:
            print 'Detected opportunistic connection'
##            raise HIPNewConnection, header.sourceHIT
##        if header.remoteHIT <> machine.localHIT:
##            raise HIPUnpackError, ('Not local HIT '
##                                   + hexlify(header.remoteHIT) + ' '
##                                   + hexlify(machine.localHIT))
##        if (hasattr(machine, 'remoteHIT')
##            and header.sourceHIT <> machine.remoteHIT):
##            print 'Detected new connection'
##            raise HIPNewConnection, header.sourceHIT
        try:
            machine.remoteHI=HI.HI.HITable[header.sourceHIT]
        except:
            print 'Detected new connection'
            #raise HIPNewConnection, header.sourceHIT
        return 1
        


class R1Message(Message):
    '''
    4.2. R1 - the HIP Responder packet

       +----------------------+
       | Fixed Header         |
       +----------------------+
       | BIRTHDAY_COOKIE      |
       +----------------------+
       | DIFFIE_HELLMAN       |
       +----------------------+
       | HIP_TRANSFORM        |
       +----------------------+
       | ESP_TRANSFORM        |
       +----------------------+
       | HOST_ID |            |
       | HOST_ID_FQDN         |
       +----------------------+
       | HIP_SIGNATURE_2      |
       +----------------------+

       Header:
         Packet Type = 2

       IP ( HIP ( BIRTHDAY_COOKIE,
                  DIFFIE_HELLMAN,
                  HIP_TRANSFORM,
                  ESP_TRANSFORM,
                  ( HOST_ID | HOST_ID_FQDN ),
                  HIP_SIGNATURE_2 ) )
    '''
    def __init__(self):
        Message.__init__(self, 'R1', 2)
    def pack(self, machine):
        dhdict = self.DHdict(machine)
        if DHGroups.has_key(dhdict['GroupID']):
            dhrec = HIP_REC_DH(**dhdict)
        else:
            dhrec = HIP_REC_DH_FULL(**dhdict)
        RRset = [HIP_REC_HI(Algorithm=machine.HI.Algorithm,
                             Identity=machine.HI.pack()),
                 dhrec,
                 HIP_REC_BIRTHDAY_COOKIE_R1(Birthday=machine.birthday,
                                            I=machine.Cookie.I,
                                            JK=struct.pack('!Q',
                                                           machine.Cookie.K),
                                            Target=machine.Cookie.cookie),
                 HIP_REC_HIP_TRANSFORM(HIPXfrm=machine.HIPXfrmList),
                 HIP_REC_ESP_TRANSFORM(ESPXfrm=machine.ESPXfrmList),
                 ]
        head = HIPHeader(nh=machine.piggybackProtocol,
                         len=0,
                         type = self.code,
                         control=machine.controls,
                         sourceHIT = machine.localHIT,
                         remoteHIT = machine.remoteHIT)
        tail = packRRset(RRset)
        return signpacket2(head, tail, machine.HI)
    def input(self, machine, header, RRset):
        body=Body(RRset)
        # todo: handle controls
        machine.remoteHI = HI.HI(Rec=body.HOST_ID.Identity)
        machine.Cookie.stored = HIPCookie.HIPCookie(
            I=body.BIRTHDAY_COOKIE.I,
            K=struct.unpack('!Q', body.BIRTHDAY_COOKIE.JK)[0],
            cookie=body.BIRTHDAY_COOKIE.Target,
            hits=''.join([machine.localHIT,
                          machine.remoteHIT]))
        remoteBirthday = body.BIRTHDAY_COOKIE.Birthday
        if hasattr(machine,'remoteBirthday'):
            if machine.remoteBirthday <> remoteBirthday:
                # it rebooted, bang it on the head
                # not right.
                #machine.send(I2)
                pass
        machine.remoteBirthday = remoteBirthday
        # in both cases, take the first we're configured to support
        machine.HIPXfrm = [x
                           for x in body.HIP_TRANSFORM.HIPXfrm + [ENCR_3DES]
                           if x in machine.HIPXfrmList][0]
        machine.ESPXfrm = [x
                           for x in body.ESP_TRANSFORM.ESPXfrm + [ESP_3DES_CBC_HMAC_SHA1]
                           if x in machine.ESPXfrmList][0]
        # allocate LSI
        machine.remoteLSI = machine.LSIgen.next()
        # allocate SPI
        machine.remoteSPI = machine.SPIgen.next()
        # Extract HIP keymat.  We're initiator.
        try:
            dhdict = body.DH_FULL.__dict__
        except AttributeError:
            dhdict = {}
            dhdict.update(body.DIFFIE_HELLMAN.__dict__)
            dhdict.update(DHGroups[body.DIFFIE_HELLMAN.GroupID])
            #print 'Got DH', dhdict
        machine.keygenerator=self.unDHdict(machine,
                                           dhdict,
                                           machine.localHIT,
                                           machine.remoteHIT,
                                           1)
        kl = HIPXfrmTable[machine.HIPXfrm][2]
        machine.drawHIPkeys(kl, 1)
        # extract ESP keys and set up SA
        machine.ESPalg = ESPXfrmTable[machine.ESPXfrm]
        (alg, keylen, blocksize,
         authalg, authkeylen, authlen) = ESP.ESPAlgTable[machine.ESPalg]
        machine.drawESPkeys(keylen, authkeylen, 1)
        return 1

class I2Message(Message):
    '''
    4.3. I2 - the HIP Second Initiator packet

       +----------------------+
       | Fixed Header         |
       +----------------------+
       | SPI_LSI              |
       +----------------------+
       | BIRTHDAY_COOKIE      |
       +----------------------+
       | DIFFIE_HELLMAN       |
       +----------------------+
       | HIP_TRANSFORM        |
       +----------------------+
       | ESP_TRANSFORM        |
       +----------------------+
       | ENCRYPTED            |
       +----------------------+
       | HIP_SIGNATURE        |
       +----------------------+

       Header:
         Packet Type = 3

       IP ( HIP ( SPI_LSI,
                  BIRTHDAY_COOKIE,
                  DIFFIE_HELLMAN,
                  HIP_TRANSFORM,
                  ESP_TRANSFORM,
                  ENCRYPTED { HOST_ID | HOST_ID_FQDN },
                  HIP_SIGNATURE ) )

       The HOST_ID or the HOST_ID_FQDN field is encrypted and it is as a
       payload in the ENCRYPTED field.
    '''
    def __init__(self):
        Message.__init__(self, 'I2', 3)
    def pack(self, machine):
        encRRset = [HIP_REC_HI(Algorithm=machine.HI.Algorithm,
                               Identity=machine.HI.pack())]
        machine.Cookie.puzzle2(machine.Cookie.stored.I,
                               machine.Cookie.stored.K,
                               machine.Cookie.stored.cookie)
        dhdict = self.DHdict(machine)
        if DHGroups.has_key(dhdict['GroupID']):
            dhrec = HIP_REC_DH(**dhdict)
        else:
            dhrec = HIP_REC_DH_FULL(**dhdict)
        RRset = [HIP_REC_BIRTHDAY_COOKIE_I2(Birthday=machine.birthday,
                                            I=machine.Cookie.I,
                                            JK=machine.Cookie.J,
                                            Target=machine.Cookie.cookie),
                 HIP_REC_SPI_LSI(LSI=machine.remoteLSI,
                                 SPI=machine.remoteSPI),
                 dhrec,
                 HIP_REC_HIP_TRANSFORM(HIPXfrm=[machine.HIPXfrm]),
                 HIP_REC_ESP_TRANSFORM(ESPXfrm=[machine.ESPXfrm]),
                 HIP_REC_ENCRYPTED(
            Encrypted=self.packEncrypted(machine,
                                         packRRset(encRRset)))
                 ]
        head = HIPHeader(nh=machine.piggybackProtocol,
                         len=0,
                         type = self.code,
                         control=machine.controls,
                         sourceHIT = machine.localHIT,
                         remoteHIT = machine.remoteHIT)
        tail = packRRset(RRset)
        return signpacket(head, tail, machine.HI)
    def input(self, machine, header, RRset):
        body=Body(RRset)
#        for i in body.__dict__.keys():
#            print i, repr(body.__dict__[i].__dict__)
        # todo: handle controls
        remoteBirthday = body.BIRTHDAY_COOKIE.Birthday
        if hasattr(machine,'remoteBirthday'):
            if machine.remoteBirthday <> remoteBirthday:
                # it rebooted, bang it on the head
                # todo
                pass
##        if machine.remoteHIT <> bod.keylist.pop(0):
##            # we just got to check this under the sig
##            raise HIPUnpackError, 'remote gave us inconsistent HIT'
        if not machine.Cookie.cookieOp(machine.Cookie.I,
                                       body.BIRTHDAY_COOKIE.JK,
                                       machine.Cookie.K):
            print "Cookie puzzle failure"
        else:
            print "Cookie puzzle pass"
            #raise HIPUnpackError, 'Bad Cookie'
        # in both cases, take the first we're configured to support
        machine.HIPXfrm = [x
                           for x in body.HIP_TRANSFORM.HIPXfrm + [ENCR_3DES]
                           if x in machine.HIPXfrmList][0]
        machine.localLSI = body.SPI_LSI.LSI
        machine.localSPI = body.SPI_LSI.SPI
        # allocate LSI
        machine.remoteLSI = machine.LSIgen.next()
        if hasattr(machine, 'LSIcallback') and callable(machine.LSIcallback):
            machine.LSIcallback(machine)
        # allocate SPI
        machine.remoteSPI = machine.SPIgen.next()
        # extract HIP keymat.  We're rESPonder.
        try:
            dhdict = body.DH_FULL.__dict__
        except AttributeError:
            dhdict = {}
            dhdict.update(body.DIFFIE_HELLMAN.__dict__)
            try:
                dhdict.update(DHGroups[body.DIFFIE_HELLMAN.GroupID])
            except:
                print "Invalid GroupID received"
                raise
        print 'Got DH', dhdict
        machine.keygenerator=self.unDHdict(machine,
                                           dhdict,
                                           machine.localHIT,
                                           machine.remoteHIT,
                                           0)
        #print repr(machine.HIPXfrm)
        kl = HIPXfrmTable[machine.HIPXfrm][2]
        machine.drawHIPkeys(kl, 0)
        try:
            # now unpack the encrypted record
            rest = self.unpackEncryptedPl(machine, body.Encrypted.Encrypted)
            l = []
            while rest:
                (t, v, rest) = HIPRec().unpack(rest)
                l.append(v)
            body.__dict__.update(dict([(x.name, x) for x in l]))
            #if not hasattr(machine, 'remoteHI'):
            machine.remoteHI = HI.HI(Rec=body.HOST_ID.Identity)
        except:
            raise
        # default if we don't support initiator's choice
        machine.ESPXfrm = [x
                           for x in body.ESP_TRANSFORM.ESPXfrm + [ESP_3DES_CBC_HMAC_SHA1]
                           if x in machine.ESPXfrmList][0]
        # extract ESP keys and set up SA
        machine.ESPalg = ESPXfrmTable[machine.ESPXfrm]
        (alg, keylen, blocksize,
         authalg, authkeylen, authlen) = ESP.ESPAlgTable[machine.ESPalg]
        machine.drawESPkeys(keylen, authkeylen, 0)
        machine.makeRemoteSPI(blocksize)
        machine.makeLocalSPI(blocksize)
        return 1
        

class R2Message(Message):
    '''
    4.4. R2 - the HIP Second Responder packet

       +----------------------+
       | Fixed Header         |
       +----------------------+
       | SPI_LSI              |
       +----------------------+
       | HIP_SIGNATURE        |
       +----------------------+

       Header:
         Packet Type = 4

       IP ( HIP ( SPI_LSI,
                  HIP_SIGNATURE ) )
    '''
    def __init__(self):
        Message.__init__(self, 'R2', 4)
    def pack(self, machine):
        #machine.remoteSPI = machine.SPIgen.next()
        RRset = [HIP_REC_SPI_LSI(SPI=machine.remoteSPI,
                                 LSI=machine.remoteLSI)]         
        head = HIPHeader(nh=machine.piggybackProtocol,
                         len=0,
                         type = self.code,
                         control=machine.controls,
                         sourceHIT = machine.localHIT,
                         remoteHIT = machine.remoteHIT)
        tail = packRRset(RRset)
        return signpacket(head, tail, machine.HI)
    def input(self, machine, header, RRset):
        body=Body(RRset)
        #for i in body.__dict__.keys():
        #    print i, repr(body.__dict__[i].__dict__)
        # todo: handle controls
        machine.localLSI = body.SPI_LSI.LSI
        machine.localSPI = body.SPI_LSI.SPI
        if hasattr(machine, 'LSIcallback') and callable(machine.LSIcallback):
            machine.LSIcallback(machine)
        machine.ESPalg = ESPXfrmTable[machine.ESPXfrm]
        (alg, keylen, blocksize,
         authalg, authkeylen, authlen) = ESP.ESPAlgTable[machine.ESPalg]
        machine.makeLocalSPI(blocksize)
        machine.makeRemoteSPI(blocksize)
        return 1
        
class BOSMessage(Message):
    '''
    4.7. BOS - the HIP Bootstrap Packet

       +----------------------+
       | Fixed Header         |
       +----------------------+
       | HOST_ID |            |
       | HOST_ID_FQDN         |
       +----------------------+
       | HIP_SIGNATURE        |
       +----------------------+

       Header:
         Packet Type = 7

       IP ( HIP ( ( HOST_ID | HOST_ID_FQDN ),
                  HIP_SIGNATURE ) )
    '''
    def __init__(self):
        Message.__init__(self, 'BOS', 7)
    def pack(self, machine):
        RRset = [HIP_REC_HI(Algorithm=machine.HI.Algorithm,
                             Identity=machine.HI.pack())]
        head = HIPHeader(nh=machine.piggybackProtocol,
                         len=0,
                         type = self.code,
                         control=machine.controls,
                         sourceHIT = machine.localHIT,
                         remoteHIT = machine.remoteHIT)
        tail = packRRset(RRset)
        return signpacket(head, tail, machine.HI)
    def input(self, machine, header, RRset):
        body=Body(RRset)
        newHI = HI.HI(Rec=body.HOST_ID.Identity)
        # sanity check
        if newHI.HIT127() == header.sourceHIT:
            HI.HI.HITable[header.sourceHIT] = newHI
            machine.remoteHI = newHI
            machine.remoteHIT = header.sourceHIT

class REAMessage(Message):
    '''
    4.6. REA - the HIP Readdress Packet

       +----------------------+
       | Fixed Header         |
       +----------------------+
       | REA_INFO             |
       +----------------------+
       | HIP_SIGNATURE        |
       +----------------------+

       Header:
         Packet Type = 6


       IP ( HIP ( REA_INFO,
                  HIP_SIGNATURE ) )
    '''
    def __init__(self):
        Message.__init__(self, 'REA', 6)
    def pack(self, machine):
        RRset = [HIP_REC_REA_INFO(Interface=machine.Interface,
                                  SPI=machine.remoteESP.SPI,
                                  RevSPI=machine.localESP.SPI,
                                  NewSPI=machine.newspi,
                                  interfaces=machine.interfaces,
                                  KeyInd=machine.nextkeyind,
                                  REAID=machine.nextreaid)]
        head = HIPHeader(nh=machine.piggybackProtocol,
                         len=0,
                         type = self.code,
                         control=machine.controls,
                         sourceHIT = machine.localHIT,
                         remoteHIT = machine.remoteHIT)
        tail = packRRset(RRset)
        return signpacket(head, tail, machine.HI)
    def input(self, machine, header, RRset):
        body=Body(RRset)
        #for i in body.__dict__.keys():
        #    print i, repr(body.__dict__[i].__dict__)
        machine.remoteREAID = Body.REA_INFO.REAID
        machine.send(AC)


class NESMessage(Message):
    '''
    4.5. NES - the HIP New SPI Packet

       +----------------------+
       | Fixed Header         |
       +----------------------+
       | NEW_SPI              |
       +----------------------+
       | DIFFIE_HELLMAN (opt) |
       +----------------------+
       | HIP_SIGNATURE        |
       +----------------------+

       Header:
         Packet Type = 5


       IP ( HIP ( NEW_SPI
                  [ ,DIFFIE_HELLMAN ],
                  HIP_SIGNATURE ) )
    '''
    def __init__(self):
        Message.__init__(self, 'NES', 5)
    def pack(self, machine):
        # assume ESP is held if necessary when we get here
        # or that we're turning around immediately
        # also assume DH key was regenerated elsewhere
        # SN is preincrement
        SN = machine.remoteESP.SN + 1
        machine.localSPI =  StateMachine.SPIgen.next()
        dhdict = self.DHdict(machine)
        if DHGroups.has_key(dhdict['GroupID']):
            dhrec = HIP_REC_DH(**dhdict)
        else:
            dhrec = HIP_REC_DH_FULL(**dhdict)
        RRset = [HIP_REC_NEW_SPI(ESP_SN=SN,
                                 OldSPI=machine.localESP.SPI,
                                 NewSPI=machine.remoteSPI),
                 dhrec]
        head = HIPHeader(nh=machine.piggybackProtocol,
                         len=0,
                         type = self.code,
                         control=machine.controls,
                         sourceHIT = machine.localHIT,
                         remoteHIT = machine.remoteHIT)
        tail = packRRset(RRset)
        return signpacket(head, tail, machine.HI)
    def input(self, machine, header, RRset):
        body=Body(RRset)
        SN = body.NEW_SPI.ESP_SN
        machine.remoteSPI = body.NEW_SPI.NewSPI
        try:
            try:
                dhdict = body.DH_FULL.__dict__
            except AttributeError:
                dhdict = {}
                dhdict.update(body.DIFFIE_HELLMAN.__dict__)
                dhdict.update(DHGroups[body.DIFFIE_HELLMAN.GroupID])
                #print 'Got DH', dhdict
            machine.keygenerator=self.unDHdict(machine,
                                               dhdict,
                                               machine.localHIT,
                                               machine.remoteHIT,
                                               0)
        except AttributeError:
            # AttributeError means no DH_FULL in the packet
            # Ok, we were not passed a DH, therefore we already have
            # the keymat. note that I think we have a bug here; is this
            # correct when we generated a new DH key when sending?
            print "NES: This shouldn't happen!"
            machine.dhkey = long_to_bytes(
                machine.DH.decrypt((bytes_to_long(dict['Public']))))
            machine.keygenerator = keymatgen(machine.dhkey,
                                             [machine.localHIT,
                                              machine.remoteHIT])
            DHpassed = 0
            pass
        #if not machine.rekeying:
            # unsolicited NES, must reply
            # always do this
            # now doing this in advance
            # machine.DH.gen_key(RandomPool.get_bytes)
            #pass
        # OK, we've got our reply
        # keygen is primed, so here we go
        (alg, keylen, blocksize,
         authalg, authkeylen, authlen) = ESP.ESPAlgTable[machine.ESPalg]
        machine.drawESPkeys(keylen, authkeylen, machine.rekeying)
        if machine.rekeying:
            machine.rekeying = 0
        else:
            # unsolicited NES, must reply
            # do this here, NOT in the states!
            # that would NES loop forever :-)
            machine.send(NES)
        machine.makeLocalSPI(blocksize)
        machine.makeRemoteSPI(blocksize)
                 

class ACMessage(Message):
    '''
    6.1.2 AC and ACR - the HIP Address Check and Address Check Reply

       The HIP Address Check (AC) and Address Check Reply (ACR) packets
       contain an AC_INFO payload, followed by a HMAC.

       In addition to acting as an address probe, the Address Check packet
       may also acts as an implicit acknowledgement to a REA packet.
    '''
    def __init__(self):
        Message.__init__(self, 'AC', 32)
    def pack(self, machine):
        RRset = [HIP_REC_AC_INFO(ACID=0,
                                 REAID=machine.remoteREAID,
                                 Timestamp=0)]
        head = HIPHeader(nh=machine.piggybackProtocol,
                         len=0,
                         type = self.code,
                         control=machine.controls,
                         sourceHIT = machine.localHIT,
                         remoteHIT = machine.remoteHIT)
        tail = packRRset(RRset)
        return signpacket(head, tail, machine.HI)
    def input(self, machine, header, RRset):
        body=Body(RRset)
        machine.remoteACID = Body.AC_INFO.ACID
        return 1
        
class ACRMessage(Message):
    '''
    6.1.2 AC and ACR - the HIP Address Check and Address Check Reply

       The HIP Address Check (AC) and Address Check Reply (ACR) packets
       contain an AC_INFO payload, followed by a HMAC.

       In addition to acting as an address probe, the Address Check packet
       may also acts as an implicit acknowledgement to a REA packet.
    '''
    def __init__(self):
        Message.__init__(self, 'ACR', 33)
    def pack(self, machine):
        RRset = [HIP_REC_AC_INFO(ACID=machine.remoteACID,
                                 REAID=0,
                                 Timestamp=0)]
        head = HIPHeader(nh=machine.piggybackProtocol,
                         len=0,
                         type = self.code,
                         control=machine.controls,
                         sourceHIT = machine.localHIT,
                         remoteHIT = machine.remoteHIT)
        tail = packRRset(RRset)
        return signpacket(head, tail, machine.HI)
    def input(self, machine, header, RRset):
        body=Body(RRset)
        return 1



class PAYLOADMessage(I1Message):
    '''
    4.9. PAYLOAD - the HIP Payload Packet

       +----------------------+
       | Fixed Header         |
       +----------------------+
       | payload              |
       +----------------------+

       Header:
         Packet Type = 64

       IP ( HIP ( payload ) )

       Payload Proto field in the Header MUST be set to correspond
       the correct protocol number of the payload.

       The PAYLOAD packet is used to carry a non-ESP protected data. By
       using HIP header we ensure interoperability with NAT and other
       middle boxes.
    '''
    def __init__(self):
        Message.__init__(self, 'PAYLOAD', 64)
        


class ESPMessage(Message):
    def __init__(self):
        Message.__init__(self, 'ESP', 0)


I1 = I1Message()
R1 = R1Message()
I2 = I2Message()
R2 = R2Message()
REA = REAMessage()
AC = ACMessage()
ACR = ACRMessage()
BOS = BOSMessage()
NES = NESMessage()
PAYLOAD = PAYLOADMessage()
ESPM = ESPMessage()

Message.dispatchlist = {1: I1,
                        2: R1,
                        3: I2,
                        4: R2,
                        5: NES,
                        6: REA,
                        7: BOS,
                        64: PAYLOAD}

