import struct
import operator

from binascii import hexlify, unhexlify
from functools import reduce

IPheader      = '!BBHHHBBH4s4s'
IPheader_len  = struct.calcsize(IPheader)

def packLV(Value):
    length=len(Value)
    # calculate padding to build format string
    (paddedlength, pad) = divmod(len(Value), 4)
    if pad != 0:
        paddedlength += 1
    paddedlength     *= 4
    formatstring = '!H%ds' % paddedlength
    return struct.pack(formatstring, length, Value)

def unpackLV(payload):
    # wierd single element tuple constructor follows...
    (length,) = struct.unpack('!H', payload[:2])
    (paddedlength, pad) = divmod(length, 4)
    if pad != 0:
        paddedlength += 1
    paddedlength     *= 4
    return (payload[2:2+length], payload[2+paddedlength:])

def packTLV(Tag, Value):
    try:
        length=len(Value)
    except TypeError:
        Value=struct.pack('B', Value)
        length=1
    return (struct.pack('!HH', Tag, length)
            + Value + '\x00'*(7-(length+3)%8))

def unpackTLV(payload):
    (tag, length) = struct.unpack('!HH', payload[:4])
    paddedlength = length + (7-(length+3)%8)
##    paddedlength = length + ((8-(length+4)&7)&7)
    return (tag,
            payload[4:4+length],
            payload[4+paddedlength:])

def fixULPChecksum(packet):
    # evil assumptions: no IP options, IPv4
    pseudopkt = ''.join([packet[:IPheader_len][-8:],
                         '\x00',
                         packet[:IPheader_len][-11],
                         struct.pack('!H', len(packet) - IPheader_len),
                         packet[IPheader_len:IPheader_len+16],
                         '\x00\x00',
                         packet[IPheader_len+18:],
                         '\x00'[0:(len(packet) & 1)]])
    csum = reduce(operator.add,
                  struct.unpack('!%dH' % (len(pseudopkt)>>1),
                                pseudopkt))
    csum = (csum>>16) + (csum&0xffff)
    csum += (csum>>16)
    csum = (csum&0xffff)^0xffff
    return ''.join([packet[:IPheader_len+16],
                    struct.pack('!H', csum),
                    packet[IPheader_len+18:]])

def HIPChecksum(packet, Saddr, Daddr, nh):
    # Checksum for the HIP header.
    # Assume packet has no IP header, but does have HIP header
    # zero the checksum first
    pseudopkt = ''.join([Saddr,
                         Daddr,
                         struct.pack('!L', len(packet)),
                         #struct.pack('!L',(ord(packet[1])+1)<<3),
                         '\x00\x00\x00',
                         chr(nh),
                         packet[:6],
                         '\x00\x00',
                         packet[8:],
                         '\x00'[0:(len(packet) & 1)]])
    print("HIPChecksum:", hexlify(pseudopkt), len(pseudopkt), len(packet))
    l = struct.unpack('!%dH' % (len(pseudopkt)>>1),
                      pseudopkt)
    csum = reduce(operator.add,
                  l)
    csum = (csum>>16) + (csum&0xffff)
    csum += (csum>>16)
    csum = (csum&0xffff)^0xffff
    return ''.join([packet[:6],
                    struct.pack('!H', csum),
                    packet[8:]])
