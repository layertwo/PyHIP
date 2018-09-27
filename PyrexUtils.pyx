import struct
IP6Header = '!LHBB16s16s'
IP6Header_len  = struct.calcsize(IP6Header)

cdef extern from "netinet/in.h":
    unsigned int htonl(unsigned int hostlong)
    unsigned short htons(unsigned short hostshort)
    unsigned int ntohl(unsigned int netlong)
    unsigned short ntohs(unsigned short netshort)



cdef extern from "Python.h":
    object PyString_FromStringAndSize(char *s, int len)
    int PyString_AsStringAndSize(object obj, char **buffer, int *length)
    int PyString_Check(object o)
    
cdef extern from "stdlib.h":
    void *calloc(unsigned int nmemb, unsigned int size)
    void *malloc(unsigned int size)
    void free(void *ptr)

cdef extern from "string.h":
    void *memcpy(void *dest, void *src, int n)

def packLV(Value):
    cdef int length
    cdef int i
    cdef char *valbuf, *buf
    cdef int paddedlength, pad

    PyString_AsStringAndSize(Value, &valbuf, &length)

    paddedlength = length / 4
    pad = length % 4
    if pad != 0:
        paddedlength = paddedlength + 1
    paddedlength = paddedlength * 4
    buf = <char *> calloc(paddedlength+2, 1)
    (<unsigned short *> buf)[0] = htons(<unsigned short> length)
    memcpy(buf+2, valbuf, length)
    r = PyString_FromStringAndSize(buf, paddedlength+2)
    free(buf)
    return r

def unpackLV(payload):
    cdef unsigned short length, paddedlength, pad
    cdef int payloadlength
    cdef char *paybuf

    PyString_AsStringAndSize(payload, &paybuf, &payloadlength)

    length = ntohs((<unsigned short*>paybuf)[0])
    paddedlength = length / 4
    pad = length % 4
    if pad != 0:
        paddedlength = paddedlength + 1
    paddedlength = paddedlength * 4
    return (PyString_FromStringAndSize(paybuf + 2, length),
            PyString_FromStringAndSize(paybuf + paddedlength + 2,
                                       payloadlength - paddedlength -2))

def packTLV(Tag, Value):
    cdef unsigned short ctag 
    cdef int totallength, length
    cdef char *paybuf, *valbuf
    ctag = Tag
    if not PyString_Check(Value):
        Value=struct.pack('B', Value)
    PyString_AsStringAndSize(Value, &valbuf, &length)
    
    totallength = (((length+3) / 8) + 1) * 8
    paybuf = <char *> calloc(totallength, 1)
    (<unsigned short *> paybuf)[0] = htons(ctag)
    (<unsigned short *> paybuf)[1] = htons(<unsigned short> length)
    memcpy(paybuf+4, valbuf, length)
    r = PyString_FromStringAndSize(paybuf, totallength)
    free(paybuf)
    return r


def unpackTLV(payload):
    cdef unsigned short tag, length, paddedlength
    cdef char *paybuf
    cdef int l
    l = len(payload)
    paybuf = payload
    tag = ntohs((<unsigned short *>paybuf)[0])
    length = ntohs((<unsigned short *>paybuf)[1])
    paddedlength = length + (7-(length+3)%8)
    return (tag,
            PyString_FromStringAndSize(paybuf + 4, <int> length),
            PyString_FromStringAndSize(paybuf + 4 + paddedlength,
                                       l - 4 - paddedlength))


def fixULPChecksum(packet):
    cdef int plength, csum, i
    cdef unsigned short ncsum
    cdef char *packetbuf, *paybuf
    PyString_AsStringAndSize(Value, &packetbuf, &plength)
    # evil assumptions: no IP options, IPv4
##    pseudopkt = ''.join([packet[:IPheader_len][-8:],
##                         '\x00',
##                         packet[:IPheader_len][-11],
##                         struct.pack('!H', len(packet) - IPheader_len),
##                         packet[IPheader_len:IPheader_len+16],
##                         '\x00\x00',
##                         packet[IPheader_len+18:]]
##                        + [x for x in ['\x00'] if len(packet) & 1])
##    csum = reduce(operator.add,
##                  struct.unpack('!%dH' % (len(pseudopkt)>>1),
##                         pseudopkt))
    csum = 0
    for i from 6 <= i < 10:
        csum = csum + ntohs((<unsigned short *> packetbuf)[i])
    csum = csum + packetbuf[9] + ntohs(<unsigned short> (plength - 20))
    #i=0
    for i from 10 <= i < 18:
        csum = csum + ntohs((<unsigned short *> packetbuf)[i])
    #i=0
    for i from 20 <= i < (plength >> 1):
        csum = csum + ntohs((<unsigned short *> packetbuf)[i])
    # do the last byte
    if plength & 1:
        csum = csum + (<int> (packetbuf[plength-1]))<<8
    csum = (csum>>16) + (csum&0xffff)
    csum = csum + (csum>>16)
    csum = (csum&0xffff)^0xffff
    ncsum = htons(<unsigned short> csum)

    paybuf = <char *> calloc(plength, 1)
    memcpy(paybuf, packetbuf, plength)
    memcpy(paybuf + 36, &ncsum, 2)
    s = PyString_FromStringAndSize(paybuf, plength)
    free(paybuf)
    return s


##    return ''.join([packet[:IPheader_len+16],
##                    struct.pack('!H', csum),
##                    packet[IPheader_len+18:]])

##def HIPChecksum(packet, Saddr, Daddr):
##    cdef int plength, csum, i
##    cdef char *packetbuf
    
##    # Checksum for the HIP header.
##    # Assume packet has no IP header, but does have HIP header
##    # zero the checksum first
####    pseudopkt = ''.join([Saddr,
####                         Daddr,
####                         struct.pack('!L',(ord(packet[1])+1)<<3),
####                         '\x00\x00\x00\x32',
####                         packet[:6],
####                         '\x00\x00',
####                         packet[8:]]
####                        + [x for x in ['\x00'] if len(packet) & 1])
##    csum = 0
##    PyString_AsStringAndSize(Saddr, &packetbuf, &plength)
##    i = 0
##    for i from 0 <= i < (plength >> 1):
##        csum = csum + ntohs((<unsigned short *> packetbuf)[i])
##    PyString_AsStringAndSize(Daddr, &packetbuf, &plength)
##    i = 0
##    for i from 0 <= i < (plength >> 1):
##        csum = csum + ntohs((<unsigned short *> packetbuf)[i])
##    csum = csum + (<int> (packetbuf[1]+1))<<3 + 0x32
##    PyString_AsStringAndSize(packet, &packetbuf, &plength)
##    i = 0
##    for i from 0 <= i < (plength >> 1):
##        if i = 3:
##            continue
##        csum = csum + ntohs((<unsigned short *> packetbuf)[i])
##    # do the last byte
##    if plength & 1:
##        csum = csum + (<int> (packetbuf[plength-1]))<<8

##    csum = (csum>>16) + (csum&0xffff)
##    csum = csum + (csum>>16)
##    csum = (csum&0xffff)^0xffff

##    r = PyString_FromStringAndSize(packetbuf, plength)
##    # move packetbuf to pointing into the new string's buffer
##    packetbuf = r
##    ((<unsigned short *> (packetbuf))[3]) = htons(<unsigned short> csum)
##    return r

####    csum = reduce(operator.add,
####                  struct.unpack('!%dH' % (len(pseudopkt)>>1),
####                         pseudopkt))
####    csum = (csum>>16) + (csum&0xffff)
####    csum += (csum>>16)
####    csum = (csum&0xffff)^0xffff
####    return ''.join([packet[:6],
####                    struct.pack('!H', csum),
####                    packet[8:]])
