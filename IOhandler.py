from __future__ import generators
import threading
import gc
import traceback
import struct
import sys
from getopt import getopt
import string
import os
import copy
import libnet
import operator
import socket
socket.IP_HDRINCL = 3
socket.SOL_RAW = 255

from select import select
from fcntl import ioctl
from binascii import hexlify, unhexlify
from array import array
from pprint import pformat
import Queue

import ESP
import weakref
from HIPutils import *
import HIPState
import HIPOptMessage
import DH
import HI
import IPAddress
from Future import Future

import time
import ipqueue

Memoize(libnet.name_resolve)
Memoize(IPAddress.IPv6_ntoa)


# don't use this directly, it's supposed to be subclassed!
# subclasses should define:
# OpenSocket(address) -> socket
# WorkHandler(r) where r is (pkt, addr) 


class RawSocketIOHandler(object, IPhandler):
    def __init__(self,
                 address):
        self.OutQueue = Queue.Queue(4)

    def Writer(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(0, socket.IP_HDRINCL, 1)
        s6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
        #s6.setsockopt(0, socket.IP_HDRINCL, 1)
        p = libnet.packet()
        q = self.OutQueue
        while 1:
            #print self.__class__, 'Writer'
            stack, pkt, nextheader, daddr = q.get()
            if stack == 4:
                #print "RawSocketIOHandler writing to v4:", hexlify(pkt), IPAddress.IPv6_ntoa(daddr), nextheader
                s.sendto(pkt, (IPAddress.IPv6_ntoa(daddr), nextheader)), socket.inet_ntoa(daddr), nextheader
            else:
                #print "RawSocketIOHandler writing to v6:", hexlify(pkt), IPAddress.IPv6_ntoa(daddr), nextheader
                s6.sendto(pkt, (IPAddress.IPv6_ntoa(daddr), nextheader))

    def run(self):
        self.WriterThread = threading.Thread(target = self.Writer,
                                             args = [])
        self.WriterThread.setDaemon(1)
        self.WriterThread.start()


class SocketIOHandler(object, IPhandler):
    def __init__(self,
                 address,
                 af=socket.AF_INET):
        self.OutQueue = Queue.Queue(4)
        self.Socket = self.OpenSocket(address, af)

    def Reader(self):
        s = self.Socket
        WorkHandler = self.WorkHandler
        while 1:
            #print self.__class__, 'Reader'
            try:
                r = s.recvfrom(70000)
                #print self.__class__, "Socket gave:", hexlify(r[0]), repr(r[1])
            except socket.error:
                continue
            WorkHandler(r)

    def Writer(self):
        s = self.Socket
        p = libnet.packet()
        q = self.OutQueue
        while 1:
            #print self.__class__, 'Writer'
            payload, r, l = q.get()
            R = libnet.name_resolve(r[0],0)
            L = libnet.name_resolve(l[0],0)
            p.payload=payload
            p.build_ip(len(p),
                       0,
                       1,
                       0,
                       255,
                       l[1],
                       L,
                       R)
            # needn't bother, stack will do it for us
            #p.do_checksum(libnet.IPPROTO_IP, libnet.IP_H)
            #print self.__class__, "delivering", hexlify(repr(p))
            #print 'SocketOut', d.getsockname()
            #if d.getsockname()[1] == HIP_PROTO_NO: print HIPOptMessage.packetDump(p)
            s.sendto(repr(p), r)

    def run(self):
        self.ReaderThread = threading.Thread(target = self.Reader,
                                             args = [])
        self.ReaderThread.setDaemon(1)
        self.ReaderThread.start()
        self.WriterThread = threading.Thread(target = self.Writer,
                                             args = [])
        self.WriterThread.setDaemon(1)
        self.WriterThread.start()

class HIPSocketHandler(SocketIOHandler):
    HITtable = {}
    def OpenSocket(self,
                   address,
                   af=socket.AF_INET):
        sk = socket.socket(af, socket.SOCK_RAW, HIP_PROTO_NO)
        print self.__class__, 'OpenSocket', address, af, sk
        if address is not None and af == socket.AF_INET:
            try:
                sk.bind((address, HIP_PROTO_NO))
            except:
                print "Address was <"+address+'>'
                raise
        #sk.setsockopt(0, socket.IP_HDRINCL, 1)
        sk.setblocking(1)
        return sk

    def Reader(self):
        s=self.Socket
        WorkHandler = self.WorkHandler
        while 1:
            #print self.__class__, 'Reader', s
            try:
                r = s.recvfrom(70000)
                #print self.__class__, "Socket gave:", hexlify(r[0]), repr(r[1])
            except socket.error:
                continue
            #print "Reader", repr(r)
            WorkHandler(r)

##    def runReaders():
##        self.ReaderThread = threading.Thread(target = self.Reader,
##                                             args = [])
##        self.ReaderThread.setDaemon(1)
##        self.ReaderThread.start()

    def WorkHandler(self, r):
        pkt, addr = r
        saddr, daddr, protocol, payload = self.ipinput(pkt, addr)
        #print 'ipinput gave', hexlify(saddr), hexlify(daddr), addr
        HIPOptMessage.packetDump(payload)
        (h, rest) = (HIPOptMessage.HIPHeader(string=payload),
                     payload[HIPOptMessage.HIPHeader.size:])
        #print 'Received...', hexlify(h.sourceHIT), '->', hexlify(h.remoteHIT)
        #print HIPOptMessage.packetDump(payload)
        #print 'ipinput to', repr(saddr), repr(daddr)
        try:
            #handler
            try:
                if daddr == '':
                    daddr = self.defaultHandler.localIP_n
                computed = HIPChecksum(payload, saddr, daddr, HIP_PROTO_NO)
                if h.csum <> computed:
                    print "Checksum failure:", h.csum, '<>', computed
                else:
                    print "Checksum OK"
            except:
                print "Checksum not checked"
                pass
            self.defaultHandler.inputHIP(addr, payload, h, rest)
        except:
            traceback.print_exc()
            pass

    def Writer(self):
        s = self.Socket
        p = libnet.packet()
        q = self.OutQueue
        while 1:
            #print self.__class__, 'Writer'
            payload, r, l = q.get()
            HIPOptMessage.packetDump(payload)
            if self.defaultHandler.useIPv6:
                pkt = payload
            else:
                R = libnet.name_resolve(r[0],0)
                L = libnet.name_resolve(l[0],0)
                p.payload=payload
                p.build_ip(len(p),
                           0,
                           1,
                           0,
                           255,
                           l[1],
                           L,
                           R)
                # needn't bother, stack will do it for us
                #p.do_checksum(libnet.IPPROTO_IP, libnet.IP_H)
                pkt = repr(p)
            #print self.__class__, "delivering", hexlify(pkt)
            #print 'SocketOut', d.getsockname()
            #if d.getsockname()[1] == HIP_PROTO_NO: print HIPOptMessage.packetDump(p)
            s.sendto(pkt, r)


class ESPSocketHandler(SocketIOHandler):
    def OpenSocket(self, address):
        ESPsk = socket.socket(socket.AF_INET, socket.SOCK_RAW, ESP_PROTO_NO)
        #ESPsk.bind(address)
        ESPsk.setsockopt(0, socket.IP_HDRINCL, 1)
        ESPsk.setblocking(1)
        return ESPsk

    def Writer(self):
        s = self.Socket
        p = libnet.packet()
        q = self.OutQueue
        send = s.send
        #print self.__class__, 'Writer'
        while 1:
            pkt = q.get()
            #print self.__class__, "delivering", hexlify(pkt)
            send(pkt)


    def WorkHandler(self, r):
        pass
##        try:
##            pkt, addr = r
##            saddr, daddr, protocol, payload = self.ipinput(pkt, addr)
##            #print 'ipinput gave', repr(saddr), repr(daddr)
##            try:
##                handler = ESP.SPI.findHandler(payload)
##                R, L = handler.libnetLSIs
##            except KeyError:
##                print 'KeyError finding ESP handler'
##                #print hexlify(payload)
##                return
##            except AttributeError:
##                print '! no cached names'
##                R = libnet.name_resolve(socket.inet_ntoa(struct.pack('!L', handler.machine.remoteLSI)),0)
##                L = libnet.name_resolve(socket.inet_ntoa(struct.pack('!L', handler.machine.localLSI)),0)
##                handler.libnetLSIs = (R, L)
##            (rSPI, rSN, rdata, nextheader) = handler.unpack(payload)
##            #print "------>", time.time() - c, 'for ESP find and unpack'
##            #print 'ESP:', rSPI, rSN, hexlify(rdata), nextheader
##            if nextheader == 60:
##                print 'unpacking IPv6 packet'
##                # IPv6, has to be
##                # remove the padding destopt we put in
##                if rdata[2] == '\x01':
##                    nextheader = ord(rdata[0])
##                    optlen = (ord(rdata[1])+1)*8
##                    rdata = rdata[optlen:]
##                header = struct.pack(IP6Header,
##                                     0x60000000,
##                                     len(rdata),
##                                     nextheader,
##                                     63,
##                                     handler.remoteIPv6addr,
##                                     handler.localIPv6addr)
##                pkt2 = ''.join([header, rdata])
##            else:
##                # IPv4
##                #c = time.time()
##                p=libnet.packet()
##                p.payload=rdata
##                p.build_ip(len(p),
##                           0,
##                           1,
##                           0,
##                           255,
##                           nextheader,
##                           R,
##                           L)
##                p.do_checksum(libnet.IPPROTO_IP, libnet.IP_H)
##                #print "delivering", hexlify(p.getvalue())
##                pkt2 = repr(p)
##                if nextheader in [6, 17]: # need to fix the checksum
##                    pkt2 = fixULPChecksum(pkt2)
##                #print "--->", time.time() - c, 'for ESP deliver construction'
##            #print "delivering", hexlify(pkt2)
##            self.TunOutQueue.put(pkt2)
##        except ESP.ESPUnpackError, x:
##            print 'Unpack error:', x                
##        except KeyError:
##            #traceback.print_exc()
##            #print 'nope. Not our packet...'
##            pass
        
class TunDeviceHandler(SocketIOHandler):
    def OpenSocket(self, address):
        def AliasGen():
            i=1
            while 1:
                yield i
                i+=1
        self.Aliases = AliasGen()
        fd = os.open('/dev/net/tun', os.O_RDWR ) #| os.O_NONBLOCK)
        val = ioctl(fd, 0x400454ca, struct.pack('16xH14x', 0x1001))
        self.dev = string.replace(val[:16],'\x00','')
        #print dev
        #os.system('/sbin/ifconfig %s 10.0.0.1 mtu 1000' % self.dev)
        #os.system('/sbin/route add -net 10.0.0.0 netmask 255.0.0.0 %s' % self.dev)
        #os.system('/sbin/ifconfig %s 1.0.0.1 mtu 1000' % self.dev)
        #os.system('/sbin/route add -net 1.0.0.0 netmask 255.0.0.0 %s' % self.dev)

        os.system('/sbin/ifconfig %s up' % self.dev)
        #os.system('/sbin/route add -net 1.0.0.0 netmask 255.0.0.0 %s' % self.dev)

        return fd
    
    def AddAlias(self, m):
        m.dev = '%s:%d' % (self.dev,
                           self.Aliases.next())
        os.system('/sbin/ifconfig %s %s'
                  % (m.dev,
                     socket.inet_ntoa(struct.pack('!L', m.localLSI))))
        os.system('/sbin/route add -host %s gateway %s'
                  % (socket.inet_ntoa(struct.pack('!L', m.remoteLSI)),
                     socket.inet_ntoa(struct.pack('!L', m.localLSI))))

    def DelAlias(self, m):
        os.system('/sbin/ifconfig %s down' % m.dev)
        os.system('/sbin/route del %s' %
                  (socket.inet_ntoa(struct.pack('!L', m.remoteLSI))))


    def Writer(self):
        s = self.Socket
        while 1:
            pkt = self.OutQueue.get()
            #print 'Writer', hexlify(pkt)
            os.write(s, pkt)
            
    def Reader(self):
        pass
##        # We want to be fast
##        ipinput = self.ipinput
##        LSItable = self.LSItable
##        ESPOutQueue = self.ESPOutQueue
##        s = self.Socket
##        read = os.read
##        while 1:
##            print 'Reader'
##            try:
##                #r = os.read(self.Socket, 70000)
##                pkt = read(s, 70000)
##                #print self.__class__, "Socket gave:", hexlify(r[0]), repr(r[1])
##            except OSError:
##                continue
##            try:
##                #pkt, addr = r
##                #print "Tunnel gave:", hexlify(pkt)
##                saddr, daddr, protocol, payload = ipinput(pkt)
##                if payload == None:
##                    return
##                #print "tunnel:", repr(Host.IPtable), repr(daddr), repr(daddr)
##                if len(daddr) == 4:
##                    # IPv4
##                    machine = LSItable[daddr]
##                else:
##                    # IPv6
##                    # This is ugly...
##                    # and doesn't work either
##                    machine = self.IPtable[(socket.AF_INET6,
##                                       socket.SOCK_RAW,
##                                       0,
##                                       '',
##                                       (IPAddress.IPv6_ntoa(daddr),
##                                        0, 0, 0))]
##                    # add a Pad6 destination option
##                    # costs 8 bytes, but lets destination
##                    # figure out that this *is* IPv6
##                    payload = ''.join([chr(protocol),
##                                       '\x00\x01\x04\x00\x00\x00\x00',
##                                       payload])
##                    protocol = 60
##                #print "Machine is:", machine
##                machine.lastused = time.time()
##                if machine.piggyback:
##                    machine.send(HIPOptMessage.PAYLOAD,
##                                 piggy=machine.remoteESP.pack(protocol, payload),
##                                 piggybackProtocol=ESP_PROTO_NO)
##                else:
##                    ESPOutQueue.put(
##                        (machine.remoteESP.pack(protocol, payload),
##                         machine.remoteIPCurrent,
##                         (machine.localIPCurrent[0], ESP_PROTO_NO)))
##            except (KeyError, ESP.ESPHeld):
##                #print 'Error'
##                pass

class NetfilterInputHandler(object, IPhandler):
    def __init__(self, IPv6inside=1, outside=0):
        self.IPv6inside, self.outside = IPv6inside, outside
        print "NetfilterInputHandler: IPv6inside=%d, outside=%d" % (IPv6inside, outside)
        if IPv6inside and not outside:
            self.pf = ipqueue.PF_INET
        else:
            self.pf = ipqueue.PF_INET6
        self.queue = ipqueue.IPQ(ipqueue.IPQ_COPY_PACKET,
                                 self.pf)
        self.sendHandler = RawSocketIOHandler(None)
        
    def run(self):
        self.sendHandler.run()
        self.ReaderThread = threading.Thread(target = self.Reader,
                                             args = [])
        self.ReaderThread.setDaemon(1)
        self.ReaderThread.start()


    def Reader(self):
        q = self.queue
        InputHandler = self.InputHandler
        OutputHandler = self.OutputHandler
        while 1:
            #print self.__class__, 'Nefilter Queue Handler'
            p = q.read()
            pkt = p[ipqueue.PAYLOAD]
            #print self.__class__, 'Nefilter Queue Handler Receive', hexlify(pkt)
            saddr, daddr, protocol, payload = self.ipinput(pkt)
            if saddr is None:
                print 'Dropping', IPAddress.IPv6_ntoa(saddr), '->', IPAddress.IPv6_ntoa(daddr), protocol
                q.set_verdict(p[0], ipqueue.NF_DROP)
            else:
                #print 'Handling', IPAddress.IPv6_ntoa(saddr), '->', IPAddress.IPv6_ntoa(daddr), protocol
                if daddr in self.LocalIPs:
                    pkt, v = InputHandler(saddr, daddr, protocol, payload)
                else:
                    pkt, v = OutputHandler(saddr, daddr, protocol, payload)
                if pkt is None:
                    q.set_verdict(p[0], v)
                else:
                    q.set_verdict(p[0], v, pkt)

    def InputHandler(self, saddr, daddr, protocol, payload):
        try:
            try:
                handler = ESP.SPI.findHandler(payload)
                #print "InputHandler", repr(handler)
                R, L = handler.libnetLSIs
            except KeyError:
                #print 'IOHandler: KeyError finding ESP handler'
                #print repr(ESP.SPI.SPItable)
                #print hexlify(payload)
                #maybe someone else can deal with it
                return None, ipqueue.NF_ACCEPT
            except AttributeError:
                #print '! no cached names'
                R = libnet.name_resolve(IPAddress.IPv6_ntoa(struct.pack('!L', handler.machine.remoteLSI)),0)
                L = libnet.name_resolve(IPAddress.IPv6_ntoa(struct.pack('!L', handler.machine.localLSI)),0)
                handler.libnetLSIs = (R, L)
            (rSPI, rSN, rdata, nextheader) = handler.unpack(payload)
            #print "------>", time.time() - c, 'for ESP find and unpack'
            #print 'ESP:', rSPI, rSN, hexlify(rdata), nextheader
            if self.IPv6inside:
                stack = 6
                #print 'unpacking IPv6 packet'
                # IPv6, has to be
                header = struct.pack(IPAddress.IP6Header,
                                     0x60000000,
                                     len(rdata),
                                     nextheader,
                                     63,
                                     handler.machine.remoteHIT,
                                     handler.machine.localHIT)
                pkt2 = ''.join([header, rdata])
                daddr = handler.machine.localHIT
            else:
                # IPv4
                #c = time.time()
                stack = 4
                p=libnet.packet()
                p.payload=rdata
                p.build_ip(len(p),
                           0,
                           1,
                           0,
                           255,
                           nextheader,
                           R,
                           L)
                p.do_checksum(libnet.IPPROTO_IP, libnet.IP_H)
                #print "delivering", hexlify(p.getvalue())
                pkt2 = repr(p)
                if nextheader in [6, 17]: # need to fix the checksum
                    pkt2 = fixULPChecksum(pkt2)
                daddr = struct.pack('!L', handler.machine.localLSI)
                #print "--->", time.time() - c, 'for ESP deliver construction'
            #print "InputHandler delivering", hexlify(pkt2)
            self.sendHandler.OutQueue.put((stack, pkt2, nextheader, daddr))
            #return pkt2, ipqueue.NF_REPEAT
            return None, ipqueue.NF_DROP
        except ESP.ESPUnpackError, x:
            print 'Unpack error:', x
            return None, ipqueue.NF_DROP
        except KeyError:
            #traceback.print_exc()
            print 'nope. Not our packet...'
            return None, ipqueue.NF_ACCEPT
        
##    def OpenSocket(self, address):
##        def AliasGen():
##            i=1
##            while 1:
##                yield i
##                i+=1
##        self.Aliases = AliasGen()
##        fd = os.open('/dev/net/tun', os.O_RDWR ) #| os.O_NONBLOCK)
##        val = ioctl(fd, 0x400454ca, struct.pack('16xH14x', 0x1001))
##        self.dev = string.replace(val[:16],'\x00','')
##        #print dev
##        #os.system('/sbin/ifconfig %s 10.0.0.1 mtu 1000' % self.dev)
##        #os.system('/sbin/route add -net 10.0.0.0 netmask 255.0.0.0 %s' % self.dev)
##        os.system('/sbin/ifconfig %s 1.0.0.1 mtu 1000' % self.dev)
##        os.system('/sbin/route add -net 1.0.0.0 netmask 255.0.0.0 %s' % self.dev)
##        return fd
    
##    def AddAlias(self, m):
##        m.dev = '%s:%d' % (self.dev,
##                           self.Aliases.next())
##        os.system('/sbin/ifconfig %s %s'
##                  % (m.dev,
##                     socket.inet_ntoa(struct.pack('!L', m.localLSI))))
##        os.system('/sbin/route add -host %s gateway %s'
##                  % (socket.inet_ntoa(struct.pack('!L', m.remoteLSI)),
##                     socket.inet_ntoa(struct.pack('!L', m.localLSI))))

##    def DelAlias(self, m):
##        os.system('/sbin/ifconfig %s down' % m.dev)
##        os.system('/sbin/route del %s' %
##                  (socket.inet_ntoa(struct.pack('!L', m.remoteLSI))))


##    def Writer(self):
##        s = self.Socket
##        while 1:
##            print 'Writer'
##            os.write(s, self.OutQueue.get())
            
    def OutputHandler(self, saddr, daddr, protocol, payload):
        # We want to be fast
        try:
            #pkt, addr = r
            #print "Filter gave:", hexlify(payload)
            #print "tunnel:", hexlify(saddr), hexlify(daddr)
            if payload == None:
                return None, ipqueue.NF_ACCEPT
            try:
                # IPv4
                machine = self.LSItable[daddr]
            except KeyError:
                try:
                    #print "HITtable has keys", self.HITtable.keys()
                    machine = self.HITtable[daddr]
                except KeyError:
                    #print "Dropping it on the floor"
                    return None, ipqueue.NF_DROP
            try:
                #print "Machine is:", machine
                machine.lastused = time.time()
            except:
                #print 'Giving up, see if stack can do something.'
                return None, ipqueue.NF_ACCEPT
            if hasattr(machine, 'piggyback') and machine.piggyback:
                machine.send(HIPOptMessage.PAYLOAD,
                             piggy=machine.localESP.pack(protocol, payload),
                             piggybackProtocol=ESP_PROTO_NO)
                return None, ipqueue.NF_DROP
            else:
                #print machine.__dict__.keys()
                payload, r, l = (machine.localESP.pack(protocol,
                                                        payload),
                                 machine.remoteIPCurrent,
                                 (machine.localIPCurrent,
                                  ESP_PROTO_NO))
                if not self.outside:
                    # IPv4
                    stack = 4
                    R = libnet.name_resolve(r[0],0)
                    L = libnet.name_resolve(l[0],0)
                    p=libnet.packet()
                    p.payload=payload
                    p.build_ip(len(p),
                               0,
                               1,
                               0,
                               255,
                               l[1],
                               L,
                               R)
                    p.do_checksum(libnet.IPPROTO_IP, libnet.IP_H)
                    pkt = repr(p)
                else:
                    # IPv6
                    stack = 6
                    nextheader = ESP_PROTO_NO
                    #print "Sending ESP with this:", repr(machine.__dict__)
                    header = struct.pack(IPAddress.IP6Header,
                                         0x60000000,
                                         len(payload),
                                         nextheader,
                                         63,
                                         machine.localIPCurrent6_n,
                                         machine.remoteIPCurrent_n)
                    pkt = ''.join([header, payload])
                #print "OutputHandler delivering", stack, hexlify(pkt)
                #self.tunhandler.OutQueue.put(pkt)
                self.sendHandler.OutQueue.put((stack,
                                               pkt,
                                               ESP_PROTO_NO,
                                               machine.remoteIPCurrent_n))
                #return pkt, ipqueue.NF_REPEAT
                return None, ipqueue.NF_DROP
        except (KeyError, ESP.ESPHeld):
            print 'Error'
            return None, ipqueue.NF_ACCEPT



#ESPInputHandler = ESPSocketHandler
#ESPOutputHandler = TunDeviceHandler

ESPInputHandler = NetfilterInputHandler
ESPOutputHandler = None
