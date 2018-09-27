from __future__ import generators

##try:
##    from psyco.classes import *
##except ImportError:
##    pass

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
import HIPOptMessage as HIPMessage
import DH
import HI
import IPAddress
from Future import Future

import time
import IOhandler

Memoize(libnet.name_resolve)
Memoize(IPAddress.IPv6_ntoa)

def convertIPlist(IPs):
    # IPs can be:
    # list of numeric IP addresses
    # list of getaddrinfo values
    remoteIPs=[]
    for i in IPs:
        if type(i) == types.StringType:
            if len(i) == 4:
                i = socket.inet_ntoa(i)
            else:
                i = IPAddress.IPv6_ntoa(i)
            remoteIPs.append(
                [x
                 for x in socket.getaddrinfo(i[0], None)
                 if x[0] in [10, 2]][0])
        else:
            remoteIPs.append(i)
    return remoteIPs

class HostStateMachine(HIPState.StateMachine):
    canpiggyback = 0
    def __init__(self, host, queue, interfaces, hit='', fqdn=''):
        #print 'New StateMachine:', fqdn, repr(hit), repr(self), self.canpiggyback
        HIPState.StateMachine.__init__(self, state=HIPState.E0, HI=host.hi)
##        # this is MODP group 5, actually.
##        self.DH = DH.construct((241031242692103258855207602219756607485695054850245994265416941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919,
##                                2))
        self.DH = DH.construct((0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
                                2))
        self.DH.groupid = 3
        self.localHIT = self.HI.HIT127()
        #self.localHIT = self.HI.HIT64(unhexlify('9e800000000000000000000000000000'))
        self.DH.gen_key(RandomPool.get_bytes)
        self.setFQDN(fqdn)
        self.remoteHIT = hit
        self.OutQueue = queue
        self.piggyback = 0
        self.LSIcallback = host.LSIcallback
        self.lifetime = 9000 #seconds
        self.rekey = 6000 #seconds
        self.lastused = time.time()
        self.lastkeyed = time.time()
        self.rekeying = 0
        self.trace = 1
        self.interfaces = interfaces
        self.setLocalIPs(self.interfaces)
        self.useIPv6 = 0
        def cb(host, m):
            k=Future(m.DH.gen_key(RandomPool.get_bytes))
            if host.useIPv6:
                m.useIPv6 = host.useIPv6
                m.localESP.remoteIPv6addr = m.remoteHI.HITv6link()
                m.localESP.localIPv6addr = host.hi.HITv6link()
                m.remoteESP.remoteIPv6addr = m.localESP.remoteIPv6addr
                m.remoteESP.localIPv6addr = m.localESP.localIPv6addr
        self.E3callback = curryl(cb, host)
        self.callbacks[HIPState.E3] = self.E3callback

    def setRemoteIPs(self, IPs):
        # IPs can be:
        # list of numeric IP addresses
        # list of getaddrinfo values
        remoteIPs=convertIPlist(IPs)
        print 'setRemoteIPs to:', repr(remoteIPs)
        self.remoteIPs = remoteIPs
        self.remoteIPCurrent = (self.remoteIPs[0][4][0], HIP_PROTO_NO)
        self.remoteIPCurrent_n = IPAddress.IPv6_aton(self.remoteIPCurrent[0])
        
    def setLocalIPs(self, interfaces):
        current = 0
        current6 = 0
        self.localIPs_n = []
        print "setting local ips:"
        for i in interfaces.keys():
            for j in interfaces[i]:
                print i, ':', j.af, j.String, j.isglobal, j.name
                if j.isglobal:
                    self.localIPs_n.append(j.Netstring)
                    if j.af == 'inet' and not current:
                        print "bingo4"
                        current = 1
                        self.localIPCurrent = j.String 
                        self.localIPCurrent_n = j.Netstring
                    if j.af == 'inet6' and not current6:
                        print "bingo6"
                        current6 = 1
                        self.localIPCurrent6 = j.String 
                        self.localIPCurrent6_n = j.Netstring
        print "set", self.localIPCurrent, 'and', self.localIPCurrent6
    
    def send(self, message, piggy='', piggybackProtocol=NO_PROTO, obj=None):
        if obj is None:
            obj = self
        message.valid=1
        self.piggybackProtocol = piggybackProtocol
        pkt = ''.join([message.pack(obj), piggy])
        self.piggybackProtocol = NO_PROTO
        if self.trace:
            print self.FQDN, 'Sending:', message, (
                repr((HIPChecksum(pkt,
                                  self.remoteIPCurrent_n,
                                  self.localIPCurrent_n,
                                  HIP_PROTO_NO),
                      self.remoteIPCurrent,
                      self.localIPCurrent)))
            pass
        self.OutQueue.put((HIPChecksum(pkt,
                                       self.remoteIPCurrent_n,
                                       self.localIPCurrent_n,
                                       HIP_PROTO_NO),
                           self.remoteIPCurrent,
                           self.localIPCurrent)
                           )



class Host:
    LSItable={}
    IPtable={}
    HITtable=IOhandler.HIPSocketHandler.HITtable
    HIP6OutQueue = Queue.Queue(2)
    ESP6OutQueue = Queue.Queue(1)
    CMDWorkQueue = Queue.Queue()
    FutureEvents = priorityDictionary()

    def __init__(self,
                 hi,
                 fqdn,
                 useIPv6,
                 interfaces,
                 LSIcallback,
                 piggyback=0):
        
        self.hi = hi
        self.useIPv6 = useIPv6
        self.interfaces = interfaces
        self.IPs=[]
        HostStateMachine.canpiggyback = piggyback
        def HostLSICallback(m, nextcallback=LSIcallback, host=self):
            #print m.__dict__
            m.lastkeyed = time.time()
            Host.LSItable[struct.pack('!L', copy.copy(m.remoteLSI))] = m
            #os.system('ip addr add %s dev dummy0' % IPAddress.IPv6_ntoa(m.localLSI))
##            if host.useIPv6:
##                Host.IPtable[(socket.AF_INET6,
##                              socket.SOCK_RAW,
##                              0,
##                              '',
##                              (IPAddress.IPv6_ntoa(m.remoteHI.HITv6link()),
##                               0, 0, 0))] = m
            #host.tunHandler.AddAlias(m)
            p = weakref.proxy(m)
            return nextcallback(p)
        if self.useIPv6:
            # assumption: correct v6 address is listed first
            #self.LocalAddrInfo = [x for x in socket.getaddrinfo(fqdn, None)
            #                      if x[:2] == (socket.AF_INET6, socket.SOCK_RAW)][0]
            #print self.LocalAddrInfo
            #self.sk6 = socket.socket(socket.AF_INET6,
            #                         socket.SOCK_RAW,
            #                         HIP_PROTO_NO)
            #self.localsk6addr = list(self.LocalAddrInfo[4])
            #self.localsk6addr[2] = HIP_PROTO_NO
            #self.sk6.setblocking(1)
            #self.ESPsk6 = socket.socket(socket.AF_INET6,
            #                            socket.SOCK_RAW,
            #                            ESP_PROTO_NO)
            #self.localESPsk6addr = list(self.LocalAddrInfo[4])
            #self.localESPsk6addr[2] = ESP_PROTO_NO
            #self.ESPsk6.setblocking(1)
            self.IPProtocols = [10, 2]
        else:
            self.IPProtocols = [2]
        self.LSIcallback = HostLSICallback
        #print 'New Host:', fqdn, repr(hi.HIT127())
        self.fqdn=fqdn

        self.CMDsk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.CMDsk.bind('/tmp/hipd')
        self.CMDsk.setblocking(1)
        self.CMDsk.listen(5)
        self.CMDsklist = [self.CMDsk]

        self.tundev = None
        self.machines = []
        # self.IPs is in getaddrinfo format
        self.IPs = []
        for i in interfaces.keys():
            for j in interfaces[i]:
                #print i+':', j.af, j.String, j.isglobal, j.name
                if j.isglobal and j.af_n in self.IPProtocols:
                    self.IPs.append(j.Addrinfo)
##        self.IPs = [x
##                    for x in socket.getaddrinfo(fqdn, None)
##                    if x[0] in self.IPProtocols]
        print "Using local IP addresses", repr(self.IPs)
        for i in self.IPs:
            Host.IPtable[i] = self

        self.run = 1
        self.timechecked = time.time()

        self.hipHandler = IOhandler.HIPSocketHandler(None)
        self.hip6Handler = IOhandler.HIPSocketHandler([x[0]
                                                       for x in self.IPs
                                                       if len(x)==4][0],
                                                      af=socket.AF_INET6)

        if not self.useIPv6:
            # IPv4
            print "IPv4 output selected"
            q = self.hipHandler.OutQueue
        else:
            # IPv6
            print "IPv6 output selected"
            q = self.hip6Handler.OutQueue

        
        # this must be here
        self.sm = HostStateMachine(self,
                                   hit='',
                                   queue=q,
                                   interfaces=self.interfaces,
                                   fqdn=fqdn)

        # then this
        self.hipHandler.defaultHandler = self
        self.hip6Handler.defaultHandler = self
        # then this
        #Host.HITtable[self.sm.localHIT] = self
        # that's all folks

    def send(self, message, remoteIP, hit, state=HIPState.E1, callback=None):
        # remoteIP should be a la getaddrinfo
        m = self.newConnection(remoteIP, hit)
        m.setstate(state)
        if callback:
            m.callbacks.update({state: callback})
        m.send(message)

    def newConnection(self, IP, hit):
        # IP should be a la getaddrinfo; if not, then fix it
        # must have been from recvfrom, then.
        if len(IP) < 5:
            IP = [x
                  for x in socket.getaddrinfo(IP[0], None)
                  if x[0] in self.IPProtocols][0]
        print "New Connection:", IP[4][0]
        if len(IP[4]) == 2:
            # IPv4
            print "IPv4 output selected"
            q = self.hipHandler.OutQueue
        else:
            # IPv6
            print "IPv6 output selected"
            q = self.hip6Handler.OutQueue
        m = HostStateMachine(self,
                             hit=hit,
                             queue = q,
                             interfaces = self.interfaces,
                             fqdn=self.fqdn)
        m.setRemoteIPs([IP])
        # delete connection if we fail to negotiate
        m.callbacks[HIPState.EFail] = curryl(self.delCon,
                                             self,
                                             m)
        Host.IPtable[IP] = m
        Host.HITtable[hit] = m
        print "Installing new:", repr(m), hexlify(hit)
        self.machines.insert(0,m)
        t = time.time()
        #print 'Setting DelCOn at', t, 'to', t+900
        #self.FutureEvents[t+20] = curryl(Host.delCon, self.machines[0])
        return weakref.proxy(m)

    def delCon(self, machine):
        #self.tunHandler.DelAlias(machine)
        for i in machine.remoteIPs:
            del Host.IPtable[i]
        del Host.HITtable[machine.localHIT]
        del Host.HITtable[machine.remoteHIT]
        del Host.LSItable[machine.remoteLSI]
        self.machines.remove(machine)

    def CMD_done(self, sk, args):
        return 'done'

    def CMD_exit(self, sk, args):
        self.run = 0
        return 'exiting'

    def CMD_readdress(self, sk, args):
        IPs = args
        for con in self.LSItable.values():
            con.send(HIPMessage.REA)
            con.setLocalIPs(IPs)
        return pformat(IPs)

    def CMD_connect(self, sk, args):
        def cb(host, m, d=sk):
            # do this now in background
            k=Future(m.DH.gen_key(RandomPool.get_bytes))
            m.rekey = 3000
            resp = ('Connected. Local LSI is %s, remote is %s.'
                    % (socket.inet_ntoa(struct.pack('!L', m.localLSI)),
                       socket.inet_ntoa(struct.pack('!L', m.remoteLSI))))
            if host.useIPv6:
                m.useIPv6 = host.useIPv6
                m.localESP.remoteIPv6addr = m.remoteHI.HITv6link()
                m.localESP.localIPv6addr = host.hi.HITv6link()
                m.remoteESP.remoteIPv6addr = m.localESP.remoteIPv6addr
                m.remoteESP.localIPv6addr = m.localESP.localIPv6addr
                resp += ('\nIPv6 addr is %s'
                         % IPAddress.IPv6_ntoa(m.localESP.remoteIPv6addr))
            if d in host.OutMap:
                host.OutMap[d][0].put(resp)
            else:
                host.OutMap[d] = (Queue.Queue(), host.handleCMDOut)
                host.OutMap[d][0].put(resp)
            # remove ourself from the callbacks
            m.callbacks[HIPState.E3] = m.E3callback
        print args
        host = args[0]
        if len(args)>1 and args[1] <> '.':
            hit = unhexlify(args[1])
            if len(args)>2:
                RR = args[2]
                hi2 = HI.HI(Rec=unhexlify(RR))
            else:
                hi2 = None
            #hit = hi2.HIT64(unhexlify('9e800000000000000000000000000000'))
            #hit = hi2.HIT127()
            #hit = unhexlify('711d10d3058affb0c69bef095911dc23')
            #hi2.hit127 = hit
        else:
            hi2 = None
            hit = HI.zeroHIT
        #ip = socket.inet_aton(socket.gethostbyname(host))
        # now ip is a la getaddrinfo
        ip = [x
              for x in socket.getaddrinfo(host, None)
              if x[0] in self.IPProtocols][0]
        print 'Connecting to ip', ip
        if hit in HI.HI.HITable:
            try:
                m = Host.IPtable[ip]
                m.send(HIPMessage.I1)
                m.callbacks[HIPState.E3] = curryl(cb, self)
            except KeyError:
                pass
            return 'Already connected to %s, with HIT %s.' % (host, hexlify(hit))
        if hi2 is not None:
            HI.HI.HITable[hit] = hi2
        #self.send(HIPMessage.BOS, ip, hit)
        #m = Host.IPtable[ip]
        #m.callbacks[HIPState.E3] = curryl(cb, self)
        #m.send(HIPMessage.I1)
        self.send(HIPMessage.I1, ip, hit,
                  state=HIPState.E3,
                  callback=curryl(cb, self))
        return ('Connecting to %s at ip address %s, with HIT %s.'
                % (host,
                   ip,
                   hexlify(hit)))

    def makeLocalSPI(self, localSPI, ESPalg, ESPkey, ESPauthkey, ip):
        ESP.SPI.SPItable[int(localSPI)] = ESP.SPI(SPI=localSPI,
                                             key=ESPkey,
                                             authkey=ESPauthkey,
                                             algname=ESPalg)
        return
    
    def makeRemoteSPI(self, remoteSPI, ESPalg, remoteESPkey, remoteESPauthkey, ip):
        class Machine:
            pass
        Machine = Machine()
        #Machine.ESPOutQueue = self.ESPOutQueue
        Machine.remoteESP = ESP.SPI(SPI=remoteSPI,
                                    key=remoteESPkey,
                                    authkey=remoteESPauthkey,
                                    algname=ESPalg)
        Machine.remoteIPCurrent = (ip, 50)
        Host.LSItable[socket.inet_aton(ip[4][0])] = Machine
        return
        
    def CMD_makeSPI(self, sk, args):
        print 'MakeSPI:', args
        try:
            host, ESPalg, SPI, remoteSPI, ESPkey, authkey = args[:6]
        except:
            return ''.join(traceback.format_exception(sys.exc_type, sys.exc_value, sys.exc_traceback) + ['Wrong number of arguments'])
        try:
            ip = [x
                  for x in socket.getaddrinfo(host, None)
                  if x[0] in self.IPProtocols][0]
        except:
            return ''.join(traceback.format_exception(sys.exc_type, sys.exc_value, sys.exc_traceback) + ['IP address invalid'])
        try:
            self.makeLocalSPI(SPI, ESPalg, unhexlify(ESPkey), unhexlify(authkey), ip)
            self.makeRemoteSPI(remoteSPI, ESPalg, unhexlify(ESPkey), unhexlify(authkey), ip)
        except:
            return ''.join(traceback.format_exception(sys.exc_type, sys.exc_value, sys.exc_traceback) + ['error making SPIs (wrong key length?)'])
        return ('Made SPI with '
                + host + ' at '
                + repr(ip) + ' key: '
                + ESPkey + ':' + authkey
                )

    def CMD_loadhi(self, sk, args):
        RR = args[0]
        hi2 = HI.HI(Rec=unhexlify(RR))
        if len(args) > 1:
            hit = unhexlify(args[1])
        else:
            hit = hi2.HIT127()
        HI.HI.HITable[hit] = hi2
        return 'Loaded HI with HIT %s.' % (hexlify(hit))

    def CMD_hi(self, sk, args):
        return hexlify(self.hi.pack())
        
    def CMD_list_his(self, sk, args):
        return pformat(map(hexlify, HI.HI.HITable.keys()))
        
    def CMD_list_connections(self, sk, args):
        return pformat([{'LSIlocal': socket.inet_ntoa(struct.pack('!L',
                                                                  x.localLSI)),
                         'LSIremote': socket.inet_ntoa(struct.pack('!L',
                                                                   x.remoteLSI)),
                         #'IPsremote': x.remoteIPs,
                         #'IPslocal': x.localIPs,
                         'HITlocal': hexlify(x.localHIT),
                         'HITremote': hexlify(x.remoteHIT),
                         #'LSI6local': IPAddress.IPv6_ntoa(self.hi.HITv6link()),
                         #'LSI6remote': IPAddress.IPv6_ntoa(x.remoteHI.HITv6link()),
                         'ESPsent': x.remoteESP.packcount,
                         'ESPrecv': x.localESP.unpackcount,
                         'ESPsendSPI': hex(x.remoteESP.SPI),
                         'ESPrecvSPI': hex(x.localESP.SPI),
                         'ESPsendSN': x.remoteESP.SN,
                         'ESPrecvSN': x.localESP.SN,
                         'Algorithm': x.ESPalg,
                         'Rekey': x.rekey,
                         'state': str(x.state)}
                        for x in self.LSItable.values()])

    def CMD_list_allstate(self, sk, args):
        return pformat([x.__dict__
                        for x in self.LSItable.values()])

    def emit(self):
        'Send everything we have queued'
        pass
    
    
    def inputHIP(self, saddr, payload, h=None, rest=None):
        try:
##            if not h:
##                (h, rest) = (HIPMessage.HIPHeader(string=payload),
##                             payload[HIPMessage.HIPHeader.size:])
            handler = Host.HITtable[h.sourceHIT]
        except KeyError:
            print 'Using new handler (opportunistic)'
            handler = self.newConnection(saddr, h.sourceHIT)
            print 'Handler:', hexlify(handler.localHIT), repr(handler)
        endHIP = (h.len-4)<<3
        #
        rest, piggy = rest[:endHIP], copy.copy(rest[endHIP:])
        try:
            handler.input(payload, h=h, rest=rest)
            if piggy and (h.nh == ESP_PROTO_NO):
                self.deliverESP(piggy)
        except HIPState.HIPNewConnection, x:
            print 'New connection', x.value
            handler = self.newConnection(saddr, x.value)
            print 'Handler:', hexlify(handler.localHIT), repr(handler)
            handler.input(payload, h=h, rest=rest)
        except HIPState.HIPUnpackError, x:
            print 'Unpack failed because', x.value                 
        handler.lastused = time.time()


    def handleScheduledEvents():
        try:
            x = self.FutureEvents.smallest()
            #print 'It is', time.time()
            while x < time.time():
                #print 'Event fired:', repr(self.FutureEvents[x]), 'set at', x, 'now', time.time()
                self.FutureEvents[x]()
                del self.FutureEvents[x]
                x = self.FutureEvents.smallest()
        except IndexError:
            #print 'It is', time.time(), 'no scheduled events.'
            pass


    def doTimeouts(self, now):
        self.timechecked = now
        for m in [m for m in self.machines
                  if (now - m.lastkeyed) > m.rekey]:
            #print 'Rekeying'
            # follow this variable around, it's interesting
            # it's a buffer for packets sent while the q is held
            holdlist = []
            def rekey(message):
##                for p in m.remoteESP.unhold(holdlist):
##                    m.ESPOutQueue.put((p,
##                                       (m.remoteIPs[0][4][0],
##                                        50)))
                del m.callbacks[HIPMessage.NES]
            def sendrekey():
                try:
                    m.DH.gen_key(RandomPool.get_bytes)
                    m.rekeying = 1
##                    m.remoteESP.hold(holdlist)
                    #m.callbacks[HIPMessage.NES] = rekey
                    m.send(HIPMessage.NES)
                    m.lastkeyed = now
                except:
                    traceback.print_exc()
            m.rekeyresult=sendrekey()
        for m in [m
                  for m in self.machines
                  if (now - m.lastused) > m.lifetime]:
            self.delCon(m)

    def handleCMDOut(self, d, q):
        try:
            dat = q.get()
        except Queue.Empty:
            del self.SocketMap[d]
            del self.OutMap[d]
            return
        try:
            d.send(dat)
        except:
            print 'Command connection write error'
            del self.SocketMap[d]
            del self.OutMap[d]
            d.close()
        if dat and dat == 'done':
            print 'Closing command connection'
            del self.SocketMap[d]
            del self.OutMap[d]
            d.close()

    def handleCMD(self, d, q):
        dat = d.recv(2000)
        if not dat:
            print 'Command connection closing due to error'
            del self.SocketMap[d]
            d.close()
        commandline = string.split(dat)
        if not commandline:
            return
        command = commandline[0]
        args = commandline[1:]
        funcname = 'CMD_%s' % command
        if hasattr(self, funcname):
            rESP = getattr(self, funcname, d)(d, args)
        else:
            rESP = 'No such command %s' % command
        if d in self.OutMap:
            self.OutMap[d][0].put(rESP)
        else:
            self.OutMap[d] = (Queue.Queue(), self.handleCMDOut)                
            self.OutMap[d][0].put(rESP)

    def handleCMDCon(self, d, q):
        try:
            sk2, addr = self.CMDsk.accept()
            self.SocketMap[sk2] = (Host.CMDWorkQueue, self.handleCMD)
        except socket.error:
            pass
            
    def mainLoop(self):
        print 'MainLoop'

#        self.hipHandler.run()
        self.hip6Handler.run()

        self.espHandler = IOhandler.NetfilterInputHandler(IPv6inside=1,
                                                          outside=1)
        self.espHandler.defaultHandler = self.sm
        self.espHandler.LSItable = self.LSItable
        self.espHandler.LocalIPs = self.sm.localIPs_n
        self.espHandler.HITtable = Host.HITtable
        self.espHandler.run()

##        self.esp6Handler = IOhandler.NetfilterInputHandler(IPv6inside=1,
##                                                          outside=1)
##        self.esp6Handler.defaultHandler = self.sm
##        self.esp6Handler.LSItable = self.LSItable
##        self.esp6Handler.LocalIPs = [self.sm.localIPCurrent_n]
##        self.esp6Handler.HITtable = Host.HITtable
##        self.esp6Handler.run()

        #self.espOutputSocketHandler = IOhandler.ESPSocketHandler(('', ESP_PROTO_NO))
        #self.espOutputSocketHandler.run()
        #self.espHandler.SocketHandler = self.espOutputSocketHandler
##        self.espHandler.defaultHandler = self.sm
##        self.tunHandler = IOhandler.ESPOutputHandler(None)
##        self.espHandler.TunOutQueue = self.tunHandler.OutQueue
##        self.tunHandler.ESPOutQueue = self.espHandler.OutQueue
##        self.tunHandler.LSItable = self.LSItable
##        self.espHandler.run()
##        self.tunHandler.run()

        self.SocketMap = {self.CMDsk: (Host.CMDWorkQueue, self.handleCMDCon)}
        
        self.inThreadList = []

        self.OutMap = {}
        self.outThreadList = []

        #if self.useIPv6:
        if 0:
            self.inThreadList.append((self.sk6,
                                      Host.HIPWorkQueue,
                                      self.queueHip))
            self.outThreadList.append((self.sk6,
                                       Host.HIP6OutQueue,
                                       self.handleSocketOut))
            self.inThreadList.append((self.ESPsk6,
                                      Host.ESPWorkQueue,
                                      self.handleESP))
            self.outThreadList.append((self.ESPsk6,
                                       Host.ESP6OutQueue,
                                       self.handleSocketOut))

        def outQueueDrainer(f, d, q):
            #print 'Started output worker', f.__name__
            while 1:
                print 'Output worker', f.__name__, d, ':'
                f(d, q)

        for d, q, f in self.outThreadList:
            thread = threading.Thread(target=outQueueDrainer,
                                      args=(f, d, q))
            thread.setDaemon(1)
            thread.start()

        def inQueueDrainer(f, d, q):
            #print 'Started input worker', f.__name__
            while 1:
                print 'Input worker', f.__name__, d, ':'
                f(d, q)

        for d, q, f in self.inThreadList:
            thread = threading.Thread(target=inQueueDrainer,
                                      args=(f, d, q))
            thread.setDaemon(1)
            thread.start()

        run = self.run
        while run:
            try:
                InList = [x
                          for x in self.SocketMap.keys()
                          if (self.SocketMap[x][0].empty())]
                OutList = [x[0]
                           for x in self.OutMap.items()
                           if not x[1][0].empty()]

                l, o, e = select(InList,
                                 OutList,
                                 OutList,
                                 1)
##                print 'tick.', l, o, e,
##                print time.time(), threading.currentThread().getName()
##                print 'in', pformat(InList)
##                print 'out', pformat(OutList)
##                print 'drain', pformat([x for x in self.outThreadList if not x[1].empty()]),
##                print
                while l:
                    d=l.pop()
                    q, f = self.SocketMap[d]
                    f(d, q)
                while o:
                    d=o.pop()
                    q, f = self.OutMap[d]
                    f(d, q)
                while e:
                    d=e.pop()
                    if d.getsockname() == '/tmp/hipd':
                        print 'Closing command connection', d.getsockname()
                        del self.SocketMap[d]
                        del self.OutMap[d]
                        d.close()
                now = time.time()
                if (now - self.timechecked) > 1:
                    self.doTimeouts(now)
            except KeyError:
                # Normal, happens with deleted connections or cmd closed unexpectedly
                #traceback.print_exc()
                pass
            except KeyboardInterrupt:
                run=0
##            except:
##                traceback.print_exc()
            #handleScheduledEvents()
            #self.emit()


def main():
    connect = ''
    useIPv6 = 0
    pig = 0

    opts, args = getopt(sys.argv[1:], 'k:h:6p', ['key=', 'hostname=', 'ipv6', 'piggyback'])

    for opt, val in opts:
        if opt in ('-h', '--hostname'):
            hostname = val
            print 'Hostname:', hostname
        if opt in ('-k', '--key'):
            keyname = val
            print 'Keyname:', keyname
        if opt in ('-6', '--ipv6'):
            useIPv6 = 1
            print 'Using IPv6'
        if opt in ('-p', '--piggyback'):
            pig = 1
            print 'Using Piggyback (if remote advertises)'

    hi1=HI.HI(keyname)
    if connect:
        hi2=HI.HI(connect)
        print 'Other hit is', hexlify(hi2.HIT127())
        HI.HI.HITable[hi2.HIT127()] = hi2

    print hostname, 'hit127 is', hexlify(hi1.HIT127())
    print hostname, 'hit64 is ', hexlify(hi1.HIT64(unhexlify('9e800000000000000000000000000000')))

    def cb(machine):
        print 'Remote host is %s' % socket.inet_ntoa(struct.pack('!L', machine.remoteLSI))
        print 'Local host is %s' % socket.inet_ntoa(struct.pack('!L', machine.localLSI))
        pass

    def bing():
        #print 'bing!'
        pass

    #if useIPv6:
    if 0:
        # varies from spec, this is a 118 bit HIT as a link addr
        os.system('/sbin/ip -f inet6 addr add %s scope link dev %s'
                  % (IPAddress.IPv6_ntoa(hi1.HITv6link()),
                     dev))


    interfaces={}

    (ip_pipe_in, if_pipe_out, if_pipe_err) = os.popen3('/sbin/ip -o addr show')

    for line in if_pipe_out.xreadlines():
        splitline = line.split()
        interface, name, af, addr = splitline[:4]
        interface = int(interface[:-1])
        isglobal = 'global' in splitline
        if af in ('inet', 'inet6'):
            try:
                addr, prefixlen = addr.split('/')
            except:
                if af == 'inet':
                    prefixlen = 32
                else:
                    prefixlen = 64
            ip = IPAddress.IP(addr)
            ip.af = af
            if af == 'inet':
                ip.af_n = socket.AF_INET
            else:
                ip.af_n = socket.AF_INET6
            ip.isglobal = isglobal
            ip.prefixlen = prefixlen
            ip.name = name
            try:
                # anything going wrong here
                ip.Lifetime = long(splitline[-1].split('sec')[0])
            except:
                # means we don't know, so default.
                ip.Lifetime = 0L
            print str(interface)+':', ip.af, ip.String, ip.isglobal, ip.name, ip.Lifetime
            if interfaces.has_key(interface):
                interfaces[interface].append(ip)
            else:
                interfaces[interface] = [ip]

#    print pformat(dict([(a, [b.__dict__ for b in interfaces[a]])
#                        for a in interfaces.keys()]))

    #H1.FutureEvents[time.time() + 10] = bing


    try:
        os.system('modprobe ip_queue')
        os.system('modprobe dummy')
        os.system('modprobe ipv6')
        os.system('modprobe ip6_queue')
        os.system('modprobe ip6_tables')
        os.system('iptables -I OUTPUT -d 1.0.0.0/8 -j QUEUE')
        os.system('iptables -I INPUT -p 50 -j QUEUE')
        os.system('ip6tables -A OUTPUT -d 4000::/2 -j QUEUE')
        os.system('ip6tables -I INPUT -p 50 -j QUEUE')
        os.system('ip link set dummy0 up')
        os.system('ip -6 addr add %s scope link dev %s'
                  % (IPAddress.IPv6_ntoa(hi1.HITv6link()),
                     'dummy0'))
        os.system('ip -6 route add 4000::/2 dev dummy0')
        H1 = None
        H1 = Host(hi1,
                  hostname,
                  useIPv6,
                  interfaces,
                  LSIcallback = cb,
                  piggyback = pig)

        Host.defaultHandler = H1

        H1.mainLoop()        
    except:
        if hasattr(H1, 'CMDsk'):
            H1.CMDsk.close
        os.system('rm /tmp/hipd')
        os.system('ip6tables -D OUTPUT -d 4000::/2 -j QUEUE')
        os.system('ip6tables -D INPUT -p 50 -j QUEUE')
        os.system('iptables -D OUTPUT -d 1.0.0.0/8 -j QUEUE')
        os.system('iptables -D INPUT -p 50 -j QUEUE')
        os.system('ip -6 addr add %s scope link dev %s'
                  % (IPAddress.IPv6_ntoa(hi1.HITv6link()),
                     'dummy0'))
        raise
    else:
        if hasattr(H1, 'CMDsk'):
            H1.CMDsk.close
        os.system('rm /tmp/hipd')
        os.system('ip6tables -D OUTPUT -d 4000::/2 -j QUEUE')
        os.system('ip6tables -D INPUT -p 50 -j QUEUE')
        os.system('iptables -D OUTPUT -d 1.0.0.0/8 -j QUEUE')
        os.system('iptables -D INPUT -p 50 -j QUEUE')
        os.system('ip -6 addr add %s scope link dev %s'
                  % (IPAddress.IPv6_ntoa(hi1.HITv6link()),
                     'dummy0'))
        


if __name__ == "__main__":
    import profile
    import pstats
    #    gc.set_debug(gc.DEBUG_LEAK)
    #    gc.set_debug(gc.DEBUG_STATS)
##    import psyco
##    psyco.bind(SocketIOHandler)
##    psyco.bind(HIPSocketHandler)
##    psyco.bind(ESPSocketHandler)
##    psyco.bind(TunDeviceHandler)
    main()
    #profile.run('main()','/tmp/hipd.profile')

    #stats=pstats.Stats('/tmp/hipd.profile')
    #stats.sort_stats('cumulative')
    #stats.sort_stats('calls')
    #stats.print_stats()
