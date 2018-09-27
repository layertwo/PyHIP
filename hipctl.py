#!/usr/local/bin/python
from getopt import getopt
import socket
import string
import os
import sys
import time
import readline
import HI
import time
from binascii import *
from cmd import Cmd

class hipctl(Cmd):
    def __init__(self):
        self.prompt = 'hip> '
        self.sk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sk.connect('/tmp/hipd')
    
    def default(self, line):
        self.sk.send(line)
        print self.sk.recv(2000)

    def do_done(self, line):
        self.sk.send('done')
        # this is simply to avoid the daemon reporting an error
        # no harm otherwise.
        time.sleep(0.1)
        self.sk.close()
        sys.exit()

    def do_write(self, line):
        self.sk.send('hi')
        ret = self.sk.recv(2000)
        filename = string.split(line)[0]
        if os.access(filename, os.F_OK):
            print 'File %s exists' % filename
            return
        try:
            f = file(filename, 'w+')
            f.write(ret)
            f.close()
        except IOError:
            print 'Could not write file %s' % filename
            return
        print 'Wrote HI to file %s' % filename

    def do_connect(self, line):
        l = string.split(line)
        print repr(l)
        host = l[0]
        if len(l) > 2:
            hit = l[2]
        else:
            hit = ''
        if len(l) > 1:
            filename = l[1]
            try:
                f = file(filename, 'r')
                rr = f.read()
            except:
                rr = ''
        else:
            rr = ''
        print rr
        self.sk.send('connect %s %s %s' % (host, hit, rr))
        print self.sk.recv(2000)
        if len(l) > 1:
            print self.sk.recv(2000)
        
    def do_loadhi(self, line):
        try:
            l = string.split(line)
            filename = l[0]
            if len(l) > 1:
                hi = l[1]
            else:
                hi = ''
        except IndexError:
            print 'Specify a filename'
            return
        f = file(filename, 'r')
        rr = f.read()
        print rr
        self.sk.send('loadhi %s %s' % (rr, hi))
        print self.sk.recv(2000)



def main():
    opts, args = getopt(sys.argv[1:], 'c:f:t:l', ['connect=',
                                                  'file=',
                                                  'hit=',
                                                  'list'])

    connect = None
    list = None
    h = hipctl()
    hit = '.'
    file = '.'
    
    for opt, val in opts:
        if opt in ('-c', '--connect'):
            connect = val
        if opt in ('-f', '--file'):
            file = val
        if opt in ('-l', '--list'):
            list = 1
        if opt in ('-t', '--hit'):
            hit = val
    print 'hit is', hit

    if connect:
        h.do_connect('%s %s %s' % (connect, file, hit))
    elif list:
        h.default('list_connections')
    else:
        h.cmdloop()
    h.do_done('')


if __name__ == "__main__":
	main()
