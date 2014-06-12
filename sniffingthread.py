import time
from select import select
import threading

from data import *
from config import conf
from gtk.gdk import offscreen_window_get_embedder
from utils import PcapReader
import plist


__author__ = 'Michael'


class ThreadedSniffer(threading.Thread):

    def __init__(self, count=0, store=1, offline=None, prn=None, lfilter=None, L2socket=None, timeout=None,
                opened_socket=None, stop_filter=None, kill_switch=False):
        threading.Thread.__init__(self)
        self.count = count
        self.store = store
        self.offline=offline
        self.prn = prn
        self.lfilter = lfilter
        self.L2socket = L2socket
        self.timeout = timeout
        self.opened_socket = opened_socket
        self.stop_filter = stop_filter
        self.running = True

    def stop(self):
        self.running = False

    def run(self):
        self.running = True
        self.mysniff()

    def mysniff(self, *arg, **karg):
        c = 0

        if self.opened_socket is not None:
            s = self.opened_socket
        else:
            if self.offline is None:
                if self.L2socket is None:
                    self.L2socket = conf.L2listen
                s = self.L2socket(type=ETH_P_ALL, *arg, **karg)
            else:
                s = PcapReader(self.offline)

        lst = []
        if self.timeout is not None:
            stoptime = time.time() + self.timeout
        remain = None
        while 1:
            try:
                if self.timeout is not None:
                    remain = stoptime - time.time()
                    if remain <= 0:
                        break
                sel = select([s], [], [], remain)
                if s in sel[0]:
                    p = s.recv(MTU)
                    if p is None:
                        break
                    if self.lfilter and not self.lfilter(p):
                        continue
                    if self.store:
                        lst.append(p)
                    c += 1
                    if self.prn:
                        r = self.prn(p)
                        if r is not None:
                            print r
                    if self.stop_filter and self.stop_filter(p):
                        break
                    if 0 < self.count <= c:
                        break
                    if self.running:
                        break
            except KeyboardInterrupt:
                break
        if self.opened_socket is None:
            s.close()
        return plist.PacketList(lst, "Sniffed")