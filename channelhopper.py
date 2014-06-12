import os
import threading
import time

__author__ = 'Michael'


class ChannelHopper(threading.Thread):
    running = False
    iface = None

    def __init__(self, iface):
        threading.Thread.__init__(self)
        self.iface = iface

    def stop(self):
        self.running = False

    def run(self):
        channels = range(1, 14)  # outside for loop so we do not create list every time
        self.running = True

        while self.running:
            for channel in channels:
                if not self.running:
                    break
                out = os.system('iwconfig %s channel %d' % (self.iface, channel))
                if out == 1:
                    self.running = False
                    break
                time.sleep(1)