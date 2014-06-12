import os
import threading
import time

__author__ = 'Michael'


class ChannelHopper(threading.Thread):
    running = False
    iface = None
    oneitter = False

    def __init__(self, iface, oneitter=False):
        threading.Thread.__init__(self)
        self.iface = iface
        self.oneitter = oneitter

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

            if not self.oneitter:
                self.running = False