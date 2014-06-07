__author__ = 'michael'

class Interface:
    def __init__(self, name, essid, mode, bssid):
        self.name = name
        self.essid = essid
        self.mode = mode
        self.bssid = bssid

    def tostring(self):
        return 'name: ' + str(self.name) + ', essid: ' + str(self.essid) + ', mode: ' + str(self.mode) + ', bssid: ' + str(self.bssid)
        #return 'name: %s, essid: %s, mode: %s, bssid: %s' % str(self.name), str(self.essid), str(self.mode), str(self.bssid)
