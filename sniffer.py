from subprocess import Popen, PIPE

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt

from interface import Interface


__author__ = 'michael'
aplist = []
aps = {}


def getap(pkt):
    global aplist
    # print pkt.summary()
    if 'Salerno' in pkt.summary():
        pass
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
            if pkt.addr2 not in aplist:
                aplist.append(pkt.addr2)
                print "BSSID: %s SSID: %s" % (pkt.addr2, pkt.info)


def insert_ap(pkt):
    # # Done in the lfilter param
    # if Dot11Beacon not in pkt and Dot11ProbeResp not in pkt:
    # return
    bssid = pkt[Dot11].addr3
    if bssid in aps:
        return
    p = pkt[Dot11Elt]
    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                      "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
    ssid, channel = None, None
    crypto = set()
    while isinstance(p, Dot11Elt):
        if p.ID == 0:
            ssid = p.info
        elif p.ID == 3:
            channel = ord(p.info)
        elif p.ID == 48:
            crypto.add("WPA2")
        elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
            crypto.add("WPA")
        p = p.payload
    if not crypto:
        if 'privacy' in cap:
            crypto.add("WEP")
        else:
            crypto.add("OPN")
    print "NEW AP: %r [%s], channed %d, %s" % (ssid, bssid, channel,
                                               ' / '.join(crypto))
    aps[bssid] = (ssid, channel, crypto)


def startmonmode(iface):
    os.system('ifconfig %s down' % iface)
    os.system('iwconfig %s mode monitor' % iface)
    os.system('ifconfig %s up' % iface)


def iwconfig():
    devnull = open(os.devnull, 'w')
    lst = []

    cmd = Popen(['iwconfig'], stdout=PIPE, stderr=devnull)
    for line in cmd.communicate()[0].split('\n\n'):
        tmpiface = Interface(None, None, None, None)
        line = line.strip()

        if len(line) == 0:
            continue

        ifname = re.search('^([A-Za-z0-9]+)', line)
        ifessid = re.search('ESSID:"([A-Za-z0-9]+)"', line)
        ifmode = re.search('Mode:([A-Za-z]+)', line)
        ifbssid = re.search('Access Point: ([0-9:A-F]+)', line)

        if ifname is not None:
            tmpiface.name = ifname.group(1)

            if ifessid is not None:
                tmpiface.essid = ifessid.group(1)

            if ifmode is not None:
                tmpiface.mode = ifmode.group(1)

            if ifbssid is not None:
                tmpiface.bssid = ifbssid.group(1)

            lst.append(tmpiface)

    devnull.close()
    return lst


def main():
    global aplist
    aps = {}

    interfaces = iwconfig()

    for i in interfaces:
        print i.tostring()

    pick = input('Pick one (starting from 0): ')
    pick = interfaces[pick].name

    print 'putting %s in mon mode' % pick
    startmonmode(pick)
    conf.iface = pick
    print 'ok I should be printing out packets now'
    sniff(count=1, prn=insert_ap, lfilter=lambda p: (
        (Dot11Beacon in p or Dot11ProbeResp in p) and 'privacy' in p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                                                                             "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split(
            '+')))
    print 'Stopping mon mode on %s' % pick
    stopmonmode(pick)


if __name__ == '__main__':
    main()
