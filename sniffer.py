#!/usr/bin/env python

from subprocess import Popen, PIPE

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11WEP
from channelhopper import ChannelHopper

from interface import Interface
import wepcracker

__author__ = 'michael'
aplist = []
aps = {}


def get_ap(pkt):
    global aplist
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

    str_crypt = ' / '.join(crypto)

    if len(ssid) > 0:
        print '{0:20} | {1:20} | {2:2} | {3:10}'.format(ssid, bssid, channel, str_crypt)
    else:
        print '{0:20} | {1:20} | {2:2} | {3:10}'.format('HIDDEN', bssid, channel, str_crypt)

    aps[bssid] = (ssid, channel, crypto)


def start_mon_mode(iface):
    os.system('ifconfig %s down' % iface)
    os.system('iwconfig %s mode monitor' % iface)
    os.system('ifconfig %s up' % iface)


def stop_mon_mode(iface):
    os.system('ifconfig %s down' % iface)
    os.system('iwconfig %s mode managed' % iface)
    os.system('ifconfig %s up' % iface)


def check_for_mon(lst):
    rtn = None
    for i in lst:
        if i.mode == 'Monitor':
            rtn = i
            break
    return rtn


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


wep_count = 0
iv_count = 0


def test(pkt):
    global wep_count, iv_count
    wep_pkt = pkt.getlayer(Dot11WEP)
    if wep_pkt:
        wep_count += 1

        # print '\n' + str(pkt.show2)
        # print '\naddr1: ' + pkt.addr1
        #print 'addr2: ' + pkt.addr2
        #print 'addr3: ' + pkt.addr3
        #print 'iv: ' + wep_pkt.iv
        #print 'wepdata[0]: ' + wep_pkt.wepdata[0]
        readable_iv = [ord(char) for char in wep_pkt.iv]
        # Shane: using 128bit WEP so key size is 13
        if wepcracker.weak_iv(readable_iv, 13):
            iv_count += 1
            print 'weak iv: %s\tWEP count: %d\tIV count: %d' % (str(readable_iv), wep_count, iv_count)
            #print '\n########\naddr1: %s, addr2: %s addr3: %s, iv: %s\n webdata: %s\n########\n' % (addr1.group(1), addr2.group(1), addr3.group(1), iv.group(1), webdata.group(1))


def main():
    global aplist
    aps = {}

    interfaces = iwconfig()
    foundmon = check_for_mon(interfaces)
    pick = None

    if foundmon is not None:
        print foundmon.tostring()
        ans = None
        while ans != 'y' and ans != 'n':
            ans = raw_input('Found an iface already in mon mode would you like to use it? (y/n) : ')
            if ans == 'y':
                pick = foundmon.name

    if pick is None:
        for i in interfaces:
            print i.tostring()

        pick = input('Pick one (starting from 0): ')
        pick = interfaces[pick].name
        print 'putting %s in mon mode' % pick
        start_mon_mode(pick)

    conf.iface = pick
    print 'ok I should be printing out packets now'

    hopper = ChannelHopper(iface=pick)
    try:
        hopper.start()

        print '{0:^20} | {1:^20} | {2:^2} | {3:^10}'.format('SSID', 'BSSID', 'ch', 'crypto')
        print '-------------------------------------------------------------'
        sniff(count=0, prn=insert_ap, lfilter=lambda p: (
            (Dot11Beacon in p or Dot11ProbeResp in p) and 'privacy' in p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                                                                                 "{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
            .split('+')))

        # sniff(prn=test)
        hopper.stop()
    except KeyboardInterrupt:
        hopper.stop()

    print 'Stopping mon mode on %s' % pick
    stop_mon_mode(pick)


if __name__ == '__main__':
    main()
