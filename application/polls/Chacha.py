from ctypes import c_uint32
from random import randint, seed
import json
import base64

from .poly1305 import poly1305


# TODO switch endian

class Chacha:
    def __init__(self, msg):
        self.msg = msg.encode("ascii")
        #on complete le message pour pouvoir des blocs de 512 bits (64 octets)
        if len(msg) % 64 != 0:
            self.msg += bytes(64 - len(msg) % 64)

        # matrice des 512 octets du message sur lesquels on travaille
        self.msg_cint = []
        for i in range(16):
            v = c_uint32(int.from_bytes(self.msg[i*4 : (i+1)*4]))
            self.msg_cint.append(v)


        self.init_matrice = [c_uint32() for _ in range(16)]

        self.init_matrice[0] = c_uint32(0x65787061)
        self.init_matrice[1] = c_uint32(0x6e642033)
        self.init_matrice[2] = c_uint32(0x322d6279)
        self.init_matrice[3] = c_uint32(0x7465206b)


        self.key = [c_uint32(i) for i in range(8)]
        for i in range(8):
                self.init_matrice[4 + i].value = self.key[i].value

        self.compteur = c_uint32(1)
        self.init_matrice[12].value = self.compteur.value # copie pour éviter effets de bord

        # le keystream et le message chiffré sont stockés dans une liste
        # de blocs de 512 octets
        self.keystream = []
        self.enc_msg = []

        seed(0) # pour tester c'est plus pratique d'avoir tjrs la meme chose

        # gen nonce
        # TODO better nonce gen https://datatracker.ietf.org/doc/html/rfc7539#section-2.3
        for i in range(3):
            self.init_matrice[13 + i] = c_uint32(randint(0, 0xffffffff))

        self.matrice = copy_cuint32_mat(self.init_matrice)

        self.gen_poly1305_MAC()

        # variables d'état
        self.tour = 0
        self.qr = 0
        self.msg_index = 0
        self.done = False

    def gen_poly1305_MAC(self):
        mat = copy_cuint32_mat(self.init_matrice)
        #reset counter
        mat[12] = c_uint32(0)
        for i in range(10):
            c1 = mat[0]
            c2 = mat[1]
            c3 = mat[2]
            c4 = mat[3]
            k1 = mat[4]
            k2 = mat[5]
            k3 = mat[6]
            k4 = mat[7]
            k5 = mat[8]
            k6 = mat[9]
            k7 = mat[10]
            k8 = mat[11]
            ct = mat[12]
            n1 = mat[13]
            n2 = mat[14]
            n3 = mat[15]
            self.QR(c1, k1, k5, ct)
            self.QR(c2, k2, k6, n1)
            self.QR(c3, k3, k7, n2)
            self.QR(c4, k4, k8, n3)
            self.QR(c1, k2, k7, n3)
            self.QR(c2, k3, k8, ct)
            self.QR(c3, k4, k5, n1)
            self.QR(c4, k1, k5, n2)

        key = b"".join([bytes(mat[i]) for i in range(8)])

        self.MAC = poly1305(key, self.msg)


    def next_step(self):
        if self.done == True:
            return
        if self.tour == 10:
            self.keystream.append([c_uint32() for _ in range(16)])
            self.enc_msg.append([c_uint32() for _ in range(16)])
            for i in range(16):
                self.keystream[-1][i].value = self.init_matrice[i].value + self.matrice[i].value
                self.enc_msg[-1][i].value = self.keystream[-1][i].value ^ self.msg_cint[i].value

            self.msg_index += 1
            if self.msg_index*64 == len(self.msg):
                self.done = True
            for i in range(16):
                index = self.msg_index*64 + i*4
                v = c_uint32(int.from_bytes(self.msg[index : index+4]))
                self.msg_cint[i] = v

            self.tour = 0
            self.matrice = copy_cuint32_mat(self.init_matrice)
            self.compteur.value += 1
            self.matrice[12] = c_uint32(self.compteur.value)

        else:
            c1 = self.matrice[0]
            c2 = self.matrice[1]
            c3 = self.matrice[2]
            c4 = self.matrice[3]
            k1 = self.matrice[4]
            k2 = self.matrice[5]
            k3 = self.matrice[6]
            k4 = self.matrice[7]
            k5 = self.matrice[8]
            k6 = self.matrice[9]
            k7 = self.matrice[10]
            k8 = self.matrice[11]
            ct = self.matrice[12]
            n1 = self.matrice[13]
            n2 = self.matrice[14]
            n3 = self.matrice[15]

            if self.qr == 0:
                self.QR(c1, k1, k5, ct)
                self.qr += 1
            elif self.qr == 1:
                self.QR(c2, k2, k6, n1)
                self.qr += 1
            elif self.qr == 2:
                self.QR(c3, k3, k7, n2)
                self.qr += 1
            elif self.qr == 3:
                self.QR(c4, k4, k8, n3)
                self.qr += 1
            elif self.qr == 4:
                self.QR(c1, k2, k7, n3)
                self.qr += 1
            elif self.qr == 5:
                self.QR(c2, k3, k8, ct)
                self.qr += 1
            elif self.qr == 6:
                self.QR(c3, k4, k5, n1)
                self.qr += 1
            elif self.qr == 7:
                self.QR(c4, k1, k5, n2)
                self.qr += 1

            elif self.qr == 8:
                self.qr = 0
                self.tour += 1

    def QR(self, a, b, c, d):
        a.value = a.value + b.value
        d.value = d.value ^ a.value
        ROTl(d, 16)
        c.value = c.value + d.value
        b.value = b.value ^ c.value
        ROTl(b, 12)
        a.value = a.value + b.value
        d.value = d.value ^ a.value
        ROTl(d, 8)
        c.value = c.value + d.value
        b.value = b.value ^ c.value
        ROTl(b, 7)

    def decrypt(self):
        res = ""
        for k in range(len(self.keystream)):
            for i in range(16):
                v = self.enc_msg[k][i].value ^ self.keystream[k][i].value
                for j in range(4):
                    res += chr(v>>((3-j)*8) & 0xff)

        return res

    def toJSON(self):
        return json.dumps(
                self,
                default=self.encode,
                sort_keys = True)

    def encode(self, o):
        if type(o) == bytes:
            encoded_bytes = base64.b64encode(o).decode('utf-8')
            return json.dumps(encoded_bytes)
        elif type(o) == c_uint32:
            return o.value
        elif type(o) == Chacha:
            return o.__dict__
        else:
            raise TypeError(type(o))




def ROTl(x: c_uint32, n: int):
    a = x.value << n
    x.value = a | (a >> 32)

def copy_cuint32_mat(matrice):
    return [c_uint32(matrice[i].value) for i in range(len(matrice))]

def print_matrice(C):
    for i in range(16):
        print(f"{C.matrice[i].value:08x}", end=" ")
        if i & 3 == 3:
            print()
    print()

def main():
    C = Chacha("Hello, World!" * 10 + "\n2e ligne\nencore plus de donnees dans ce message qui est super long et qui va necessiter beaucoup de blocs de 512 octets")

    print_matrice(C)
    C.next_step()
    print_matrice(C)

    while not C.done:
        C.next_step()

    print("ENCODED DATA :")
    for k in range(len(C.enc_msg)):
        for i in range(16):
            v = C.enc_msg[k][i].value
            print(f"{v:08x}", end="")
    print("\n\nMAC : ", end="")
    for b in C.MAC:
        print(f"{b:02x}", end="")
    print("\n\nDECODED DATA :")
    print(C.decrypt())


if __name__ == "__main__":
    main()
