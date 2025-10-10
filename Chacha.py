from ctypes import c_uint32
from random import randint, seed

class Chacha:
    def __init__(self, msg):
        self.msg = msg.encode("ascii")
        #on complete le message pour pouvoir des blocs de 512 bits (64 octets)
        if len(msg) % 64 != 0:
            self.msg += bytes(64 - len(msg) % 64)

        self.msg_cint = []
        for i in range(16):
            v = c_uint32(int.from_bytes(self.msg[i*4 : (i+1)*4]))
            self.msg_cint.append(v)


        self.init_matrice = [c_uint32() for _ in range(16)]
        self.keystream = [c_uint32() for _ in range(16)]
        self.enc_msg = [c_uint32() for _ in range(16)]

        self.init_matrice[0] = c_uint32(0x65787061)
        self.init_matrice[1] = c_uint32(0x6e642033)
        self.init_matrice[2] = c_uint32(0x322d6279)
        self.init_matrice[3] = c_uint32(0x7465206b)

        self.key = [c_uint32(i) for i in range(8)]
        for i in range(8):
                self.init_matrice[4 + i] = self.key[i]

        self.compteur = c_uint32(1)
        self.init_matrice[12] = c_uint32(self.compteur.value) # copie pour éviter effets de bord

        seed(0) # pour tester c'est plus pratique d'avoir tjrs la meme chose
        # gen nonce
        for i in range(3):
            self.init_matrice[13 + i] = c_uint32(randint(0, 0xffffffff))

        self.matrice = self.init_matrice.copy()

        self.tour = 0
        self.qr = 0

    def next_step(self):
        if self.tour == 10:
            for i in range(16):
                self.keystream[i].value = self.init_matrice[i].value + self.matrice[i].value
                self.enc_msg[i].value = self.keystream[i].value ^ self.msg_cint[i].value
                #TODO faire avancer self.msg_cint

            self.tour = 0
            self.matrice = self.init_matrice.copy()
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
            if self.qr == 1:
                self.QR(c2, k2, k6, n1)
                self.qr += 1
            if self.qr == 2:
                self.QR(c3, k3, k7, n2)
                self.qr += 1
            if self.qr == 3:
                self.QR(c4, k4, k8, n3)
                self.qr += 1
            if self.qr == 4:
                self.QR(c1, k2, k7, n3)
                self.qr += 1
            if self.qr == 5:
                self.QR(c2, k3, k8, ct)
                self.qr += 1
            if self.qr == 6:
                self.QR(c3, k4, k5, n1)
                self.qr += 1
            if self.qr == 7:
                self.QR(c4, k1, k5, n2)
                self.qr += 1

            if self.qr == 8:
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
        for i in range(16):
            v = self.enc_msg[i].value ^ self.keystream[i].value
            for j in range(4):
                res += chr(v>>((3-j)*8) & 0xff)

        return res



def ROTl(x: c_uint32, n: int):
    a = x.value << n
    x.value = a | (a >> 32)

def print_matrice(C):
    for i in range(16):
        print(f"{C.matrice[i].value:08x}", end=" ")
        if i & 3 == 3:
            print()
    print()

def main():
    a = c_uint32(0xff00ff00)
    ROTl(a, 8)
    print(f"{a.value:08x}")
    ROTl(a, 4)
    print(f"{a.value:08x}")
    print()

    C = Chacha("Hello, World!" * 100 + "\n2e ligne")

    print_matrice(C)
    C.next_step()
    print_matrice(C)

    for i in range(500):
        C.next_step()

    for i in range(16):
        print(f"{C.enc_msg[i].value:08x}", end="")
    print()

    print(C.decrypt())



if __name__ == "__main__":
    main()
