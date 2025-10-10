from ctypes import *

key = b'1234567890abcdef'
msg = b'jaidesprblemesjemedisputainzebiiii'

print(len(key))

def little_end(key):
    return key[::-1]

def break_msg(msg):
    chunks = [msg[i:i+16] for i in range(0, len(msg), 16)]
    
    if chunks and len(chunks[-1]) < 16:
        chunks[-1] = chunks[-1].ljust(16, b'\x00')

    return chunks

def poly(chunks):
    new_chunks = []
    for chunk in chunks:
        chunk_17 = chunk + b'\x01'
        new_chunks.append(chunk_17)
    return new_chunks

def eval_poly_mod(poly, key, p=(2**130 - 5)):

    key_int = int.from_bytes(key, 'little')
    result = 0
    power_of_key = 1

    for coeff_bytes in poly:
        coeff = int.from_bytes(coeff_bytes, 'little')
        result = (result + coeff * power_of_key) % p
        power_of_key = (power_of_key * key_int) % p

    return result.to_bytes(17, 'little')

def reduce(eval):

    result_int = int.from_bytes(eval, 'little')
    reduced_int = result_int & ((1 << 128) - 1)
    return reduced_int.to_bytes(16, 'little')


def poly1305(key, msg):
    interpreted_key = little_end(key)
    divided_msg = break_msg(msg)
    pl = poly(divided_msg)
    eval = eval_poly_mod(pl, interpreted_key)
    return reduce(eval)


print(poly1305(key, msg))