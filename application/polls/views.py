from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.safestring import SafeString
from copy import deepcopy

from ctypes import c_uint32

from .Chacha import Chacha

previous_states = []

def create_context(chacha: Chacha):
    # --- Résultat chiffré (concaténé sur tous les blocs)
    res = ""
    for k in range(len(chacha.enc_msg)):
        for i in range(16):
            v = chacha.enc_msg[k][i].value
            res += f"{v:08x}"

    # --- Clé principale (clé ChaCha20)
    key_str = "".join(f"{v.value:08x}" for v in chacha.key)

    # --- Décryptage du message
    decrypt = chacha.decrypt()

    # --- Message original en hexadécimal (pour affichage XOR)
    msg_hex = chacha.msg.hex()

    # --- Keystream actuel (si généré)
    if chacha.keystream:
        last_keystream = chacha.keystream[-1]
        keystream_hex = " ".join(f"{x.value:08x}" for x in last_keystream)
    else:
        keystream_hex = "—"

    # --- Calcul d’un XOR partiel (visuel)
    if chacha.enc_msg and chacha.keystream:
        xor_preview = []
        for i in range(min(4, len(chacha.enc_msg[-1]))):
            v_enc = chacha.enc_msg[-1][i].value
            v_key = chacha.keystream[-1][i].value
            xor_preview.append(f"{v_enc ^ v_key:08x}")
        xor_hex = " ".join(xor_preview)
    else:
        xor_hex = "—"

    # --- Clé dérivée pour Poly1305 (premier bloc ChaCha20 avec compteur=0)
    try:
        mac_key = "".join(f"{x.value:08x}" for x in chacha.init_matrice[:8])
    except Exception:
        mac_key = "—"

    return {
        "c1": f"{chacha.matrice[0].value:08x}",
        "c2": f"{chacha.matrice[1].value:08x}",
        "c3": f"{chacha.matrice[2].value:08x}",
        "c4": f"{chacha.matrice[3].value:08x}",
        "k1": f"{chacha.matrice[4].value:08x}",
        "k2": f"{chacha.matrice[5].value:08x}",
        "k3": f"{chacha.matrice[6].value:08x}",
        "k4": f"{chacha.matrice[7].value:08x}",
        "k5": f"{chacha.matrice[8].value:08x}",
        "k6": f"{chacha.matrice[9].value:08x}",
        "k7": f"{chacha.matrice[10].value:08x}",
        "k8": f"{chacha.matrice[11].value:08x}",
        "ct": f"{chacha.matrice[12].value:08x}",
        "n1": f"{chacha.matrice[13].value:08x}",
        "n2": f"{chacha.matrice[14].value:08x}",
        "n3": f"{chacha.matrice[15].value:08x}",
        "tour": chacha.tour,
        "qr": chacha.qr,
        "key_str": key_str,
        "mac": chacha.MAC.hex(),
        "res": res,
        "decrypt": decrypt,
        "msghex": msg_hex,
        "keystream": keystream_hex,
        "xorres": xor_hex,
        "mackey": mac_key,
    }

@csrf_exempt
def index(request):
    global previous_states

    context = {}
    
    if request.method == "POST" and request.headers.get('x-requested-with') == 'XMLHttpRequest':
        message = request.POST.get("message", "")
        command = request.POST.get("command", "")

        if message != "":
            message_hexa = message.encode("utf-8").hex()
            taille_bloc = 512
            taille_bloc_hexa = taille_bloc // 4
            parties = [message_hexa[i:i+taille_bloc_hexa] for i in range(0, len(message_hexa), taille_bloc_hexa)]

            c = Chacha(message)
            context = create_context(c)
            context["parties"] = parties

            previous_states = [c]

            return JsonResponse(context)

        elif command == "next":
            prev = previous_states[-1]

            c = Chacha(prev.msg.decode(encoding="ascii"))

            c.MAC = prev.MAC
            c.compteur = prev.compteur
            c.done = prev.done
            c.msg_index = prev.msg_index
            c.qr = prev.qr
            c.tour = prev.tour

            c.msg_cint = deepcopy(prev.msg_cint)
            c.matrice = deepcopy(prev.matrice)
            c.init_matrice = deepcopy(prev.init_matrice)
            c.key = deepcopy(prev.key)

            c.keystream = deepcopy(prev.keystream)
            c.enc_msg = deepcopy(prev.enc_msg)

            c.next_step()
            previous_states.append(c)

            context = create_context(c)
            return JsonResponse(context)

        elif command == "previous":
            if len(previous_states) > 2:
                previous_states.pop()

                prev = previous_states[-1]
        
                context = create_context(prev)
                return JsonResponse(context)

        elif command == "reset":
            previous_states = [previous_states[0]]
            return JsonResponse(create_context(previous_states[0]))

    else:
        c = Chacha("")
        context = create_context(c)


    return render(request, "polls/index.html", context)
