from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.safestring import SafeString
from copy import deepcopy

from ctypes import c_uint32

from .Chacha import Chacha

previous_states = []

def create_context(chacha: Chacha):
    res = ""
    for k in range(len(chacha.enc_msg)):
        for i in range(16):
            v = chacha.enc_msg[k][i].value
            res += f"{v:08x}"

    key_str = ""
    for v in chacha.key:
        key_str += f"{v.value:08x}"

    decrypt = chacha.decrypt()
    
    return {
            "key_str": key_str,
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
            "mac": chacha.MAC.hex(),
            "res": res,
            "decrypt": decrypt,
            "tour": chacha.tour,
            "qr": chacha.qr,
            "keystream": " ".join(f"{x.value:08x}" for x in chacha.init_matrice[:4]),
            "mackey": "".join(f"{x.value:08x}" for x in chacha.init_matrice[:8]),
            "xorres": "",
            "msghex": chacha.msg.hex(),
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
