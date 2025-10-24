from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.safestring import SafeString

import json

from .Chacha import Chacha

def create_context(c: Chacha):
    res = ""
    for k in range(len(c.enc_msg)):
        for i in range(16):
            v = c.enc_msg[k][i].value
            res += f"{v:08x}"

    key_str = ""
    for v in c.key:
        key_str += f"{v.value:08x}"

    return {
            "chacha": SafeString(c.toJSON()),
            "key_str": key_str,
            "c1": f"{c.matrice[0].value:08x}",
            "c2": f"{c.matrice[1].value:08x}",
            "c3": f"{c.matrice[2].value:08x}",
            "c4": f"{c.matrice[3].value:08x}",
            "k1": f"{c.matrice[4].value:08x}",
            "k2": f"{c.matrice[4].value:08x}",
            "k3": f"{c.matrice[6].value:08x}",
            "k4": f"{c.matrice[7].value:08x}",
            "k5": f"{c.matrice[8].value:08x}",
            "k6": f"{c.matrice[9].value:08x}",
            "k7": f"{c.matrice[10].value:08x}",
            "k8": f"{c.matrice[11].value:08x}",
            "ct": f"{c.matrice[12].value:08x}",
            "n1": f"{c.matrice[13].value:08x}",
            "n2": f"{c.matrice[14].value:08x}",
            "n3": f"{c.matrice[15].value:08x}",
            "res": res,
        }

@csrf_exempt
def index(request):
    context = {}
    
    if request.method == "POST" and request.headers.get('x-requested-with') == 'XMLHttpRequest':
        message = request.POST.get("message", "")
        c = Chacha("message")
        context = create_context(c)

        if message != "":
            message_hexa = message.encode("utf-8").hex()
            taille_bloc = 512
            taille_bloc_hexa = taille_bloc // 4
            parties = [message_hexa[i:i+taille_bloc_hexa] for i in range(0, len(message_hexa), taille_bloc_hexa)]
            context["parties"] = parties
            context["mac"] =  c.MAC.hex(),

        else:
            print(request.POST)
            data = json.loads(request.body.decode('utf-8'))
            obj = data.get("chacha")
            print(obj)
            c.MAC = obj.get("MAC")
            c.compteur = obj.get("compteur")
            c.done = obj.get("done")
            c.msg_index = obj.get("msg_index")
            c.qr = obj.get("qr")
            c.tour = obj.get("tour")

            c.msg_cint = obj.get("done")
            c.msg = obj.get("done")
            c.matrice = obj.get("done")
            c.keystream = obj.get("done")
            c.key = obj.get("done")
            c.init_matrice = obj.get("done")
            c.enc_msg = obj.get("enc_msg")
            # TODO : reconstruire Chacha à partir du JSON
            # et avance d'une étape




        return JsonResponse(context)

    else:
        c = Chacha("")
        context = create_context(c)


    return render(request, "polls/index.html", context)
