from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .Chacha import Chacha

@csrf_exempt
def index(request):
    context = {}
    
    if request.method == "POST" and request.headers.get('x-requested-with') == 'XMLHttpRequest':
        message = request.POST.get("message", "")
        message_hexa = message.encode("utf-8").hex()
        taille_bloc = 512
        taille_bloc_hexa = taille_bloc // 4
        parties = [message_hexa[i:i+taille_bloc_hexa] for i in range(0, len(message_hexa), taille_bloc_hexa)]

        c = Chacha(message)

        while not c.done:
            c.next_step()

        res = ""
        for k in range(len(c.enc_msg)):
            for i in range(16):
                v = c.enc_msg[k][i].value
                res += f"{v:08x}"

        key_str = ""
        for v in c.key:
            key_str += f"{v.value:08x}"

        context = {
                # "c": c,
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
                "mac": c.MAC.hex(),
                "parties": parties,
            }

        return JsonResponse(context)

    return render(request, "polls/index.html", context)
