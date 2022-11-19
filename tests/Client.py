from datetime import *

import json
import Tools
import funciones_aes

from socket_class import *
from constans import *
from colorama import Fore, Style

KAB = funciones_aes.crear_AESKey()
KBT = open("KBT.bin", "rb").read()
engineKAB = funciones_aes.iniciarAES_GCM(KAB)
engineKBT = funciones_aes.iniciarAES_GCM(KBT)
KAB_S = KAB.hex()
TS_S = str(datetime.timestamp(datetime.now()))

socket = SOCKET_SIMPLE_TCP(LOCALHOST, 55600)

socket.conectar()

print(Fore.LIGHTGREEN_EX + "[STATUS]   Conexión con Bob establecida" + Style.RESET_ALL)


cifrdo, mac, iv = funciones_aes.cifrarAES_GCM(engineKBT, ("[" + TS_S + ", " + KAB_S +"]").encode("utf-8"))

cifM_S, macM_S, ivM_S = json.loads(json.dumps(funciones_aes.descifrarAES_GCM(KBT, iv, cifrdo, mac)))

cifrado, mac, iv = funciones_aes.cifrarAES_GCM(engineKAB, json.dumps([A, TS_S]))
msg = json.dumps([cifM_S, macM_S, ivM_S, cifrado.hex(), mac(), iv.hex()])

socket.enviar(msg.encode("utf-8"))

cifrado, mac, iv = Tools.reciveAESMessage(socket)
textoClaro = Tools.checkHMAC_GCM(KAB_S, iv, cifrado, mac)
resol = json.loads(textoClaro)

if resol != float(TS_S) + 1:
    print(Fore.RED + "[ERROR]   Desafío no superado")
    exit()

""" 
Paso  (7) : 
    Cifrar mensaje: KAB->[DNI]
    Obtener respuesta final
"""

dni = "12345678x"

Tools.sendAESMessage(
    funciones_aes.cifrarAES_GCM(engineKAB, dni)
    , socket
)

print(Fore.LIGHTGREEN_EX + "[STATUS]   Petici'on enviada esperando respuesta" + Style.RESET_ALL)

cifrado, mac, iv = Tools.reciveAESMessage()

textoClaro = Tools.checkHMAC_GCM(KAB_S, iv, cifrado, mac)

print("Nombre correspondiente al DNI(" + dni + "): " + textoClaro.decode())

socket.cerrar()

"""
socket = SOCKET_SIMPLE_TCP(LOCALHOST, 55600)

socket.conectar()
socket.enviar(str(datetime.timestamp(datetime.now())).encode("utf-8"))
socket.cerrar()

socket.conectar()
socket.enviar(str(datetime.timestamp(datetime.now())).encode("utf-8"))
socket.cerrar()

socket.conectar()
socket.enviar(str(datetime.timestamp(datetime.now())).encode("utf-8"))
socket.cerrar()

socket.conectar()
socket.enviar(str(datetime.timestamp(datetime.now())).encode("utf-8"))
socket.cerrar()
"""