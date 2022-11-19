import json
import Tools
import funciones_aes

from socket_class import *
from constans import *
from colorama import Fore, Style


datos = {"12345678x":"Eliot", "09876543Y":"MR.Roboot"}
KBT = open("KBT.bin", "rb").read()

socket = SOCKET_SIMPLE_TCP(LOCALHOST, 55600)
socket.escuchar()

print(Fore.CYAN + "[INFO]     Conexion establecida. Atendiendo cliente (Alice)")

""" 
Paso  (6) : 
    Extraer mensaje inicial de Alice (E_KBT, E_KAB)
    Recuperar KAB
    Procesar Desaf'io
    Enviar respuesta del desaf'io con KAB: KAB->[TS + 1]
    Importante revisar identiuficador del mensaje
"""

response = socket.recibir()

cifradoM, macM, ivM, cifrado, mac, iv = json.loads(response) # [cifradoM, macM, ivM] -> reenvio de A y [cifrado, mac, iv] para KAB

# cifradoM -> TS, KAB
# cifrado -> "Alice", TS

textoClaro = Tools.checkMessage_GCM(KBT, ivM.encode("utf-8"), cifradoM.encode("utf-8"), macM.encode("utf-8"))

TS_S, KAB_S = json.loads(textoClaro)
engineKAB = funciones_aes.iniciarAES_GCM(KAB_S.encode("utf-8"))

textoClaro = Tools.checkMessage_GCM(
    KAB_S.encode("utf-8")
    , iv.encode("utf-8")
    , cifrado.encode("utf-8")
    , mac.encode("utf-8")
)

idSesion, aux = json.loads(textoClaro)

if idSesion == A and aux == TS_S:
    print(Fore.CYAN + "[INFO]   Id de sesi'on verificado. Time stamps 'integros" + Style.RESET_ALL)
else:
    print(Fore.RED + "[ERROR]   Mensaje inicial mal formulado. Los Time-Stamps han de coincidir, y la identificaci'on ""'Alice'" + Style.RESET_ALL)

print(Fore.CYAN + "[INFO]     Datos de sesi'on recogidos. Resolviendo desaf'io" + Style.RESET_ALL)

resolucion = float(TS_S) + 1
""" 
Paso  (8) : 
    Descifrar el DNI para obtener la respuesta
    acceder al nombre almacenado en el diccionario
    IMPORTANTE: en caso de que el dni no est'e recogido en el diccionario se enviara la cadena vac'ia
"""

cifrado, mac, iv = Tools.reciveAESMessage(socket)

textoClaro = Tools.checkMessage_GCM(KAB_S.encode("utf-8"), iv, cifrado, mac)

dni = textoClaro.decode("utf-8")

print("DNI ->" + dni)

print(Fore.LIGHTGREEN_EX + "[STATUS]   Procesando respuesta. Cifrando mensaje")

cifrado, mac, iv = funciones_aes.cifrarAES_GCM(datos[dni])

Tools.sendAESMessage(cifrado, mac, iv)

print(Fore.CYAN + "[INFO]     Respuesta a la peticion de DNI enviada" + Style.RESET_ALL)

print(Fore.LIGHTGREEN_EX + "[STATUS]   Cerrando servicio")

exit()

"""
socket = SOCKET_SIMPLE_TCP(LOCALHOST, 55600)


print("asdfasdf")

i = 0
while True:
    print("Iterac: " + str(i))
    socket.escuchar()
    aux = socket.recibir()

    print("Reciv: " + str(float(aux)) + " -> " + str(float(aux)+ 1) )
    i = i + 1
"""