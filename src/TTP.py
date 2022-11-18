
import socket_class
import funciones_aes
import json
import Tools

from Crypto.Util.Padding import pad, unpad
from datetime import datetime
from colorama import Fore, Style
from constans import *
from funciones_rsa import *
"""
Paso 0 (Inicializacion de recursos): 
    Generar claves públicas/privadas
    Guardar clave publica en el fichero <pub_TTP.pub>
    Inicializar socket de conexión, permeneciendo a la espera de peticiones iniciales
"""
asimKey =  crear_RSAKey()# Pub key = asimKey.publickey()   Priv key = asimkey
guardar_RSAKey_Publica("pub_TTP.pub", asimKey)
socket = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", TTP_PORT)

print(Fore.LIGHTGREEN_EX + "[STATUS]   Recursos inicializados. Esperando cliente (Alice)...." + Style.RESET_ALL)
socket.escuchar()

pub_Alice = cargar_RSAKey_Publica("Alice.pub")

""" 
Paso 1 : Recopilar claves de sesion KAT y KBT
    Recibir del socket -> [cifrado(Id, clave), firma(clave)]
    Identificar emisor del mensaje con el primer campo del JSON: "Alice" -> KAT; "Bob" -> KBT
"""
cifradoSesion = socket.recibir()
firmaSesionA = socket.recibir()

print("Cifrado -> " + cifradoSesion.hex())
print("Firma -> " + firmaSesionA.hex())

engineKAT = None

response = descifrarRSA_OAEP_BIN(cifradoSesion, asimKey)

print("Response: " + response.decode("utf-8"))

idSesion, KAT_S = json.loads(response)

if not comprobarRSA_PSS(KAT_S.encode("utf-8"), firmaSesionA, pub_Alice):
    print(Fore.RED + "[ERROR]   Firmas alteradas durante el envío" + Style.RESET_ALL)
    exit()

print(Fore.CYAN + "[INFO]     Firma válidada con éxito. Emisor autenticado"+ Style.RESET_ALL)

if A != idSesion:
    print(Fore.RED + "[ERROR]   Mensaje con identificador no válido"+ Style.RESET_ALL)
    exit()

engineKAT = funciones_aes.iniciarAES_GCM(KAT_S.encode("utf-8"))
print(Fore.LIGHTGREEN_EX + "[STATUS]   Petición resuelta con esxito. Esperando cliente (Bob)"+ Style.RESET_ALL)



# -----------------   Cliente [Alice] registrado   -----------------


socket.escuchar()
print(Fore.CYAN + "[INFO]   Atendiendo nuevo cliente (Bob)" + Style.RESET_ALL)
pub_Bob = cargar_RSAKey_Publica("Bob.pub")

cifradoSesionB = socket.recibir()
firmaSesionB = socket.recibir()  # KBT.hex().encode("utf-8")

print("Cifrado ->" + cifradoSesionB.hex())
print("Firma ->" + firmaSesionB.hex())  # Las firmas son iguales hasta aqu'i
engineKBT = None

response = descifrarRSA_OAEP_BIN(cifradoSesionB, asimKey)

print("Response: " + response.decode("utf-8") + "")

idSesion, KBT_S = json.loads(descifrarRSA_OAEP(cifradoSesionB, asimKey))

if not comprobarRSA_PSS(KBT_S.encode("utf-8"), firmaSesionB, pub_Bob):
    print(Fore.RED + "[ERROR]   Firmas alteradas durante el envío" + Style.RESET_ALL)
    exit()

print(Fore.CYAN + "[INFO]     Firma válidada con éxito. Emisor autenticado"+ Style.RESET_ALL)

if B != idSesion:
    print(Fore.RED + "[ERROR]   Mensaje de orijen no válido" + Style.RESET_ALL)
    exit()

engineKBT = funciones_aes.iniciarAES_GCM(KBT_S.encode("utf-8"))
print(Fore.LIGHTGREEN_EX + "[STATUS]   Petición resuelta con esxito. Esperando cliente (Petición de conexion A<->B de Alice)"+ Style.RESET_ALL)


socket.escuchar()




""" 
Paso 4 (4) : 
    Permanecer a la espera del la peticion de comunicaci'on
    Generar clave sim'etricade para la petici'on, identificando el origren de la petici'on (X)
    Enviar KAB como: KXT->[Ts, KAB, KYT->[TS, KAB] == M]
"""

origen, destino = json.loads(socket.recibir())

if origen != A and destino != B:
    print(Fore.RED + "[ERROR]   Petición no recogida en el protocolo" + Style.RESET_ALL)

print(Fore.CYAN + "[INFO]     Peticion de conexión A-B, recibida con éxito. Procesando, espere....."+ Style.RESET_ALL)

TS = datetime.timestamp(datetime.now())
KAB = funciones_aes.crear_AESKey()
engineKAB = funciones_aes.iniciarAES_GCM(KAB)
print("Clave de sesión AB generada")
aux = json.dumps([TS.hex(), KAB.hex()]) # Para el cifrado KBT


cifM, macM, ivM = funciones_aes.cifrarAES_GCM(engineKAB, aux.encode("utf-8")) # Cifrado de TS y KAB
msg = json.dumps([TS.hex(), KAB.hex(), cifM.hex(), macM.hex(), ivM.hex()]) # cifM, macM, ivM == E_KBT


cifrado, mac, iv = funciones_aes.cifrarAES_GCM(engineKAT, msg.encode("utf-8"))

socket.enviar(cifrado)
socket.enviar(mac)
socket.enviar(iv)

print("cifrado KAT-> " + str(cifrado))
print("mac KAT-> " + str(mac))
print("iv KAT-> " + str(iv))

print(Fore.CYAN + "[INFO]     Petici'on de conexi'on resuelta" + Style.RESET_ALL)
print(Fore.LIGHTGREEN_EX + "[STATUS]   Closing service")

exit()
