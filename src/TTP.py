import funciones_rsa
import socket_class
import funciones_aes
import json
import Tools

from Crypto.Util.Padding import pad, unpad
from datetime import datetime
from constans import *

"""
Paso 0 (Inicializacion de recursos): 
    Generar claves públicas/privadas
    Guardar clave publica en el fichero <pub_TTP.pub>
    Inicializar socket de conexión, permeneciendo a la espera de peticiones iniciales
"""
asimKey = funciones_rsa.crear_RSAKey()# Pub key = asimKey.publickey()   Priv key = asimkey
funciones_rsa.guardar_RSAKey_Publica("pub_TTP.pub", asimKey.public_key())
socket = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", TTP_PORT)

print("Recursos inicializados. Esperando clientes....")
socket.escuchar()

""" 
Paso 1 : Recopilar claves de sesion KAT y KBT
    Recibir del socket -> [cifrado(Id, clave), firma(clave)]
    Identificar emisor del mensaje con el primer campo del JSON: "Alice" -> KAT; "Bob" -> KBT
"""
aux = json.loads(socket.recibir().decode("utf-8"))  # Tupla de 2 componentes (Cifrado con datos, firma)
cifradoSesion, firmaSesionA = aux[0], aux[1] # Dos string
engineKAT = None

print("\n-> "+ cifradoSesion +"\n-> "+firmaSesionA + "\n")
id, claveSesion = funciones_rsa.descifrarRSA_OAEP(cifradoSesion.encode("utf-8"), asimKey)

if id == A:
    if funciones_rsa.comprobarRSA_PSS(claveSesion.encode("utf-8"), firmaSesionA.encode("utf-8"), asimKey.public_key()):
        KAT = claveSesion
        engineKAT = funciones_aes.iniciarAES_GCM(KAT)
    else:
        print("[ERROR]   Firmas alteradas durante el envío")
        exit()
else:
    print("[ERROR]   Mensaje de orijen no válido")
    exit()
socket.escuchar()


cifradoSesionB, firmaSesionB = json.loads(socket.recibir())  # Tupla de 2 componentes (Cifrado con datos, firma)
engineKBT = None
id, claveSesion = json.loads(funciones_rsa.descifrarRSA_OAEP(cifradoSesion, asimKey))
if id == B:
    if funciones_rsa.comprobarRSA_PSS(claveSesion, firmaSesionB, asimKey):
        KBT = claveSesion
        engineKBT = funciones_aes.iniciarAES_GCM(KBT)
    else:
        print("[ERROR]   Firmas alteradas durante el envío")
        exit()
else:
    print("[ERROR]   Mensaje de orijen no válido")
    exit()



socket.escuchar()

""" 
Paso 2 (4) : 
    Permanecer a la espera del la peticion de comunicaci'on
    Generar clave sim'etricade para la petici'on, identificando el origren de la petici'on (X)
    Enviar KAB como: KXT->[Ts, KAB, KYT->[TS, KAB] == M]
"""

origen, destino = json.loads(socket.recibir())

if origen != A and destino != B:
    print("[ERROR]   Petición no recogida en el protocolo")

print("Peticion de conexión A-B, recibida con éxito. Procesando, espere.....")

TS = datetime.timestamp(datetime.now())
KAB = funciones_aes.crear_AESKey()
engineKAB = funciones_aes.iniciarAES_GCM(KAB)
print("\tClave de sesión AB generada")
aux  = json.dumps([TS.hex(), KAB.hex()])
cifM, macM, ivM = funciones_aes.cifrarAES_GCM(engineKAB, aux) # Cifrado de TS y KAB
msg = json.dumps([TS.hex(), KAB.hex(), cifM, macM, ivM])
Tools.sendAESMessage(funciones_aes.cifrarAES_GCM(engineKAT, msg), socket)

socket.cerrar()
