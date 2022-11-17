import base64

from socket_class import SOCKET_SIMPLE_TCP

import funciones_aes, funciones_rsa
import hashlib
import hmac
import json
import constans
from Crypto.Cipher import AES, PKCS1_OAEP


asimKey = funciones_rsa.crear_RSAKey()



textoClaro = ["Alice", funciones_aes.crear_AESKey().hex()]

"A".encode()

criptograma = funciones_rsa.cifrarRSA_OAEP(json.dumps(textoClaro), asimKey.public_key())

print("Texto Claro: " + json.dumps(textoClaro))
print("Criptograma: " + criptograma.hex())

print( json.loads(funciones_rsa.descifrarRSA_OAEP_BIN(criptograma, asimKey)))


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