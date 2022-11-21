import binascii
import json
import time
import Tools
import socket_class
import funciones_aes

from funciones_rsa import *
from colorama import Fore, Style
from constans import *

"""
Paso 0 (Inicialización de recursos) : 
    Generar clave pública/privada y almacenar publica en fichero Alice.py
    Recuperar clave pública de TTP del fichero <pub_TTP.pub>
    Iniciar socket de conexión
"""
asimKey = crear_RSAKey()  # Pub key = asimKey.publickey()   Priv key = asimkey
guardar_RSAKey_Publica("Alice.pub", asimKey)
socket = socket_class.SOCKET_SIMPLE_TCP(LOCALHOST, TTP_PORT)
pubTTP = cargar_RSAKey_Publica("pub_TTP.pub")

print(Fore.LIGHTGREEN_EX + "[STATUS]   Recursos inicializados. Conectando con TTP" + Style.RESET_ALL)
socket.conectar()

""" 
Paso 1 (1) : 
    Generar clave AT para cifrado en AES GCM con TTP 
    Enviar clave de sesión KAT: E(['Alice', KAT], Pub_TTP) + S(KAT, Priv_A)
"""
KAT = funciones_aes.crear_AESKey()
engineKAT = funciones_aes.iniciarAES_GCM(KAT)
print("Clave KAT generada : " + KAT.hex())
aux = json.dumps([A, KAT.hex()])

cifrado = cifrarRSA_OAEP(aux, pubTTP.public_key())
firma = firmarRSA_PSS(KAT.hex().encode("utf-8"), asimKey)

socket.enviar(cifrado)
socket.enviar(firma)

print(Fore.CYAN + "[INFO]     Mensaje enviado a TTP con la clave de sesion KAT" + Style.RESET_ALL)

socket.cerrar()

inp = input(Fore.YELLOW + "¿Ha enviado bob las claves? [Presione cualquier tecla para continuar]" + Style.RESET_ALL)

""" 
Paso 2 (3) :
    Lanzar petición de conexión con B a TTP
    Permanecer a la espera de la clave de sesión del TTP
"""
socket.conectar()
peticionInicial = json.dumps([A, B])  # formato String
socket.enviar(peticionInicial.encode("utf-8"))

print(Fore.LIGHTGREEN_EX + "[STATUS]   Petición de sesión enviada, esperando clave de sesión KAB" + Style.RESET_ALL)
""" 
Paso 3 (4) : 
    Recibir Mensaje de respuesta de TTP
    Desencriptar mensaje: KAT->[Ts, KAB, E_KBT(Ts, K AB) = M].
    IMPORTANTE: A inicia el desafío generado por TTP (TS), que B ha de resolver f(n) = TS + 1, donde n = TSs
"""

cifrado = socket.recibir()
mac = socket.recibir()
iv = socket.recibir()

textoClaro = Tools.checkMessage_GCM(binascii.hexlify(KAT), iv, cifrado, mac)


TS_S, KAB_S, cifM_S, macM_S, ivM_S = json.loads(textoClaro)
print(Fore.CYAN + "[INFO]     Clave de sesión recibida. Estableciendo conexión con Bob" + Style.RESET_ALL)

# ----------------------  Conexiones con TTP finalizadas   ----------------------


socket.cerrar()

""" 
Paso 3.1 (5) : 
    Enviar X a Bob 
    Mantenerse a la espera de la resolución del desafío por parte de Bob
"""

socket = socket_class.SOCKET_SIMPLE_TCP(LOCALHOST, BOB_PORT)
engineKAB = funciones_aes.iniciarAES_GCM(bytes.fromhex(KAB_S))
socket.conectar()

print(Fore.LIGHTGREEN_EX + "[STATUS]   Conexión con Bob establecida" + Style.RESET_ALL)

cifrado, mac, iv = funciones_aes.cifrarAES_GCM(engineKAB, json.dumps([A, TS_S]).encode("utf-8"))
msg = json.dumps([cifM_S, macM_S, ivM_S, cifrado.hex(), mac.hex(), iv.hex()])

socket.enviar(msg.encode("utf-8"))

cifrado, mac, iv = Tools.reciveAESMessage(socket)
textoClaro = Tools.checkMessage_GCM(bytes.fromhex(KAB_S), iv, cifrado, mac)

if float(textoClaro) != float(TS_S) + 1:
    print(Fore.RED + "[ERROR]   Desafío no superado" + Style.RESET_ALL)
    exit()

""" 
Paso  (7) : 
    Cifrar petición de servicio: KAB->[DNI]
    Obtener respuesta final
"""

dni = "77431443B"  # DNI Personal -> respuesta esperada "Alejandro Téllez Montiel"
engineKAB = funciones_aes.iniciarAES_GCM(bytes.fromhex(KAB_S))
cifrado, mac, iv = funciones_aes.cifrarAES_GCM(engineKAB, dni.encode("utf-8"))

Tools.sendAESMessage(
    cifrado
    , mac
    , iv
    , socket
)

print(Fore.LIGHTGREEN_EX + "[STATUS]   Petición enviada esperando respuesta" + Style.RESET_ALL)

cifrado, mac, iv = Tools.reciveAESMessage(socket)

textoClaro = Tools.checkMessage_GCM(bytes.fromhex(KAB_S), iv, cifrado, mac)

print("Nombre correspondiente al DNI(" + dni + "): " + textoClaro.decode())

print(Fore.LIGHTGREEN_EX + "[STATUS]   Petición resuelta" + Style.RESET_ALL)

socket.cerrar()
