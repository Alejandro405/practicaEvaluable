import json

import funciones_rsa
import socket_class
import funciones_aes
from constans import *
import Tools
from Crypto.Util.Padding import pad

"""
Paso 0 (Inicialización de recursos) : 
    Generar clave pública/privada y almacenar publica en fichero Alice.py
    Recuperar clave pública de TTP del fichero <pub_TTP.pub>
    Iniciar socket de conexión
"""
asimKey = funciones_rsa.crear_RSAKey()  # Pub key = asimKey.publickey()   Priv key = asimkey
pubTTP = funciones_rsa.cargar_RSAKey_Publica("pub_TTP.pub")
funciones_rsa.guardar_RSAKey_Publica("Alice" + ".pub", asimKey)
socket = socket_class.SOCKET_SIMPLE_TCP(LOCALHOST, TTP_PORT)

print("Recursos inicializados. Conectando con TTP")
socket.conectar()

""" 
Paso 1 (1) : 
    Generar clave AT para cifrado en AES con TTP 
    Enviar clave de sesión KAT: E(['Alice', KAT], Pub_TTP) + S(KAT, Priv_A)
"""
KAT = funciones_aes.crear_AESKey()
engineKAT = funciones_aes.iniciarAES_GCM(KAT)
print("Clave KAT" + KAT.hex())

# JSON opera con listas de strings!!
msg = [
    funciones_rsa.cifrarRSA_OAEP(json.dumps([A, KAT.hex()]), pubTTP).hex() # E(...)
    , funciones_rsa.firmarRSA_PSS(KAT, asimKey).hex()                          # S(...)
]

print("\n->" + msg[0] + "\n->" + msg[1] + "\n")

msgJSON = Tools.getJSONMessage(msg)

socket.enviar(msgJSON.encode("utf-8"))

print("Mensaje enviado a TTP con la clave de sesion KAT")

socket.cerrar()

""" exit()
Paso 2 (3) :
    Lanzar petición de conexion con B a TTP
    Permanecer a la espera de la clave de sesi'on del TTP
"""
socket.conectar()
peticionInicial = json.dumps([A, B])  # formato String

cifrado, mac, iv = funciones_aes.cifrarAES_GCM(engineKAT, peticionInicial.encode('utf-8'))

Tools.sendAESMessage(cifrado, mac, iv, socket)

""" 
Paso 3 (4) : Desencriptar: 
    KAT->[Ts, KAB, E_KBT(Ts, K AB) = M].
    E_KBT(...) == cifrado, mac, nonce 
    IMPORTANTE: A inicia el desafío generado por TTP (TS), que B ha de resolver f(n) = TS + 1, donde n = TSs
"""
# Pasamos a la espera de la respuesta de TTP con la clave KAB: E_KAT(Ts, KAB, E_KBT(TS, KAB) == X)

cifrado, mac, iv = Tools.reciveAESMessage()

textoClaro = funciones_aes.descifrarAES_GCM(KAT, iv, cifrado, mac)
if not textoClaro:
    print("[ERROR]   Mensaje alterado durante el envío")
    exit()

# Textoclaro es si o sí un array de bytes

TS, KAB, cifM, macM, ivM = json.loads(textoClaro)
engineKAB = funciones_aes.iniciarAES_GCM(KAB)

# ----------------------  Conexiones con TTP finalizadas   ----------------------
socket.cerrar()
""" 
Paso 3.1 (5) : Enviar X a Bob y mantenerse a la espera de la resoluci'on del desaf'io
    
"""
socket = socket_class.SOCKET_SIMPLE_TCP(LOCALHOST, BOB_PORT)
socket.conectar()

Tools.sendAESMessage(cifM, macM, ivM, socket)

cifrado, mac, iv = Tools.reciveAESMessage(socket)

textoClaro = Tools.checkHMAC_GCM(KAB, iv, cifrado, mac)

resol = json.load(textoClaro)

if resol != TS + 1:
    print("[ERROR] Desafío no superado")
    exit()

""" 
Paso  (7) : 
    Cifrar mensaje: KAB->[DNI]
    Obtener respuesta final
"""

dni = "12345678x"

Tools.sendAESMessage(
    funciones_aes.cifrarAES_GCM(engineKAB, json.dumps(dni))
    , socket
)

cifrado, mac, iv = Tools.reciveAESMessage()

textoClaro = Tools.checkHMAC_GCM(KAB, iv, cifrado, mac)

print("Nombre correspondiente al DNI(" + dni + "): " + textoClaro.decode())



socket.cerrar()