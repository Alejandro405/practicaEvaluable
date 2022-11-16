import json

import funciones_rsa
import socket_class
import funciones_aes
from constans import *
import Tools

"""
Paso 0 (Inicialización de recursos) : 
    Generar clave pública/privada y almacenar publica en fichero Alice.py
    Recuperar clave pública de TTP del fichero <pub_TTP.pub>
    Iniciar socket de conexión
"""
asimKey = funciones_rsa.crear_RSAKey() # Pub key = asimKey.publickey()   Priv key = asimkey
pubTTP = funciones_rsa.guardar_RSAKey_Publica("pub_TTP.pub", asimKey)
funciones_rsa.guardar_RSAKey_Publica("Alice" + ".pub", asimKey)
socket = socket_class.SOCKET_SIMPLE_TCP(LOCALHOST, TTP_PORT)

print("Recursos inicializados. Conectando con TTP")
socket.conectar()

""" 
Paso 1 (1) : 
    Generar clave AT para cifrado en AES con TTP 
"""
KAT = funciones_aes.crear_AESKey()
engineKAT = funciones_aes.iniciarAES_GCM(KAT)
print("Clave KAT" + KAT.hex())

# JSON opera con listas de strings!!
msg = [
    funciones_rsa.cifrarRSA_OAEP_BIN(
        Tools.getJSONMessage([A, KAT.hex()]).encode("utf-8"), asimKey.public_key()
        ).hex()
    , funciones_rsa.firmarRSA_PSS(KAT, asimKey).hex()
]

print("\n->"+msg[0]+"\n->"+msg[1]+"\n")

msgJSON = Tools.getJSONMessage(msg)
socket.enviar(msgJSON.encode("utf-8"))

print("Mensaje enviado a TTP con la clave de sesion KAT")
# exit()
""" 
Paso 2 (3) :
    Lanzar petición de conexion con B a TTP
    Permanecer a la espera de la clave de sesi'on del TTP
"""
peticionInicial = json.dumps([A, B])  # formato String

cifrado, mac, iv = funciones_aes.cifrarAES_GCM(engineKAT, peticionInicial.encode('utf-8'))

""" 
Paso 3 (4) : Desencriptar: 
    KAT->[Ts, KAB, E_KBT(Ts, K AB) = M]. 
    IMPORTANTE: A inicia el desafío generado por TTP (TS), que B ha de resolver f(n) = TS + 1, donde n = TSs
"""
ts = 0
KAB = 0
M = ""

# ----------------------  Conexiones con TTP finalizadas   ----------------------


""" 
Paso 3.1 (5) : Enviar X a Bob y mantenerse a la espera de la resoluci'on del desaf'io
    
"""
socket = socket_class.SOCKET_SIMPLE_TCP(LOCALHOST, BOB_PORT)
socket.conectar()

socket.enviar(M)

""" 
Paso  (7) : 
    Cifrar mensaje: KAB->[DNI]
    Obtener respuesta final
"""
