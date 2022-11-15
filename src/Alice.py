import json

import funciones_rsa
import socket_class
import funciones_aes
from constans import *

"""
Paso 0 (Inicialización de recursos) : 
    Generar clave pública/privada y almacenar publica en fichero Alice.py
    Recuperar clave pública de TTP del fichero <pub_TTP.pub>
    Iniciar socket de conexión
"""
asimKey = funciones_rsa.crear_RSAKey()
pubTTP = funciones_rsa.guardar_RSAKey_Publica("pub_TTP.pub", asimKey)
socket = socket_class.SOCKET_SIMPLE_TCP(LOCALHOST, TTP_PORT)
socket.conectar()

""" 
Paso 1 (1) : 
    Generar clave AT para cifrado en AES con TTP 
"""

""" 
Paso 2 (3) :
    Lanzar petición de conexion con B a TTP
    Permanecer a la espera de la clave de sesi'on del TTP
"""
peticionInicial = json.dumps([A, B])  # formato String

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
