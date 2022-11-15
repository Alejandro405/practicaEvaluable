import funciones_rsa
import socket_class
import funciones_aes
from constans import *

"""
Paso 0 (Inicialización de recursos) : 
    Generar clave pública/privada y almacenar publica en fichero Bob.py
    Recuperar clave pública de TTP del fichero <pub_TTP.pub>
    Iniciar socket de conexión
    Diccionario con los nombres asociados al DNI
"""

asimKey = funciones_rsa.crear_RSAKey()
pubTTP = funciones_rsa.guardar_RSAKey_Publica("pub_TTP.pub", asimKey)
socket = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", TTP_PORT)
socket.conectar()

""" 
Paso 1 (2) :
    Generar clave des sesion (KBT) AES 
    Enviar clave a TTP con la clave p'ublica de TTP
"""

# --------------  Conexiones con TTP finalizadas --> PERMANECER A LA ESCUCHA DEL MENSAJE INICIAL DE ALICE  -------------


socket = socket_class.SOCKET_SIMPLE_TCP(LOCALHOST, BOB_PORT)
socket.escuchar()

""" 
Paso  (6) : 
    Extraer mensaje inicial de Alice (E_KBT, E_KAB)
    Recuperar KAB
    Procesar Desaf'io
    Enviar respuesta del desaf'io con KAB: KAB->[TS + 1]
    Importante revisar identiuficador del mensaje
"""
ts = 0
KAB = []

""" 
Paso  (8) : 
    Descifrar el DNI para obtener la respuesta
    acceder al nombre almacenado en el diccionario
    IMPORTANTE: en caso de que el dni no est'e recogido en el diccionario se enviara la cadena vac'ia
"""
dni = ""
nombre = ""

cifrado, mac, iv = funciones_aes.cifrarAES_GCM()

socket.enviar()