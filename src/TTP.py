import funciones_rsa
import socket_class
import funciones_aes
import constans
import json

"""
Paso 0 (Inicializacion de recursos): 
    Generar claves públicas/privadas
    Guardar clave publica en el fichero <pub_TTP.pub>
    Inicializar socket de conexión, permeneciendo a la espera de peticiones iniciales
"""
asimKey = funciones_rsa.crear_RSAKey()
pubTTP = funciones_rsa.guardar_RSAKey_Publica("pub_TTP.pub", asimKey)
socket = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", constans.TTP_PORT)
socket.escuchar()

""" 
Paso 1 : Recopilar claves de sesion KAT y KBT
    Recibir del socket
    Identificar emisor del mensaje con el primer campo del JSON: "Alice" -> KAT; "Bob" -> KBT
"""
req1 = json.loads(socket.recibir().decode("utf-8"))  # Tupla de 2 componentes (Cifrado con datos, firma)
req2 = json.loads(socket.recibir().decode("utf-8"))  # Tupla de 2 componentes (Cifrado con datos, firma)

KAT = []
KBT = []

""" 
Paso 2 (4) : 
    Permanecer a la espera del la peticion de comunicaci'on
    Generar clave sim'etricade para la petici'on, identificando el origren de la petici'on (X)
    Enviar KAB como: KXT->[Ts, KAB, KYT->[TS, KAB] == M]
"""


TS = 0
KAB = []
M = 0 # Cifrado de TS y KAB
resp4 = [TS, KAB, M]

socket.enviar(json.loads(TS))
