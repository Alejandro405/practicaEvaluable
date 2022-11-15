import funciones_rsa
import socket_class
import funciones_aes
import constans

""" Paso 0 (Inicializacion de recursos): 
    Generar claves públicas/privadas
    Guardar clave publica en el fichero <pub_TTP.pub>
    Inicializar socket de conexión
"""

asimKey = funciones_rsa.crear_RSAKey()
funciones_rsa.guardar_RSAKey_Publica("pub_TTP.pub", asimKey)
socket = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", constans.TTP_PORT)

