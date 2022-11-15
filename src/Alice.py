import funciones_rsa
import socket_class
import funciones_aes
import constans
"""
Paso 0 (Inicialización de recursos) : 
    Generar clave pública/privada y almacenar publica en fichero Alice.py
    Recuperar clave pública de TTP del fichero <pub_TTP.pub>
    Iniciar socket de conexión"""


asimKey = funciones_rsa.crear_RSAKey()
pubTTP = funciones_rsa.guardar_RSAKey_Publica("pub_TTP.pub", asimKey)
socket = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", constans.ALICE_PORT)

""" Paso 1.1 (1) : generar clave AT para cifrado en AES con TTP """

""" Paso 2 (3) : Lanzar petición de conexion con B a TTP"""

"""Paso 3 (4) : Desencriptar: KAT->[Ts, KAB, E_KBT(Ts, K AB) = X]. IMPORTANTE: A inicia el desafío generado por TTP
(TS), que B ha de resolver, n = Ts y f(n) = TS + 1"""
ts = 0
x = ""
""" Paso 3.1 (5) : Enviar X a Bob y mantenerse a la espera"""

""" Paso  () : """
""" Paso  () : """
""" Paso  () : """
""" Paso  () : """

