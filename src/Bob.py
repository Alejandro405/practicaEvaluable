import funciones_rsa
import socket_class
import funciones_aes
import constans

asimKey = funciones_rsa.crear_RSAKey()
pubTTP = funciones_rsa.guardar_RSAKey_Publica("pub_TTP.pub", asimKey)
socket = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", constans.BOB_PORT)