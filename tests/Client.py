from src.socket_class import *
from src.constans import *
from datetime import *


socket = SOCKET_SIMPLE_TCP(LOCALHOST, 55600)

socket.conectar()
socket.enviar(str(datetime.timestamp(datetime.now())).encode("utf-8"))
socket.cerrar()

socket.conectar()
socket.enviar(str(datetime.timestamp(datetime.now())).encode("utf-8"))
socket.cerrar()

socket.conectar()
socket.enviar(str(datetime.timestamp(datetime.now())).encode("utf-8"))
socket.cerrar()

socket.conectar()
socket.enviar(str(datetime.timestamp(datetime.now())).encode("utf-8"))
socket.cerrar()