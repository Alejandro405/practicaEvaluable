from src.socket_class import *
from src.constans import *


socket = SOCKET_SIMPLE_TCP(LOCALHOST, 55600)


print("asdfasdf")

i = 0
while True:
    print("Iterac: " + str(i))
    socket.escuchar()
    aux = socket.recibir()

    print("Reciv: " + str(float(aux)) + " -> " + str(float(aux)+ 1) )
    i = i + 1








