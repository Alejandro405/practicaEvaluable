import binascii
import json

import funciones_rsa
import socket_class
import funciones_aes
import Tools

from constans import *
from colorama import Fore, Style

"""
Paso 0 (Inicialización de recursos) : 
    Generar clave pública/privada y almacenar publica en fichero Bob.py
    Recuperar clave pública de TTP del fichero <pub_TTP.pub>
    Iniciar socket de conexión
    Diccionario con los nombres asociados al DNI
"""

asimKey = funciones_rsa.crear_RSAKey() # Pub key = asimKey.publickey()   Priv key = asimkey
pubTTP = funciones_rsa.cargar_RSAKey_Publica("pub_TTP.pub")
funciones_rsa.guardar_RSAKey_Publica("Bob.pub", asimKey)
socket = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", TTP_PORT)
datos = {"12345678x":"Eliot", "09876543Y":"MR.Roboot"}


print(Fore.LIGHTGREEN_EX + "[STATUS]   Recursos inicializados. Conectando con TTP...." + Style.RESET_ALL)


""" 
Paso 1 (2) :
    Generar clave des sesion (KBT) AES 
    Enviar clave a TTP con la clave p'ublica de TTP
"""
KBT = funciones_aes.crear_AESKey()
engineKBT = funciones_aes.iniciarAES_GCM(KBT)
# JSON opera con listas de strings!!
print("Clave KBT: " + KBT.hex())

aux = json.dumps([B, KBT.hex()])

cifrado = funciones_rsa.cifrarRSA_OAEP(aux, pubTTP.public_key())
firma = funciones_rsa.firmarRSA_PSS(KBT.hex().encode("utf-8"), asimKey)

print("Firma a enviar: " + firma.hex())

socket.conectar()
socket.enviar(cifrado)
socket.enviar(firma)

print(Fore.CYAN + "[INFO]     Mensaje enviado a TTP con la clave de sesión KBT. Conexiones con TTP finalizadas" + Style.RESET_ALL)

socket.cerrar()

print(Fore.LIGHTGREEN_EX + "[STATUS]   Esperando petici'on de servicio (Alice)" + Style.RESET_ALL)

# --------------  Conexiones con TTP finalizadas --> PERMANECER A LA ESCUCHA DEL MENSAJE INICIAL DE ALICE  -------------


socket = socket_class.SOCKET_SIMPLE_TCP(LOCALHOST, BOB_PORT)
socket.escuchar()

print(Fore.CYAN + "[INFO]     Conexion establecida. Atendiendo cliente (Alice)")

""" 
Paso  (6) : 
    Extraer mensaje inicial de Alice (E_KBT, E_KAB)
    Recuperar KAB
    Procesar Desaf'io
    Enviar respuesta del desaf'io con KAB: KAB->[TS + 1]
    Importante revisar identiuficador del mensaje
"""

response = socket.recibir()

cifradoM, macM, ivM, cifrado, mac, iv = json.loads(response) # [cifradoM, macM, ivM] -> reenvio de A y [cifrado, mac, iv] para KAB

# cifradoM -> TS, KAB
# cifrado -> "Alice", TS

textoClaro = Tools.checkMessage_GCM(binascii.hexlify(KBT), bytes.fromhex(ivM), bytes.fromhex(cifradoM), bytes.fromhex(macM))

TS_S, KAB_S = json.loads(textoClaro)
engineKAB = funciones_aes.iniciarAES_GCM(bytes.fromhex(KAB_S))

textoClaro = Tools.checkMessage_GCM(
    bytes.fromhex(KAB_S)
    , bytes.fromhex(iv)
    , bytes.fromhex(cifrado)
    , bytes.fromhex(mac)
)

idSesion, aux = json.loads(textoClaro)

if idSesion == A and aux == TS_S:
    print(Fore.CYAN + "[INFO]     Id de sesi'on verificado. Time stamps 'integros" + Style.RESET_ALL)
else:
    print(Fore.RED + "[ERROR]    Mensaje inicial mal formulado. Los Time-Stamps han de coincidir, y la identificaci'on ""'Alice'" + Style.RESET_ALL)

print(Fore.CYAN + "[INFO]     Datos de sesi'on recogidos. Resolviendo desaf'io" + Style.RESET_ALL)

resolucion = float(TS_S) + 1

cifrado, mac, iv = funciones_aes.cifrarAES_GCM(engineKAB, str(resolucion).encode("utf-8"))
Tools.sendAESMessage(cifrado, mac, iv, socket)

""" 
Paso  (8) : 
    Descifrar el DNI para obtener la respuesta
    acceder al nombre almacenado en el diccionario
    IMPORTANTE: en caso de que el dni no est'e recogido en el diccionario se enviara la cadena vac'ia
"""

cifrado, mac, iv = Tools.reciveAESMessage(socket)

textoClaro = Tools.checkMessage_GCM(bytes.fromhex(KAB_S), iv, cifrado, mac)

dni = textoClaro.decode("utf-8")

print("DNI ->" + dni)

print(Fore.LIGHTGREEN_EX + "[STATUS]   Procesando respuesta. Cifrando mensaje")

engineKAB = funciones_aes.iniciarAES_GCM(bytes.fromhex(KAB_S))
cifrado, mac, iv = funciones_aes.cifrarAES_GCM(engineKAB, datos[dni].encode("utf-8"))

Tools.sendAESMessage(cifrado, mac, iv, socket)

print(Fore.CYAN + "[INFO]     Respuesta a la peticion de DNI enviada" + Style.RESET_ALL)

print(Fore.LIGHTGREEN_EX + "[STATUS]   Cerrando servicio")

exit()