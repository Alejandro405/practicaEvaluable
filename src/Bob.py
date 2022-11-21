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
datos = {
    "12345678x":"Eliot",
    "09876543Y":"MR.Roboot",
    "77431443B":"Alejandro Téllez Montiel"
}


print(Fore.LIGHTGREEN_EX + "[STATUS]   Recursos inicializados. Conectando con TTP...." + Style.RESET_ALL)


""" 
Paso 1 (2) :
    Generar clave de sesión (KBT) 
    Enviar clave de sesión a TTP con la clave pública de TTP junto a la firma del mensaje
"""
KBT = funciones_aes.crear_AESKey()
engineKBT = funciones_aes.iniciarAES_GCM(KBT)

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

print(Fore.LIGHTGREEN_EX + "[STATUS]   Esperando petición de servicio (Alice)" + Style.RESET_ALL)

# --------------  Conexiones con TTP finalizadas --> PERMANECER A LA ESCUCHA DEL MENSAJE INICIAL DE ALICE  -------------


socket = socket_class.SOCKET_SIMPLE_TCP(LOCALHOST, BOB_PORT)
socket.escuchar()

print(Fore.CYAN + "[INFO]     Conexion establecida. Atendiendo cliente (Alice)")

""" 
Paso  (6) : 
    Extraer mensaje inicial de Alice (E_KBT, E_KAB)
    Recuperar KAB
    Procesar Desafío
    Enviar respuesta del desafío con KAB: KAB->[TS + 1]
"""

response = socket.recibir()

cifradoM, macM, ivM, cifrado, mac, iv = json.loads(response)


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
    print(Fore.CYAN + "[INFO]     Id de sesión verificado. Time stamps íntegros" + Style.RESET_ALL)
else:
    print(Fore.RED + "[ERROR]    Mensaje inicial mal formulado. Los Time-Stamps han de coincidir, y la identificación ""'Alice'" + Style.RESET_ALL)

print(Fore.CYAN + "[INFO]     Datos de sesión recogidos. Resolviendo desafío" + Style.RESET_ALL)

resolucion = float(TS_S) + 1

cifrado, mac, iv = funciones_aes.cifrarAES_GCM(engineKAB, str(resolucion).encode("utf-8"))
Tools.sendAESMessage(cifrado, mac, iv, socket)

""" 
Paso  (8) : 
    Descifrar el DNI para obtener la respuesta
    acceder al nombre almacenado en el diccionario
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

print(Fore.LIGHTGREEN_EX + "[STATUS]   Cerrando servicio" + Style.RESET_ALL)

exit()