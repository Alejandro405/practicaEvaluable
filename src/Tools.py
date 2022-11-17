import base64

from socket_class import SOCKET_SIMPLE_TCP

import funciones_aes
import hashlib
import hmac
import json
import constans
from Crypto.Cipher import AES, PKCS1_OAEP


def getJSONMessage(contentList):
    """Dada una enera un JSON con el contenido de la lista pasada como par'ametro.
    El orden de los elemntos del JSON corresponde al orden de la lista introducida como parametro

    Args:
        contentList (List): Lista con los datos necesarios para generar el JSON. Los elementos de la listra han de estar en formato de texto
    """
    msg = []

    for x in contentList:
        msg.append(x)

    return json.dumps(msg)

def makeHMAC_SHA256(clave, datos):
    """Generador de HMAC usando como funcion hash SHA256

    Args:
        clave (String): Clave para la funcion MAC
        datos (bytes): Datos a los que aplicar la funci'on HASH

    Returns:
        Hash MAC c'alculado como: MAC(H(datos, sha256), clave)
    """
    return hmac.new(clave.encode('utf-8'), datos, hashlib.sha256).digest()

def checkHMAC_CTR(calcHMAC, recivHMAC):
    """Procedimiento de varificacion de MAC's. En caso de que las MAC's no concuerden el procedimieto aborta la ejecuci'on del programa que use la funci'on

    Args:
        calcHMAC (bytes): HMAC precalculada apartir del mensaje recivido
        recivHMAC (bytes): HMAC recivido en el propio mensaje recivido
    """
    if calcHMAC == recivHMAC:
        print("paquete correcto")
    else:
        print("[Error] Inicion de conexión con B comprometido")
        exit()

def descifrarRSA(criptograma, claveDescifr):
    """Función de descifrado que resuelve errores del tipo "Ciphertext with incorrect length"

    :param criptograma: Array de bytes con la información a descifrar (Array de Bytes)
    :param claveDescifr: Clave asimetrica con la que descifrar el mensaje (Array de Bytes)
    :return:  Mensaje en claro obtenido mediante el descifrado iterativo del criptograma
    """
    cipher = PKCS1_OAEP.new(claveDescifr)
    length = len(criptograma)
    offset = 0
    res = []
    while length - offset > 0:
        if length - offset > constans.DEFAULT_LENGTH:
            res.append(cipher.decrypt(criptograma[offset : offset + constans.DEFAULT_LENGTH]))
        else:
            res.append(cipher.decrypt(criptograma[offset:]))
        offset += constans.DEFAULT_LENGTH

    return res

def reciveAESMessage(socket):
    """
    Dado que solo usaremos el modo GCM para el cifrado con AES, por cada mensaje a descifrar necesitamos C, HMAC, IV
    :param socket: socket para las operaciones I/O.
    :return: Tupla con los compos del envío en el siguiente orden (criptograma, mac, nonce)
    """
    return socket.recibir(), socket.recibir(), socket.recibir()

def sendAESMessage(criptograma, mac, nonce, socket):
    """
    Enviar mensaje cifrado mediante AES_GCM según lo descrito en el fichero README.md.
    :param criptograma: mensaje cifrado.
    :param mac: mac del cifrado enviado por el otro extremo
    :param nonce: vector de inicializacion unsado en el cifrado.
    :param socket: socket para las operaciones I/O.
    """
    socket.enviar(criptograma)
    socket.enviar(mac)
    socket.enviar(nonce)

def makeHMAC_SHA256(clave, datos):
    """Generador de HMAC usando como funcion hash SHA256

    Args:
        clave (String): Clave para la funcion MAC
        datos (bytes): Datos a los que aplicar la funci'on HASH

    Returns:
        Hash MAC c'alculado como: MAC(H(datos, sha256), clave)
    """
    return hmac.new(clave.encode('utf-8'), datos, hashlib.sha256).digest()

def checkHMAC_GCM(key, iv, cif, mac):
    """Procedimiento de varificacion de MAC's. En caso de que las MAC's no concuerden el procedimieto aborta la ejecuci'on del programa que use la funci'on

    Args:
        key (bytes): clave usada por los extremos para el cifrado/descifrado GCM
        iv (bytes): vector de inicializacion usado en el cifrado/descifrado
        cif (bytes): criptograma con la información del mensaje
        mac (bytes): HMAC enviado por el extremo emisor
    """
    res = funciones_aes.descifrarAES_GCM(key, iv, cif, mac)
    if not res:
        print("paquete correcto")
        return res
    else:
        print("[Error] Inicion de conexión con B comprometido")
        exit()

