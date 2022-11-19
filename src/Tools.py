import funciones_aes
import hashlib
import hmac
import json
import constans

from funciones_rsa import *
from colorama import Fore, Style


def getJSONMessage(contentList):
    """Dada una enera un JSON con el contenido de la lista pasada como parámetro.
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
        datos (bytes): Datos a los que aplicar la función HASH

    Returns:
        Hash MAC cálculado como: MAC(H(datos, sha256), clave)
    """
    return hmac.new(clave.encode('utf-8'), datos, hashlib.sha256).digest()


def checkHMAC_CTR(calcHMAC, recivHMAC):
    """Procedimiento de varificacion de MAC's. En caso de que las MAC's no concuerden el procedimieto aborta la ejecución del programa que use la función

    Args:
        calcHMAC (bytes): HMAC precalculada apartir del mensaje recivido
        recivHMAC (bytes): HMAC recivido en el propio mensaje recivido
    """
    if calcHMAC == recivHMAC:
        print(Fore.CYAN + "[INFO]     paquete correcto" + Style.RESET_ALL)
    else:
        print(Fore.RED + "[ERROR]   Inicion de conexión con B comprometido" + Style.RESET_ALL)
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
            res.append(cipher.decrypt(criptograma[offset: offset + constans.DEFAULT_LENGTH]))
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
    :param mac: mac del cifrado enviado por el otro extremo.
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
        datos (bytes): Datos a los que aplicar la función HASH

    Returns:
        Hash MAC cálculado como: MAC(H(datos, sha256), clave)
    """
    return hmac.new(clave.encode('utf-8'), datos, hashlib.sha256).digest()


def checkMessage_GCM(key, iv, cif, mac):
    """Procedimiento de varificacion de MAC's. En caso de que las MAC's no concuerden el procedimieto aborta la ejecución del programa que use la función

    Args:
        key (bytes): clave usada por los extremos para el cifrado/descifrado GCM
        iv (bytes): vector de inicializacion usado en el cifrado/descifrado
        cif (bytes): criptograma con la información del mensaje
        mac (bytes): HMAC enviado por el extremo emisor
    """
    res = funciones_aes.descifrarAES_GCM(key, iv, cif, mac)
    if res != False:
        print(Fore.CYAN + "[INFO]     paquete correcto" + Style.RESET_ALL)
        return res
    else:
        print(Fore.RED + "[ERROR]   Mensaje comprometido" + Style.RESET_ALL)
        exit()


def checkSesionReq(expectedId, datos, firmaSesionA, publicKey):
    """
    Función para la verificación de firmas e identificación de las peticiones iniciales del protocolo. En casp de que las
    firmas no coincidan o las identificaciones no concuerden, se mostrará un mensaje de error y se finalizará la ejecución
    del programa.
    :param expectedId (String): String identificador especificado en el protocolo
    :param datos (bytes): String identificador envido por el extremo opuesto.
    :param firmaSesionA (bytes): Firma del envío opuesto, garantía de no repudio.
    :param publicKey (bytes): Clave pública del extremo opuesto.
    :return: Clave de sesión del extremo opuesto.
    """
    if not comprobarRSA_PSS(datos, firmaSesionA, publicKey):
        print(Fore.RED + "[ERROR]   Firmas alteradas durante el envío" + Style.RESET_ALL)
        exit()

    print(Fore.CYAN + "[INFO]     Firma válidada con éxito. Emisor autenticado" + Style.RESET_ALL)

    id, KAT = json.load(datos)
    if expectedId != expectedId:
        print(Fore.RED + "[ERROR]   Mensaje con identificador no válido" + Style.RESET_ALL)
        exit()

    return KAT


def castJSONMessage(json):
    """
    Procedimiento para preprocesar objetos numéricos en formato String.
    :param json: objeto JSON con objetos numéricos (cifrado, mac, iv).
    :return: Lista de objetos de tipo Bytes en codificación hexadecimal.
    """
    res = []
    for x in json:
        res.append(bytes.fromhex(x))

    return res
