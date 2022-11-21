import funciones_aes
import hashlib
import hmac
import json
import constans

from funciones_rsa import *
from colorama import Fore, Style


def getJSONMessage(contentList):
    """
    Dada una lista de String devuelve un JSON con el contenido de la lista pasada como parámetro.
    El orden de los elementos del JSON corresponde al orden de la lista introducida como parámetro.

    Args:
        contentList (List): Lista con los datos necesarios para generar el JSON. Los elementos de la listra han de estar
        en formato de texto.
    """
    msg = []

    for x in contentList:
        msg.append(x)

    return json.dumps(msg)


def makeHMAC_SHA256(clave, datos):
    """
    Generador de HMAC usando como función hash SHA256.

    Args:
        clave (String): Clave para la función MAC.
        datos (bytes): Datos a los que aplicar la función HASH.

    Returns:
        Hash MAC calculado como: MAC(H(datos, sha256), clave).
    """
    return hmac.new(clave.encode('utf-8'), datos, hashlib.sha256).digest()


def checkHMAC_CTR(calcHMAC, recivHMAC):
    """
    Procedimiento de verificación de MAC's. En caso de que las MAC's no concuerden el procedimiento aborta la ejecución
    del programa que use la función.

    Args:
        calcHMAC (bytes): HMAC precalculada a partir del mensaje recivido.
        recivHMAC (bytes): HMAC recivido en el propio mensaje recivido
    """
    if calcHMAC == recivHMAC:
        print(Fore.CYAN + "[INFO]     paquete correcto" + Style.RESET_ALL)
    else:
        print(Fore.RED + "[ERROR]   Inicio de conexión con B comprometido" + Style.RESET_ALL)
        exit()


def descifrarRSA(criptograma, claveDescifr):
    """
    Función de descifrado que resuelve errores del tipo "Ciphertext with incorrect length"

    :param criptograma (Bytes): Array de bytes con la información a descifrar (Array de Bytes).
    :param claveDescifr (Bytes): Clave asimétrica con la que descifrar el mensaje (Array de Bytes).
    :return: Mensaje en claro obtenido mediante el descifrado iterativo del criptograma.
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
    Dado que solo usaremos el modo GCM para el cifrado con AES, por cada mensaje a descifrar necesitamos C, HMAC, IV.

    :param socket(Socket TCP): socket para las operaciones I/O.
    :return: Tupla con los compos del envío en el siguiente orden (criptograma, mac, nonce).
    """
    return socket.recibir(), socket.recibir(), socket.recibir()


def sendAESMessage(criptograma, mac, nonce, socket):
    """
    Procedimiento para el envio de un mensaje cifrado mediante AES_GCM según lo descrito en el fichero README.md.

    :param criptograma (Bytes): mensaje cifrado.
    :param mac (Bytes): mac del cifrado enviado por el otro extremo.
    :param nonce(Bytes): vector de inicialización usando en el cifrado.
    :param socket(Socket TCP): socket para las operaciones I/O.
    """
    socket.enviar(criptograma)
    socket.enviar(mac)
    socket.enviar(nonce)


def makeHMAC_SHA256(clave, datos):
    """
    Generador de HMAC usando como función hash SHA256.

    Args:
        clave (String): Clave para la función MAC.
        datos (bytes): Datos a los que aplicar la función HASH.

    Returns:
        Hash MAC calculado como: MAC(H(datos, sha256), clave).
    """
    return hmac.new(clave.encode('utf-8'), datos, hashlib.sha256).digest()


def checkMessage_GCM(key, iv, cif, mac):
    """
    Procedimiento de verificación de MAC's. En caso de que las MAC's no concuerden el procedimiento aborta la ejecución
    del programa que use la función.

    Args:
        key (bytes): clave usada por los extremos para el cifrado/descifrado GCM.
        iv (bytes): vector de inicialización usando en el cifrado/descifrado.
        cif (bytes): criptograma con la información del mensaje.
        mac (bytes): HMAC enviado por el extremo emisor.
    """
    res = funciones_aes.descifrarAES_GCM(key, iv, cif, mac)
    if not res:
        print(Fore.CYAN + "[INFO]     paquete correcto" + Style.RESET_ALL)
        return res
    else:
        print(Fore.RED + "[ERROR]   Mensaje comprometido" + Style.RESET_ALL)
        exit()


def checkSesionReq(expectedId, recivedID, datos, firmaSesionA, publicKey):
    """
    Procedimiento para la validación del intercambio de claves. Comprobación de firmas e Identificadores de sesión.

    :param expectedId (String): Identificador esperado por el protocolo.
    :param datos (Bytes): Identificador recibido.
    :param firmaSesionA (Bytes): Firma recibida para validar.
    :param publicKey (Bytes): Clave pública para la validación de la firma.
    """
    if not comprobarRSA_PSS(datos, firmaSesionA, publicKey):
        print(Fore.RED + "[ERROR]   Firmas alteradas durante el envío" + Style.RESET_ALL)
        exit()

    print(Fore.CYAN + "[INFO]     Firma válidada con éxito. Emisor autenticado" + Style.RESET_ALL)

    if expectedId != recivedID:
        print(Fore.RED + "[ERROR]   Mensaje con identificador no válido" + Style.RESET_ALL)
        exit()


def castJSONMessage(json):
    """
    Función para el casteo de objeto JSON que almacena objetos de tipo bytes, de String a Bytes en codificación hexadecimal.
    Todos los elementos del JSON a de representar objetos de tipo Bytes.

    :param json (String): JSON con los objetos a castear (cifrado, mac, iv).
    :return: Lista de Bytes con los objetos contenidos en el JSON, en codificación hexadecimal.
    """
    res = []
    for x in json:
        res.append(bytes.fromhex(x))

    return res
