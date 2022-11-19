import json

import funciones_aes
import Tools

k = funciones_aes.crear_AESKey()
engineK = funciones_aes.iniciarAES_GCM(k)


cif, mac, nonce = funciones_aes.cifrarAES_GCM(engineK, "Accidentally in love".encode("utf-8"))

msg = json.loads(json.dumps([cif.hex(), mac.hex(), nonce.hex()]))

cifradoM, macM, nonceM = Tools.castJSONMessage(msg)

print(cif == cifradoM and mac == macM and nonceM == nonce)

