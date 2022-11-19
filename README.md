# Requisitos del Protocolo

## Fase Inicial (compartición de recursos)
Antes del intercambio de información entre Alice y Bob, las tres entidades del protocolo, han de compartir sus claves 
publicas con el objetivo de usar criptografía simétrica para el intercambio seguro de claves de sesión. Para ello 
se han de seguir los siguientes pasos:

    Generar claves publicas/privadas, salvando la clve pública del par en un fichero <ENTITY>.pub     

    Alice y Bob genera claves de sesion con TTP
    
    Enviar las cleves de sesion (KAT, KBT) mediante criptografía hibrida con la clave publica de TTP

LLegados a este punto las tres entidades ya deben tener los recursos necesarios para comenzar el intercambio de 
información. El establecimiento de la comunicación entre Alice y Bob se llevará a cabo mediante el protocolo de 
distribución de claves simétricas Kerberos.


## Implementación del Protocolo

Se ha de implementar algún mecanismo para obtener frescura en los mensajes, para ello se ha de hacer uso de Time-Stamps
para generar desafío y respuesta. Donde la respuesta al desafío es: F(time-stamp) = time-stamp + 1.

Alice actua como cliente en todo momento, TTP actuará como servidor en todo momento, Bob cambiará su rol dependiendo 
del estado de la comunicación (cliente para la comunicación TTP, servidor para la comunicación con Alice.

Para validar la integridad de los mensajes usando criptografía simétrica, haremos uso del modo de operación GCM. Esto
implica que cada vez que se realize el envío de un mensaje cifrado usando dicho modo de operación, se han de llevar a cabo
tres envios secuenciales con: Criptograma, HMAC del mensaje, y el vector de inicialización utilizado durante el cifrado. 
Además, se usará la misma clave para cifrar como para el cálculo de HMAC.

En el enunciado de la práctica vemos como la generación de desafíos, para la generación de frescura y validar la identidad
del otro extremo, ha de ser llevada a cabo mediante TimeStamps. Para esta tarea haremos uso de la librería "datetime", 
siguiendo el esquema propuesto en [programiz.com](https://www.programiz.com/python-programming/datetime/timestamp-datetime:):
    
    from datetime import datetime

            ...

    timestamp = datetime.timestamp(datetime.now())

            ...

Temporizadores para la sincronización de procesos, proceso Alice retardo de 8 segundos para conseguir que Bob registre
su clave de sesión (KBT) con el TTP. Alice inicia y cierra dos conexiones TCP con TTP para: comunicar la de sesión KAT y 
solicitar clave de sesión entre Alice y Bob (KAB). Bob solo establece una conexión TCP con TTP para enviar su clave de 
sesión (KBT). En todo momentos serán los clientes los encargados de cerrar las conexiones entre sockets, los servidores 
pasarán a la escucha una vez resuelta las peticiones.

Actualización de motores de cifrado para las operaciones de cifrado.

Para las operaciones de cifrado y descifrados usaremos claves simétricas y asimétricas en bytes en codificación exadecimal.
Uso de bytes.fromhex(...) para castear un str a bytes en codificación hexadecimal, y binascii.hexlify(...).

Puertos predefinidos para la escucha de las entidades:

    TTP -> 55600

    Bob -> 55700

    Alice -> 55800