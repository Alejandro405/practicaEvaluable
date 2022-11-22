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
distribución de claves simétricas, Kerberos.

## Establecimiento de conexión Punto a Punto entre Alice y Bob 
Una vez distribuidas las claves públicas, y las claves de sesión entre las entidades con TTP. Pasamos al establecimiento
de conexión entre Alice y Bob siguiendo el modelo Pull para la distribución de la clave de sesión KAB, concretamente
seguimos el procedimiento descrito en el protocolo Kerberos.

Alice será quien inicie el establecimiento de la conexión, TTP generará tanto la clave de sesión KAB como el desafío a 
resolver por Bob para que Alice valide la integridad de la operación. Dicho desafío consiste en incrementar en una unidad
el Time-Stamp generado por TTP al recibir la petición de conexión de Alice. De forma resumida el establecimiento de conexión 
sigue el siguiente esquema:
    
    A -> TTP: "['Alic', 'Bob']"
    TTP -> A: E_KAT(Ts,KAB, E_KBT(TS, KAB))
    A -> B: E_KBT(TS, KAB) + E_KAB('Alice', TS)
    B -> A: E_KAB(TS+1)

## Resolución de peticiones
Después de establecer la conexión segura entre Alice y Bob, podemos comenzar con la resolución de peticiones. Alice será 
la encargada de lanzar las peticiones a Bob. Esto hace que Bob actúe como servidor y Alice como cliente, durante toda la 
comunicación entre las dos entidades.

Nuestras peticiones consistirá en la consulta de un nombre asociado a un DNI, para resolver las peticiones Bob genera un 
diccionario en el que se mapea cada nombre con su correspondiente DNI, siguiendo el siguiente esquema:

    datos = {
        "12345678x":"Eliot", 
        "09876543Y":"MR.Roboot"
                ...
    }

## Implementación del Protocolo
Alice actua como cliente en todo momento, TTP actuará como servidor en todo momento, Bob cambiará su rol dependiendo 
del estado de la comunicación (cliente para la comunicación TTP, servidor para la comunicación con Alice.

Para validar la integridad de los mensajes usando criptografía simétrica, haremos uso del modo de operación GCM. Esto
implica que cada vez que se realize el envío de un mensaje cifrado usando dicho modo de operación, se han de llevar a cabo
tres envios secuenciales con: Criptograma, HMAC del mensaje, y el vector de inicialización utilizado durante el cifrado. 
Además, se usará la misma clave para cifrar como para el cálculo de HMAC.

En el enunciado de la práctica vemos como la generación de desafíos, para la generación de frescura y validar la identidad
del otro extremo, ha de ser llevada a cabo mediante TimeStamps. Para esta tarea haremos uso de la librería "datetime", 
siguiendo el esquema propuesto en [programiz.com](https://www.programiz.com/python-programming/datetime/timestamp-datetime):
    
    from datetime import datetime

            ...

    timestamp = datetime.timestamp(datetime.now())

            ...

Una vez generado el desafío, este ha de ser resuelto y verificado atendiendo a la siguiente función:

    F(n) = n + 1
    
    donde n = timestamp

Temporizadores para la sincronización de procesos, proceso Alice retardo de 8 segundos para conseguir que Bob registre
su clave de sesión (KBT) con el TTP. Alice inicia y cierra dos conexiones TCP con TTP para: comunicar la de sesión KAT y 
solicitar clave de sesión entre Alice y Bob (KAB). Bob solo establece una conexión TCP con TTP para enviar su clave de 
sesión (KBT). En todo momentos serán los clientes los encargados de cerrar las conexiones entre sockets, los servidores 
pasarán a la escucha una vez resuelta las peticiones.

Dado que un objeto de la Clase cipher posee un estado (statefull) una vez realizada una operación de cifrado con este, no
podemos volver a realizar la misma operación. Si violamos esta norma se eleva un error del tipo "encrypt() can only be 
called after initialization or an update()". Vease el siguiente hilo [TypeError: decrypt() cannot be called after encrypt()](https://stackoverflow.com/questions/54082280/typeerror-decrypt-cannot-be-called-after-encrypt).
Para evitar esta situación volveremos a inicializar el motor de cifrado antes de cada operación.

Para las operaciones de cifrado y descifrados usaremos claves simétricas y asimétricas en formato bytes, pero necesitamos
una codificación de bytes cón para todas las operaciones, por ello usaremos una codificación en hexadecimal. Es por eso 
que necesitaremos hacer uso de los siguientes métodos: bytes.fromhex(str: String) para castear un str en codificación 
hexadecimal a bytes, y binascii.hexlify(x: Bytes) para modificar la codificación actual del objeto pasado como argumento.

Siempre que se trabaja con sockets para el intercambio de información entre procesos, necesitamos establecer en que puertos
permanecerán a la escucha los procesos de nuestro sistema. Con ello definimos los siguientes puertos para la escucha de 
las entidades:

    TTP -> 55600

    Bob -> 55700

    Alice -> 55800

Por último dado que en el protocolo a implementar no se definen mecanismos para la sincronización de procesos, debemos 
introducir un cierto retardo en el proceso Alice.py, de tal forma que permitamos generar un margen de tiempo para que 
Bob comunique la clave de sesión KBT con TTP. Dicho retardo será introducido con la siguiente sentencia:

    time.sleep(8) # 8 segundos de margen para el intercambio de claves entre Bob y el TTP

Otra forma más elegante de resolver el problema, y por la que se ha optado en la elaboración de la práctica, sería mostrar
un mensaje por pantalla y permanecer a la espera de la confirmación del usuario. Para esta tarea haremos uso de la 
siguiente sentencia, para permitir al usuario controlar la ejecución del programa:
    
    input("¿Ha enviao bob las claves? [ENTER para continuar]")
