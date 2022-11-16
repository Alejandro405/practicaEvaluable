# Practica Evaluable




Puertos predefinidos para la escucha de las entidades:

    TTP -> 55600

    Bob -> 55700

    Alice -> 55800

## Fase inicial (comparticiond de recursos)
Antes del intercambio de informacion entre Alice y Bob, las tres entidades del protocolo, han de compartir sus claves 
publicas con el objetivo de usar criptograf'ia sim'etrica para el intercambio seguro de claves de sesi'on. Para ello 
se han de seguir los siguientes pasos:

    Generar claves publicas/privadas, salvando la clve p'ublica del par en un fichero <ENTITY>.pub     

    Alice y Bob genera claves de sesion con TTP
    
    Enviar las cleves de sesion (KAT, KBT) mediante criptograf'ia hibrida con la clave publica de TTP

LLegados a este punto las tres entidades ya deben tener los recursos necesarios para comenzar el intercambio de 
informaci'on. El establecimiento de la comunicaci'on entre Alice y Bob se llevar'a acabo mediante el protocolo de 
distribuci'on de claves simetricas Kerberos.


## Requisitos funcionales del protocolo

Se ha de implementar alg'un mecanismo para obtener frescura en los mensajes, para ello se ha de hacer uso de Time-Stamps
para generar desaf'io y respuesta. Donde la respuesta al desaf'io es: F(time-stam) = time-stamp + 1

Alice actua como cliente en todo momento, TTP actuar'a como servidor en todo momento, Bob cambiar'a su rol dependiendo 
del estado de la comunicaci'on (cliente para la comuinicacion TTP, servidor para la comunicaci'on con Alice

Para validar la integridad de los mensajes usando criptografía simétrica, haremos uso del modo de operación GCM. Esto
implica que cada vez que se realize el enío de un mensaje cifrado usando dicho modo de operación, se han de llevar acabo
tres envios secuenciales con: Criptograma, HMAC del mensaje, y el vector de inicialización usado durante el cifrado
