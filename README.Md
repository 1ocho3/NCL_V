# Andrés de la Hoz Camiroaga  
### RETO-2 National Cyberleague - Guardia Civil
##### @nocnoc37
###### Equipo NotAnonymous - UFV.Madrid
---  

### 1.&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ENUNCIADO:  

Peter es un apasionado de la tecnología y trabaja como desarrollador de software en una empresa de renombre. Ha pasado innumerables horas creando programas innovadores y asegurándose de que los sitemas estén protegidos.   

Sin embargo, Peter ha tenido un revés recientemente. Durante las últimas semanas, ha estado trabajando en un proyecto muy exigente y, debido al estrés y las largas horas de trabjo, ha olvidado por completo su contraseña. ¿Puedes ayudarle a recuperar la contraseña de su usuario?

FORMATO: contraseña 

---
---
### Preparación del entorno:  
Con este writeup, podrás descargar el reto y realizarlo paso a paso. El volcado de memoria pesa 2.5gb comprimido.  Si solo quieres ver como se resuelve, y no quieres descargar el fichero baja directamente a `"ANÁLISIS INICIAL"`. 

#### Descargar el volcado:  
Clona el repositorio en tu máquina  
```bash
git clone https://github.com/1ocho3/NATIONAL_CYBERLEAGUE
```

Entra en el directorio del volcado de memoria:

```bash
cd volcado
```  
Descomprime el primer fichero de los zips segmentados:

```bash
7z e NCL-V-SEMIFINAL-TECNICO-02.zip.001
```
El resultado es un fichero llamado `memory.dmp`   
  

---  
---
&nbsp;  

#### ANÁLISIS INICIAL:

Para este reto usaremos volatility. En este caso usaré volatility2, se puede conseguir el mismo resultado con volatility3, solo se debe omitir los pasos de identificación de perfil, y buscar los comandos homólogos en esta versión.  

&nbsp;  


Lo primero que haré será un `kdbgscan` que devuelve los posibles valores KDBG. La razón por la que uso este plugin y no `imageinfo` es simple y llanamente porque la búsqueda es más exahustiva y tiene una mayor probabilidad de acierto identificando el perfil del volcado frente a imageinfo.
```bash
vol.py -f memory.dmp kdbgscan
```
![kdbgscan](https://github.com/1ocho3/NCL_V/blob/main/imagenes/kdbgscan_output.png?raw=true)  

Desde ahora en adelante, especificaremos este perfil cada vez que ejecutemos un plugin.

Lo siguiente que pensé fue en descargar inmediatamente los hashes NTLM del volcado pero pronto descubriría que ese no era el camino.
Observar los procesos es uno de los puntos de referencia cuando no sepamos por donde seguir. Y en este caso hay un proceso que destaca sobre el resto.

```bash
vol.py -f memory.dmp --profile=Win10x64_18362 pslist
```
Este es el output que recibimos (simplificado), donde podemos observar el proceso `KeePass`

Volatility Foundation Volatility Framework 2.6.1  

|Offset(V)|Name|PID|PPID|Thds|Hnds|Sess|Wow64|Start|
|---|---|---|---|---|---|---|---|---|
|0xffffae094467f358|System|4|0|139|0|0|2023-05-18 11:41:34 UTC+0000|
|0xffffae094a7be1d8|svchost.exe|8964|696|9|0|0|2023-05-18 11:43:34 UTC+0000|
|0xffffae094c27f498|SgrmBroker.exe|8856|696|8|0|0|2023-05-18 11:43:40 UTC+0000|
|0xffffae094ccaf498|svchost.exe|7992|696|13|0|0|2023-05-18 11:43:40 UTC+0000|
|0xffffae094ad0e1d8|KeePass.exe|4288|3420|8|0|1|2023-05-18 11:43:43 UTC+0000|
|0xffffae094a6c83d8|svchost.exe|6988|696|10|0|0|2023-05-18 11:43:43 UTC+0000|
|0xffffae094a2871d8|wuauclt.exe|1372|1436|5|0|0|2023-05-18 11:44:15 UTC+0000|

Podemos tratar de dumpearlo, encontrar su versión y buscar algún tipo de vulnerabilidad.  
No podemos hacer un procdump del archivo KeePass.exe debido a la paginación pero podremos realizar un memdump que nos aportará más información, no solo el ejecutable como resuelve procdump.  
 
```bash
vol.py -f memory.dmp --profile=Win10x64_18362 memdump --pid 4288 -D [DIRECTORIO DE SALIDA EXISTENTE] 
```
![KeePass.dmp](https://github.com/1ocho3/NCL_V/blob/main/imagenes/KeePass_dump.png?raw=true)  


Una vez tenemos la memoria del proceso volcada, antes que tratar de hacer nada más, vamos a investigar la información del programa.  
Con `strings` y `grep` hacemos una búsqueda con el fin de tratar de averiguar la versión del programa.


```bash
strings 4288.dmp | grep KeePass
```
Que devuelve lo siguiente:  

![KeePass_2.53.1](https://github.com/1ocho3/NCL_V/blob/main/imagenes/KeePass_2.53.1_v2.png?raw=true)

Nos encontramos con la versión 2.53.1, en el momento de la competición la última versión es la 2.55.
Sabemos que estamos trabajando con una versión anterior, podemos buscar alguna vulnerabilidad.  
Entre las más prometedoras encontramos el CVE-2023-32784:  

![PoC-CVE-2023-32784](https://github.com/1ocho3/NCL_V/blob/main/imagenes/POC%20CVE-2023-32784.png?raw=true)

Para ejecutar el PoC debemos proporcionar el volcado del porceso: (mirar el repositorio del CVE para instalar las dependencias)  


```bash
dotnet run 4288.dmp
```
Pero en una primera instancia descubrimos que no consigue sacar la contraseña:

![4288_PoC_Output](https://github.com/1ocho3/NCL_V/blob/main/imagenes/4288_PoC_Output.png?raw=true)

Después de una investigación mas profunda sobre el PoC descubrimos que podemos ejecutarlo, sobre un volcado del proceso o sobre el volcado de memoria completo de una máquina.   
Con esto en mente, ahora tratamos de hacer lo mismo pero con nuestro volcado de memoria.  


```bash
dotnet run memory.dmp
```  
![memory.dmp_PoC_Ouput](https://github.com/1ocho3/NCL_V/blob/main/imagenes/memory.dmp_PoC_Ouput.png?raw=true)  

Tenemos la contraseña a falta de cerciorar cuales son los caracteres inciales, una de las características de esta vulnerabilidad es que el primer caracter no se puede extraer y los siguientes pueden ser inexactos. Pero analicemos el output:  

Si separamos lo que nos devuelve nos encontramos con lo siguiente:  

●  --> Primer caracter (desconocido) 

{Ú, B, \, à, 9, ¿, Ë, ½, , o, ß, =, k, À, Ó, Ì, Î, å, O, y, E, Ü, $, ,, 4, «, Á, g, ¬, ;, , , ê, M, æ, p, , ô, , , r, ¤, ¡, @, ¢, I, ®, ÿ, d, e, Ð, Â, w, ü, , !, t, º, <, ÷, Ñ, 7, S, Ô, ð, 3, ,  , T, G, ×, Æ, F, Q, Ä, %, `, L, ú, 1, ­, Ø, ., ), 8, ¨, 0, µ, , ø, z, °, {, É, ,  , H, 2, ', (, ·, s, h, , R, ç, , |, W, a, D, 5, , , , A, î, , C, "} --> Posibles 2º carácter 

{ , °, µ, 1}  --> Posibles 3er carácter 

5_1S_4_sTr0ng  --> Caracteres extraídos   

{P, _}  --> Posibles 17º carácter   

s3cUrit1  --> Caracteres extraídos  

{w, _}  --> Posibles 26º carácter 

PwD  --> Caracteres finales extraídos  

---  
&nbsp;  

De este conjunto de posibilidades podemos intuir, en base a `5_1S_4_sTr0ng` que los caracteres 17 y 26 son un guión bajo `_` &nbsp;:  
`5_1S_4_sTr0ng_s3cUrit1_PwD`   

Vemos que la contraseña en texto plano se asemeja a: __S_IS_A_STRONG_SECURITY_PWD__

Con esto conseguimos vislumbrar como será la contraseña al completo: __THIS_IS_A_STRONG_SECURITY_PWD__ 

Viendo que las i's y las S's se han cambiado por 1 y 5 la contraseña quedaría de la siguiente forma tomando las siguiente posibilidades:  
`TH15_1S_4_sTr0ng_s3cUrit1_PwD`  
`tH15_1S_4_sTr0ng_s3cUrit1_PwD`  
`Th15_1S_4_sTr0ng_s3cUrit1_PwD`  
`th15_1S_4_sTr0ng_s3cUrit1_PwD` 

Enhorabuena!!!! Ya tenemos la contraseña de KeePass, tan solo son 4 posibilidades, estamos muy cerca. Pero ahora. ¿Cómo conseguimos la contraseña de Peter?  
Necesitamos acceder a la base de datos de KeePass.  
La base de datos por defecto se llama KeePass.kdbx. Con esto procedemos a dumpear el archivo con volatility.  

```bash
vol.py -f memory.dmp --profile=Win10x64_18362 filescan | grep Database.kdbx
```   
![Database.kdbx_filescan_output](https://github.com/1ocho3/NCL_V/blob/main/imagenes/Database.kdbx_filescan_output1.png?raw=true)
     
En este momento solo queda extraer el archivo del volcado.  
Nos valdremos de la dirección virtual: `0x0000ae094c7aeb00`  
Volatility2 no me surtía resultado, por lo que acudí a volatility3 para este paso:

```bash
vol3 -f memory.dmp windows.dumpfiles --virtaddr 0x0000ae094c7aeb00
```  
![Dumpfiles_volatility3_Output](https://github.com/1ocho3/NCL_V/blob/main/imagenes/Dumpfiles_volatility3_Output.png?raw=true)  

Ya tenemos todo lo que necesitamos, las 4 posibles `Master Password` del KeePass de Peter y la base de datos.
Ahora en nuestra máquina descargaremos KeePass2 o KeePassxc y abriremos la base de datos extraída:
Probamos las contraseñas y descubrimos que __¡BINGO!__ la contraseña es la opción `tH15_1S_4_sTr0ng_s3cUrit1_PwD`  

![KeePass_Master_PwD](https://github.com/1ocho3/NCL_V/blob/main/imagenes/KeePass_Master_PwD1.png?raw=true)  

Una vez dentro de la base de datos vemos tres credenciales guardados:  

El `OnlyFans` de Peter.  
El Usuario y contraseña de la plataforma de ajedrez de peter.    
Y las credenciales de su ordenador:    

![Peter_Credentiasl_Even_OnlyFans_...._Incredible](https://github.com/1ocho3/NCL_V/blob/main/imagenes/Peter_Credentiasl_Even_OnlyFans_...._Incredible.png?raw=true)  
  
Obviando todo lo que es OFbviamente prescindible y centrándonos en nuestros valores, sobre todo en el de __CONFIDENCIALIDAD__, entraremos directos en los credenciales que parecen apuntar al ordenador de peter   
`peter computer`   

![Contraseña_sacada_del_ordenador_de_Peter_A_través_de_la_BD_de_KeePass](https://github.com/1ocho3/NCL_V/blob/main/imagenes/Pete_Come_Pato_hmmmmm.png?raw=true)  

......   ·.·    Sin comentarios....

__CONSEGUIDO!!__ Recuerda, al igual que un llavero sirve para perder todas las llaves a la vez, KeepPass sirve para filtrar todas tus contraseñas a la vez.  
No te olvides, nada es seguro ante el hacking, y todo es vulnerable. Los sistemas son seguros hasta que dejan de serlos.  

Si tienes algún tipo de información comprometedora, ten por seguro que el sitio más protegido para guardar tu contraseña es tu memoria. 
No lo dudes!!


```txt


 ________   ________  ________  ________   ________  ________          ________   ________  
|\   ___  \|\   __  \|\   ____\|\   ___  \|\   __  \|\   ____\        |\_____  \ |\_____  \ 
\ \  \\ \  \ \  \|\  \ \  \___|\ \  \\ \  \ \  \|\  \ \  \___|        \|____|\ /_ \|___/  /|
 \ \  \\ \  \ \  \\\  \ \  \    \ \  \\ \  \ \  \\\  \ \  \                 \|\  \    /  / /
  \ \  \\ \  \ \  \\\  \ \  \____\ \  \\ \  \ \  \\\  \ \  \____           __\_\  \  /  / / 
   \ \__\\ \__\ \_______\ \_______\ \__\\ \__\ \_______\ \_______\        |\_______\/__/ /  
    \|__| \|__|\|_______|\|_______|\|__| \|__|\|_______|\|_______|        \|_______||__|/   
                                                                                                                                                     

                                                                                      
```
