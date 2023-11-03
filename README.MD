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

#### ANÁLISIS INICIAL:

Para este reto usaremos volatility. En este caso usaré volatility2, se puede conseguir el mismo resultado con volatility3, solo se debe que omitir los pasos de identificación de perfil, y buscar los comandos homólogos en esta versión.  

&nbsp;  


Lo primero que haré será un `kdbgscan` que devuelve los posibles valores KDBG. La razón por la que uso este plugin y no imageinfo es simple y llanamente porque la búsqueda es más exahustiva y tiene una mayor probabilidad de acierto identificando el perfil del volcado frente a imageinfo.
```bash
vol.py -f memory.dmp kdbgscan
```
![kdbgscan](https://github.com/1ocho3/NCL_V/blob/main/imagenes/kdbgscan_output.png?raw=true)  

Desde ahora en adelante, especificaremos este perfil cada vez que ejecutemos un plugin.

Lo primero que pensé fue en descargar inmediatamente los hashes NTLM del volcado pero pronto descubriría que ese no es el camino.
Observar los procesos es uno de los puntos de referencia cuando no sepamos por donde seguir. Y en este caso hay un proceso que destaca sobre el resto.

```bash
vol.py -f memory.dmp --profile=Win10x64_18362 pslist
```
Este es el otput que recibimos (simplificado), donde podemos observar el proceso `KeePass`

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
vol.py -f memory.dmp --profile=Win10x64_18362 memdump --pid 4288 -D PS 
```
![KeePass.dmp](https://github.com/1ocho3/NCL_V/blob/main/imagenes/KeePass_dump.png?raw=true)

```bash

```

```bash

```

```bash

```
```bash

```
```bash

```
```bash

```
```bash

```
```bash

```
```bash

```
```bash

```
```bash

```
