## Instalación 

cd /tmp

git clone https://github.com/hackingyseguridad/root

sh root.sh

## root

Truco para elevar privlegios a root!


1º.- buscamos ficheros con SUID activo como Super User SUID (Set User ID):4000, que se ejecutan como root en el sistema por ejemplo con:
 

$find / -perm -4000 2>/dev/null

2º.- por ejemplo probamos a ejecutar una shell con con el comando sudo

$/usr/bin/sudo /bin/sh -p

$whoami

3º.- Persistencia como SuperUser;

$# sudo chmod +s /bin/sh

$# sudo chmod +s /bin/bash # esto activa el bit SUID (4000) sobre /bin/bash, cualquier usuario que ejecute /bin/bash tendra privilegios de root.


<img style="float:left" alt="sudo elevacion de privilegios a root" src="https://github.com/hackingyseguridad/root/blob/master/root.jpg">

**Exploits publicos para elevar privilegios a root, OS Linux**

**Vulnerabilidades**

CVE-2019-14287
CVE-2021-3156
CVE-2021-4034
CVE-2022-0847
CVE-2024-27397
CVE-2025-32463
CVE-2026-24061

### CVE-2019-14287

**afectado:** Sudo versiones *anteriores a 1.8.28* en Linux/Unix.
**Resumen:** Debido a un fallo en la verificación de IDs de usuario, un ataque local puede abusar de `sudo` (por ejemplo `sudo -u #4294967295`) para ejecutar comandos con **privilegios de root**, eludiendo restricciones de políticas de sudo. ([INCIBE][1])
**Método de explotación:** Manipulación de argumentos de `sudo` que permiten saltarse la verificación de usuario y ejecutar código como root. ([vuldb.com][2])

### CVE-2021-3156

**afectado:** Sudo *anteriores a 1.9.5p2*.
**Resumen:** Error de desbordamiento en el manejo de argumentos (heap overflow) cuando se usa `sudoedit -s` con un argumento específico que termina en `\`. Esto permite que un usuario sin privilegios escale a root. ([INCIBE][3])
**Método de explotación:** Crafting de línea de comandos con `sudoedit -s` y backslash para desencadenar el overflow y ganar ejecución arbitraria con privilegios elevados. 

### CVE-2021-4034** (pwnkit)

**afectado:** Polkit `pkexec`, presente en la mayoría de distribuciones Linux.
**Resumen:** `pkexec` no valida correctamente el número de parámetros, lo que permite a un atacante local configurar variables de entorno de manera maliciosa para ejecutar comandos arbitrarios con privilegios de root. ([nvd.nist.gov][4])
**Método de explotación:** Manipulación de variables de entorno antes de invocar `pkexec` para forzar la ejecución de código malicioso con privilegios elevados. 

### CVE-2022-0847 — Dirty Pipe

**afectado:** Linux Kernel *≥ 5.8* antes de parches.
**Resumen:** Debido a una inicialización inadecuada de varias estructuras en las funciones de tubería, un usuario local sin privilegios puede sobrescribir datos en archivos de solo lectura, incluyendo binarios SUID, conduciendo a escalado de privilegios. 
**Método de explotación:** Manipulación de pipes para sobrescribir páginas de memoria protegidas; luego inyección en binarios de sistema para escalar a root. 

### CVE-2024-27397

**afectado:** Linux Kernel (netfilter nf_tables subsystem en versiones previas a parches).
**Resumen:** Uso de un elemento expirado en operaciones de control de conjunto (`nftables`) puede provocar un *use-after-free*, permitiendo a un atacante local con bajo privilegio corromper memoria del kernel y potencialmente lograr escalado de privilegios o ejecución de código con permisos elevados. ([SentinelOne][8])
**Método de explotación:** Trigger de condición de carrera en manipulación de reglas nf_tables con timeouts, logrando uso de memoria liberada para corrupción y escalado.

### CVE-2025-32463 (gravedad 9.3) en Sudo, versiones afectadas (1.9.14 a 1.9.17)
#
<img style="float:left" alt="CVE-2025-32463 sudo elevacion de privilegios a root" src="https://github.com/hackingyseguridad/root/blob/master/CVE-2025-32463.png">

Vulnerabilidad CVE-2025-32463 gravedad 9.3 (CRÍTICO) en Sudo. - es una vulnerabilidad crítica de escalado de privilegios locales que afecta al comando sudo en sistemas Unix/Linux. Permite ejecución  de código como root, comprometiendo completamente el sistema. Esta fallp permite a un usuario local sin privilegios obtener acceso root (administrador) explotando una mala implementación de la opción --chroot (-R) en versiones vulnerables de sudo, versiones afectadas (1.9.14 a 1.9.17), sudo resuelve rutas mediante chroot() mientras aún se está evaluando el archivo sudoers. un malo puede crear un archivo /etc/nsswitch.conf falso en el directorio chroot especificado, haciendo que sudo cargue una biblioteca compartida maliciosa.  Exploit publico:  https://github.com/hackingyseguridad/root/blob/master/CVE-2025-32463

### CVE-2026-24061
#
**afectado:** GNU InetUtils *telnetd* versiones *1.9.3 – 2.7*.
**Resumen:** Error de validación en la variable de entorno `USER`: telnetd pasa ese valor directamente a `/usr/bin/login`, lo que permite a un atacante remoto enviar `USER=-f root` y forzar un bypass de autenticación, obteniendo acceso directo como root.
**Método de explotación:** Conexión remota por Telnet con un valor de entorno manipulada (`USER=-f root`) para forzar `login` a omitir autenticaciones y otorgar acceso como root.

---


#
### http://www.hackingyseguridad.com/
#

