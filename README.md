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

CVE-2008-0600
CVE-2019-14287
CVE-2021-3156
CVE-2021-4034
CVE-2022-0847
CVE-2024-27397
CVE-2025-32463
CVE-2026-24061

### CVE-2008-0600

Vulnerabilidad en la llamada al sistema vmsplice_to_pipe del Linux Kernel que no valida correctamente un puntero de espacio de usuario, permitiendo a un usuario local elevar privilegios a root mediante argumentos manipulados en vmsplice().
Versiones afectadas: Linux Kernel 2.6.17 hasta 2.6.24.1.
Método de explotación: Llamada local a vmsplice() con argumentos especialmente construidos que llevan a la lectura/uso incorrecto de un puntero sin validar, causando escalado de privilegios.

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


CVE-2025-32463 — *sudo* chroot option permite escalar privilegios a root cargando librerías maliciosas desde un entorno chroot. :contentReference[oaicite:0]{index=0}

CVE-2025-32462 — Incorrecta aplicación de la opción --host que puede permitir bypass de restricciones de *sudoers*. :contentReference[oaicite:1]{index=1}

CVE-2023-22809 — *sudoedit* malinterpreta argumentos extra de EDITOR/SUDO_EDITOR/VISUAL facilitando escalación local de privilegios. :contentReference[oaicite:2]{index=2}

CVE-2023-28487 — *sudoreplay -l* no escapa correctamente caracteres de control, exponiendo posible abuso de sesión (no directamente elevación). :contentReference[oaicite:3]{index=3}

CVE-2023-27320 — Doble liberación (*double free*) en el soporte de chroot por comando que puede permitir corrupción y escalada. :contentReference[oaicite:4]{index=4}

CVE-2023-7090 — Manejo incorrecto de *ipa_hostname* en sudo puede provocar retención inapropiada de privilegios. :contentReference[oaicite:5]{index=5}

CVE-2021-23240 — *sudoedit* con SELinux puede escalar privilegios mediante enlace simbólico en archivos temporales. :contentReference[oaicite:6]{index=6}

CVE-2021-23239 — Race condition en *sudoedit* permite pruebas de existencia de directorios arbitrarios por symlinks. :contentReference[oaicite:7]{index=7}

CVE-2021-3156 — Desbordamiento de pila en sudo (“baron samedit”) que permite a usuarios locales obtener root sin credenciales especiales. :contentReference[oaicite:8]{index=8}

CVE-2019-19234 — *sudo* no bloquea correctamente usuarios bloqueados, lo que permite suplantación con privilegios de Runas ALL. :contentReference[oaicite:9]{index=9}

CVE-2019-19232 — Similar a CVE-2019-19234: abuso del permiso Runas ALL para impersonar otros usuarios. :contentReference[oaicite:10]{index=10}

CVE-2019-18634 — Buffer overflow basado en pila si `pwfeedback` está habilitado en sudoers, pudiendo resultar en escalada. :contentReference[oaicite:11]{index=11}

CVE-2017-1000368 — *sudo* versiones antiguas tienen vulnerabilidad de privilegios por manejo inseguro de archivos/paths. :contentReference[oaicite:12]{index=12}

CVE-2017-1000367 — Entrada de usuario mal manejada permite bypass de controles y potencial elevación de privilegios. :contentReference[oaicite:13]{index=13}

CVE-2016-7091 — Configuración predeterminada en algunas distros permite escalada de privilegios debido a mal control de reglas. :contentReference[oaicite:14]{index=14}

CVE-2016-7076 — *sudo* anterior a 1.8.18p1 tiene bypass en la política *noexec* permitiendo ejecución no autorizada. :contentReference[oaicite:15]{index=15}

CVE-2016-7032 — Módulo `sudo_noexec.so` permite a usuarios locales eludir restricciones *noexec*. :contentReference[oaicite:16]{index=16}

CVE-2015-8239 — Fallo en soporte SHA-2 en plugin *sudoers* permitiendo abuso de autenticación/privilegios. :contentReference[oaicite:17]{index=17}

CVE-2015-5602 — *sudoedit* permite escalación de privilegios locales en versiones anteriores a 1.8.15. :contentReference[oaicite:18]{index=18}

CVE-2014-9680 — *sudo* anterior a 1.8.12 no valida adecuadamente variable TZ permitiendo escalada local. :contentReference[oaicite:19]{index=19}

CVE-2014-0106 — *env_reset* deshabilitado permite fallos de seguridad potenciales con escalación local. :contentReference[oaicite:20]{index=20}

CVE-2013-2777 — *tty_tickets* mal implementado puede permitir explotación y escalación local. :contentReference[oaicite:21]{index=21}

CVE-2013-2776 — Versiones antiguas de *sudo* con reglas de *Runas* y versiones problemáticas permitían escalación. :contentReference[oaicite:22]{index=22}



#
### http://www.hackingyseguridad.com/
#

