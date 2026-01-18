## Instalación 

cd /tmp

git clone https://github.com/hackingyseguridad/root

sh root.sh

## root

Truco para elevar privlegios a root!

1º.- buscamos ficheros que se ejecutan como root en el sistema por ejemplo con:

$find / -perm -4000 2>/dev/null

2º.- por ejemplo probamos a ejecutar una shell con con el comando sudo

$/usr/bin/sudo /bin/sh -p

$whoami

<img style="float:left" alt="sudo elevacion de privilegios a root" src="https://github.com/hackingyseguridad/root/blob/master/root.jpg">

**Exploits publicos para elevar privilegios a root, OS Linux**

### CVE-2025-32463 (gravedad 9.3) en Sudo, versiones afectadas (1.9.14 a 1.9.17)
#
<img style="float:left" alt="CVE-2025-32463 sudo elevacion de privilegios a root" src="https://github.com/hackingyseguridad/root/blob/master/CVE-2025-32463.png">

 Vulnerabilidad CVE-2025-32463 gravedad 9.3 (CRÍTICO) en Sudo. - es una vulnerabilidad crítica de escalado de privilegios locales que afecta al comando sudo en sistemas Unix/Linux. Permite ejecución  de código como root, comprometiendo completamente el sistema. Esta fallp permite a un usuario local sin privilegios obtener acceso root (administrador) explotando una mala implementación de la opción --chroot (-R) en versiones vulnerables de sudo, versiones afectadas (1.9.14 a 1.9.17), sudo resuelve rutas mediante chroot() mientras aún se está evaluando el archivo sudoers. un malo puede crear un archivo /etc/nsswitch.conf falso en el directorio chroot especificado, haciendo que sudo cargue una biblioteca compartida maliciosa.  Exploit publico:   https://github.com/hackingyseguridad/root/blob/master/CVE-2025-32463


#
### http://www.hackingyseguridad.com/
#

