## root

** Exploits publicos para escalado de privilegios a root, OS Linux

### CVE-2025-32463 (gravedad 9.3) en Sudo, versiones afectadas (1.9.14 a 1.9.17)
#
<img style="float:left" alt="CVE-2025-32463 sudo elevacion de privilegios a root" src="https://github.com/hackingyseguridad/root/blob/master/CVE-2025-32463.png">

https://github.com/hackingyseguridad/root/tree/master/CVE-2025-32463  Vulnerabilidad CVE-2025-32463 gravedad 9.3 (CRÍTICO) en Sudo. - es una vulnerabilidad crítica de escalada de privilegios locales que afecta al comando sudo en sistemas Unix/Linux. Permite ejecución  de código como root, comprometiendo completamente el sistema. Esta fallp permite a un usuario local sin privilegios obtener acceso root (administrador) explotando una mala implementación de la opción --chroot (-R) en versiones vulnerables de sudo, versiones afectadas (1.9.14 a 1.9.17), sudo resuelve rutas mediante chroot() mientras aún se está evaluando el archivo sudoers. un malo puede crear un archivo /etc/nsswitch.conf falso en el directorio chroot especificado, haciendo que sudo cargue una biblioteca compartida maliciosa.  Exploit:   https://github.com/hackingyseguridad/root/blob/master/CVE-2025-32463

### http://www.hackingyseguridad.com/


