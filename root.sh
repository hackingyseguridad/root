#!/bin/sh

# Busca ficheros en el sistema que se ejecuten como Super User
# Vamos a usar esos ficheros para ejecutar una Shell como Root
# (r) hackingyseguridad.com 2026
# antonio_taboada
# Uso.: $sh root.sh 

echo " busca fichero que se ejecutan como root en el sistema:"
find / -perm -4000 2>/dev/null

# por ejemplo ejecutamos una shell con con sudo

/usr/bin/sudo /bin/sh -p

whoami
