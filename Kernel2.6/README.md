### CVE-2009-2692

**CVE-2009-2692**  Afecta a: Linux kernel 2.6.0 hasta ~2.6.30 

inicialización incorrecta de punteros en estructuras proto_ops provoca NULL pointer dereference que puede explotarse para ejecutar código en contexto de kernel y obtener root.

uso de mmap(0) para mapear la página cero y manipular punteros de función para ejecutar código propio como root.

Escalado de privilegios a root, solo para Linux con Kernel 2.6.18-20

Compilar a binario
gcc root.c -o rootesc

./rootesc

