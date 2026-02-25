#!/bin/bash
# Script de auditoría avanzada para Linux
# Uso: ./audit.sh [opciones]
# Opciones: -v (verbose), -o archivo (guardar salida)

# Configuración
VERBOSE=0
OUTPUT_FILE=""
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="audit_report_${TIMESTAMP}.txt"

# Procesar argumentos
while getopts "vo:h" opt; do
    case $opt in
        v) VERBOSE=1 ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        h) echo "Uso: $0 [-v] [-o archivo_salida]"; exit 0 ;;
    esac
done

# Función para imprimir y opcionalmente guardar
print_output() {
    echo "$1"
    if [ -n "$OUTPUT_FILE" ]; then
        echo "$1" >> "$OUTPUT_FILE"
    fi
}

# Función para verificar si un comando existe
command_exists() {
    command -v "$1" &> /dev/null
}

# Función para ejecutar comando y manejar errores
run_cmd() {
    local cmd="$1"
    local fallback_msg="${2:-No disponible}"
    
    if eval "$cmd" &> /dev/null; then
        eval "$cmd" 2>/dev/null
    else
        echo "$fallback_msg"
    fi
}

# Inicio del informe
print_output "================================================================================"
print_output "INFORME DE AUDITORÍA COMPLETA - $(date)"
print_output "Sistema: $(hostname) - $(uname -srm)"
print_output "Usuario: $(whoami) (UID: $(id -u), GID: $(id -g))"
print_output "================================================================================"
print_output ""

# 1. INFORMACIÓN DETALLADA DEL SISTEMA
print_output "[01] INFORMACIÓN DEL SISTEMA"
print_output "---------------------------"
print_output "Hostname: $(hostname)"
print_output "Dominio: $(hostname -d 2>/dev/null || echo 'No configurado')"
print_output "FQDN: $(hostname -f 2>/dev/null || echo 'No configurado')"
print_output "Kernel: $(uname -r)"
print_output "Arquitectura: $(uname -m)"
print_output "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo 'Desconocido')"
print_output "Versión OS: $(cat /etc/os-release 2>/dev/null | grep VERSION_ID | cut -d'"' -f2 || echo 'Desconocido')"
print_output "Uptime: $(uptime | sed 's/.*up \([^,]*\), .*/\1/')"
print_output "Load average: $(uptime | awk -F'load average:' '{print $2}')"
print_output ""

# 2. HARDWARE Y RECURSOS
print_output "[02] HARDWARE Y RECURSOS"
print_output "-----------------------"
print_output "CPU: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d':' -f2 | sed 's/^ //')"
print_output "Núcleos CPU: $(nproc 2>/dev/null || grep -c processor /proc/cpuinfo)"
print_output "Arquitectura CPU: $(lscpu 2>/dev/null | grep Architecture | awk '{print $2}' || echo 'Desconocida')"
print_output ""

print_output "MEMORIA RAM:"
print_output "$(free -h | awk 'NR==1{printf \"%-10s %-10s %-10s %-10s\n\", $1, $2, $3, $4} NR==2{printf \"%-10s %-10s %-10s %-10s\n\", $1, $2, $3, $4}')"
print_output ""

print_output "MEMORIA SWAP:"
print_output "$(free -h | awk 'NR==1{printf \"%-10s %-10s %-10s %-10s\n\", $1, $2, $3, $4} NR==3{printf \"%-10s %-10s %-10s %-10s\n\", $1, $2, $3, $4}')"
print_output ""

print_output "DISPOSITIVOS DE BLOQUE:"
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,MODEL 2>/dev/null | grep -v loop | head -20 | while read line; do
    print_output "  $line"
done
print_output ""

print_output "ESPACIO EN DISCO:"
df -hT | grep -v tmpfs | while read line; do
    print_output "  $line"
done
print_output ""

# 3. RED Y CONECTIVIDAD
print_output "[03] RED Y CONECTIVIDAD"
print_output "----------------------"

print_output "INTERFACES DE RED:"
ip -br addr show 2>/dev/null | while read line; do
    print_output "  $line"
done
print_output ""

print_output "TABLA DE RUTAS:"
ip route show 2>/dev/null | while read line; do
    print_output "  $line"
done
print_output ""

print_output "RESOLUCIÓN DNS (/etc/resolv.conf):"
if [ -f /etc/resolv.conf ]; then
    grep -v "^#" /etc/resolv.conf | grep -v "^$" | while read line; do
        print_output "  $line"
    done
else
    print_output "  No disponible"
fi
print_output ""

print_output "PUERTOS ABIERTOS (LISTEN):"
if command_exists ss; then
    ss -tulpn 2>/dev/null | tail -n +2 | while read line; do
        PROTO=$(echo $line | awk '{print $1}')
        STATE=$(echo $line | awk '{print $2}')
        IP_PORT=$(echo $line | awk '{print $5}')
        PID=$(echo $line | awk '{print $7}' | cut -d',' -f2 | cut -d'=' -f2)
        print_output "  $PROTO $STATE $IP_PORT PID: $PID"
    done
elif command_exists netstat; then
    netstat -tulpn 2>/dev/null | tail -n +2 | while read line; do
        print_output "  $line"
    done
fi
print_output ""

print_output "CONEXIONES ESTABLECIDAS:"
ss -tun 2>/dev/null | grep ESTAB | while read line; do
    print_output "  $line"
done
print_output ""

# 4. SERVICIOS EN EJECUCIÓN
print_output "[04] SERVICIOS EN EJECUCIÓN"
print_output "-------------------------"

if command_exists systemctl; then
    print_output "Servicios activos (systemd):"
    systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -20 | while read line; do
        print_output "  $line"
    done
    print_output "  ... (mostrando primeros 20)"
elif command_exists service; then
    print_output "Servicios (init.d):"
    service --status-all 2>/dev/null | grep "+" | head -20 | while read line; do
        print_output "  $line"
    done
fi
print_output ""

print_output "PROCESOS POR USUARIO:"
ps aux --sort=-%cpu 2>/dev/null | head -15 | while read line; do
    print_output "  $line"
done
print_output ""

print_output "PROCESOS ESCUCHANDO RED:"
lsof -i -P -n 2>/dev/null | grep LISTEN | head -20 | while read line; do
    print_output "  $line"
done
print_output ""

# 5. VERSIONES DE SOFTWARE
print_output "[05] VERSIONES DE SOFTWARE"
print_output "-------------------------"

check_version() {
    local name="$1"
    local cmd="$2"
    local version=$(eval "$cmd" 2>/dev/null | head -1)
    if [ -n "$version" ]; then
        print_output "  $name: $version"
    fi
}

# Servidores web
check_version "Apache" "apache2 -v 2>/dev/null | head -1 || httpd -v 2>/dev/null | head -1"
check_version "Nginx" "nginx -v 2>&1"
check_version "Tomcat" "catalina version 2>/dev/null | head -1"

# Bases de datos
check_version "MySQL" "mysql --version"
check_version "MariaDB" "mariadb --version 2>/dev/null"
check_version "PostgreSQL" "postgres --version"
check_version "MongoDB" "mongod --version 2>/dev/null | head -1"
check_version "Redis" "redis-server --version 2>/dev/null | head -1"

# Lenguajes y runtimes
check_version "Python2" "python2 --version 2>&1"
check_version "Python3" "python3 --version 2>&1"
check_version "Java" "java -version 2>&1 | head -1"
check_version "Node.js" "node --version"
check_version "PHP" "php --version 2>/dev/null | head -1"
check_version "Ruby" "ruby --version"
check_version "Perl" "perl --version | head -2 | tail -1"
check_version "Go" "go version"
check_version "Rust" "rustc --version"

# Servicios de red
check_version "OpenSSH" "ssh -V 2>&1"
check_version "OpenSSL" "openssl version"
check_version "Docker" "docker --version"
check_version "Kubernetes" "kubectl version --client 2>/dev/null | head -1"
check_version "Git" "git --version"
check_version "Curl" "curl --version | head -1"
check_version "Wget" "wget --version | head -1"
print_output ""

# 6. SEGURIDAD Y CIFRADOS
print_output "[06] SEGURIDAD Y CIFRADOS"
print_output "------------------------"

# Cifrados SSH
if [ -f /etc/ssh/sshd_config ]; then
    print_output "Configuración SSH:"
    grep -E "^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Protocol)" /etc/ssh/sshd_config 2>/dev/null | while read line; do
        print_output "  $line"
    done
    
    print_output "Cifrados SSH soportados:"
    ssh -Q cipher 2>/dev/null | head -10 | sed 's/^/  /'
    print_output "  ... (mostrando primeros 10)"
    
    print_output "MACs SSH soportadas:"
    ssh -Q mac 2>/dev/null | head -10 | sed 's/^/  /'
    print_output "  ... (mostrando primeros 10)"
fi
print_output ""

# TLS/SSL
if command_exists openssl; then
    print_output "Versión OpenSSL: $(openssl version)"
    print_output "Cifrados OpenSSL disponibles:"
    openssl ciphers -v 2>/dev/null | head -20 | while read line; do
        print_output "  $line"
    done
    print_output "  ... (mostrando primeros 20)"
fi
print_output ""

# Políticas de contraseñas
print_output "Políticas de contraseñas:"
if [ -f /etc/login.defs ]; then
    grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE" /etc/login.defs 2>/dev/null | while read line; do
        print_output "  $line"
    done
fi

if [ -f /etc/pam.d/common-password ]; then
    print_output "Configuración PAM:"
    grep -v "^#" /etc/pam.d/common-password 2>/dev/null | grep password | head -5 | while read line; do
        print_output "  $line"
    done
fi
print_output ""

# 7. USUARIOS Y PERMISOS
print_output "[07] USUARIOS Y PERMISOS"
print_output "-----------------------"

print_output "Usuarios del sistema:"
cut -d: -f1,3,7 /etc/passwd | head -15 | while IFS=: read user uid shell; do
    print_output "  Usuario: $user (UID: $uid) Shell: $shell"
done
print_output "  ... (mostrando primeros 15)"

print_output "Grupos del sistema:"
cut -d: -f1,3 /etc/group | head -15 | while IFS=: read group gid; do
    print_output "  Grupo: $group (GID: $gid)"
done
print_output "  ... (mostrando primeros 15)"

print_output "Usuarios con sudo:"
grep -E "^[^#].*ALL" /etc/sudoers 2>/dev/null | head -10 | while read line; do
    print_output "  $line"
done
print_output ""

print_output "Últimos logins:"
last -n 10 2>/dev/null | head -10 | while read line; do
    print_output "  $line"
done
print_output ""

# 8. CRON Y TAREAS PROGRAMADAS
print_output "[08] TAREAS PROGRAMADAS"
print_output "----------------------"

print_output "Cron jobs del sistema:"
if [ -d /etc/cron.d ]; then
    ls -la /etc/cron.d/ 2>/dev/null | head -10 | while read line; do
        print_output "  $line"
    done
fi

print_output "Crontabs de usuarios:"
for user in $(cut -d: -f1 /etc/passwd | head -5); do
    crontab -l -u $user 2>/dev/null | head -5 | while read line; do
        print_output "  $user: $line"
    done
done
print_output ""

print_output "Servicios programados (systemd timers):"
systemctl list-timers --all --no-pager 2>/dev/null | head -15 | while read line; do
    print_output "  $line"
done
print_output ""

# 9. KERNEL Y MÓDULOS
print_output "[09] KERNEL Y MÓDULOS"
print_output "---------------------"

print_output "Parámetros del kernel:"
sysctl -a 2>/dev/null | grep -E "net.ipv4.ip_forward|net.ipv4.tcp_syncookies|kernel.hostname" | head -10 | while read line; do
    print_output "  $line"
done
print_output ""

print_output "Módulos del kernel cargados:"
lsmod 2>/dev/null | head -20 | while read line; do
    print_output "  $line"
done
print_output "  ... (mostrando primeros 20)"
print_output ""

# 10. LOGS Y EVENTOS
print_output "[10] LOGS Y EVENTOS"
print_output "-------------------"

print_output "Últimos errores del sistema:"
journalctl -p err -n 20 --no-pager 2>/dev/null | head -20 | while read line; do
    print_output "  $line"
done
print_output ""

print_output "Intentos de login fallidos:"
if [ -f /var/log/auth.log ]; then
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20 | while read line; do
        print_output "  $line"
    done
elif [ -f /var/log/secure ]; then
    grep "Failed password" /var/log/secure 2>/dev/null | tail -20 | while read line; do
        print_output "  $line"
    done
fi
print_output ""

# 11. CONTENEDORES Y VIRTUALIZACIÓN
print_output "[11] CONTENEDORES Y VIRTUALIZACIÓN"
print_output "---------------------------------"

if command_exists docker; then
    print_output "Contenedores Docker:"
    docker ps -a 2>/dev/null | head -10 | while read line; do
        print_output "  $line"
    done
    
    print_output "Imágenes Docker:"
    docker images 2>/dev/null | head -10 | while read line; do
        print_output "  $line"
    done
fi
print_output ""

if command_exists systemd-detect-virt; then
    print_output "Tipo de virtualización: $(systemd-detect-virt 2>/dev/null || echo 'Ninguna')"
fi
print_output ""

# 12. VARIABLES DE ENTORNO Y CONFIGURACIÓN
print_output "[12] VARIABLES DE ENTORNO"
print_output "-------------------------"

print_output "Variables PATH:"
echo $PATH | tr ':' '\n' | head -10 | while read line; do
    print_output "  $line"
done
print_output ""

print_output "Variables de entorno relevantes:"
env | grep -E "HOME|USER|SHELL|LANG|JAVA|PYTHON|NODE" | head -20 | while read line; do
    print_output "  $line"
done
print_output ""

# 13. COMPROBACIONES DE SEGURIDAD ADICIONALES
print_output "[13] COMPROBACIONES DE SEGURIDAD"
print_output "-------------------------------"

# Verificar archivos con permisos SUID/SGID
print_output "Archivos SUID/SGID (primeros 20):"
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null | head -20 | while read line; do
    print_output "  $line"
done
print_output ""

# Verificar archivos world-writable
print_output "Archivos world-writable en directorios críticos (primeros 20):"
find /etc /bin /sbin /usr/bin /usr/sbin -type f -perm -2 -ls 2>/dev/null | head -20 | while read line; do
    print_output "  $line"
done
print_output ""

# Verificar puertos inseguros comunes
print_output "Verificación de puertos inseguros:"
INSECURE_PORTS="23 21 513 514 515"
for port in $INSECURE_PORTS; do
    if ss -tln 2>/dev/null | grep -q ":$port"; then
        print_output "  ⚠️  Puerto inseguro $port detectado"
    fi
done
print_output ""

# 14. RESUMEN Y RECOMENDACIONES
print_output "[14] RESUMEN Y RECOMENDACIONES"
print_output "-----------------------------"

# Contar servicios expuestos
SERVICES_COUNT=$(ss -tln 2>/dev/null | tail -n +2 | wc -l)
print_output "Total de servicios en listening: $SERVICES_COUNT"

# Sistema de 32 o 64 bits
if [ "$(uname -m)" = "x86_64" ]; then
    print_output "✅ Sistema de 64 bits"
else
    print_output "⚠️  Sistema de 32 bits - considerar actualización"
fi

# Verificar actualizaciones de seguridad (si apt está disponible)
if command_exists apt; then
    UPDATES=$(apt list --upgradable 2>/dev/null | grep -c security 2>/dev/null)
    if [ $UPDATES -gt 0 ]; then
        print_output "⚠️  Hay $UPDATES actualizaciones de seguridad pendientes"
    fi
fi

# Verificar si hay firewall activo
if command_exists ufw; then
    ufw status 2>/dev/null | grep -q "active" && print_output "✅ UFW firewall activo" || print_output "⚠️  UFW firewall inactivo"
elif command_exists iptables; then
    iptables -L 2>/dev/null | grep -q "Chain" && print_output "✅ Iptables activo" || print_output "⚠️  Iptables sin reglas"
fi

# Verificar SELinux/AppArmor
if command_exists getenforce; then
    SELINUX=$(getenforce 2>/dev/null)
    print_output "SELinux: $SELINUX"
elif command_exists aa-status; then
    aa-status 2>/dev/null | head -1 | while read line; do
        print_output "AppArmor: $line"
    done
fi
print_output ""

# 15. INFORMACIÓN ADICIONAL
print_output "[15] INFORMACIÓN ADICIONAL"
print_output "--------------------------"

print_output "Fecha y hora del sistema: $(date)"
print_output "Zona horaria: $(cat /etc/timezone 2>/dev/null || echo 'No configurada')"
print_output "Locale: $LANG"
print_output ""

print_output "Comandos disponibles en el sistema:"
for cmd in gcc make gdb strace tcpdump nmap netcat socat; do
    if command_exists $cmd; then
        print_output "  ✅ $cmd"
    else
        print_output "  ❌ $cmd"
    fi
done
print_output ""

print_output "================================================================================="
print_output "FIN DEL INFORME - $(date)"
print_output "Total de secciones: 15"
print_output "Archivo guardado: ${OUTPUT_FILE:-No guardado en archivo}"
print_output "================================================================================="

# Guardar metadatos del informe
if [ -n "$OUTPUT_FILE" ]; then
    echo "Generado por: $0" >> "$OUTPUT_FILE"
    echo "Usuario: $(whoami)" >> "$OUTPUT_FILE"
    echo "Timestamp: $(date +%s)" >> "$OUTPUT_FILE"
fi
