#!/bin/bash
# audit_local.sh - POC simple para auditar vulnerabilidades de escalado a root
# Basado en: https://github.com/hackingyseguridad/root
# Uso: ./audit_local.sh

ROJO='\033[0;31m'
VERDE='\033[0;32m'
AMARILLO='\033[1;33m'
AZUL='\033[0;34m'
SIN_COLOR='\033[0m'

echo -e "${AZUL}========================================${SIN_COLOR}"
echo -e "${AZUL}  Auditoría Local de Escalado Privilegios${SIN_COLOR}"
echo -e "${AZUL}========================================${SIN_COLOR}\n"

# --- Información del Sistema ---
KERNEL_VERSION=$(uname -r)
SUDO_VERSION=$(sudo --version | head -n1 | awk '{print $3}')
echo -e "🔍 Kernel detectado: ${AMARILLO}$KERNEL_VERSION${SIN_COLOR}"
echo -e "🔍 Sudo detectado:   ${AMARILLO}${SUDO_VERSION:-No instalado}${SIN_COLOR}\n"

# --- Función para comprobar CVE específicos ---
check_cve() {
    local CVE=$1
    local AFECTADO=$2
    local MENSAJE=$3
    local VULNERABLE=false

    # Lógica simple de verificación basada en versiones
    if [[ "$CVE" == "CVE-2019-14287" ]] && [[ -n "$SUDO_VERSION" ]]; then
        # Vulnerable si es < 1.8.28
        if [[ "$SUDO_VERSION" < "1.8.28" ]]; then
            VULNERABLE=true
        fi
    elif [[ "$CVE" == "CVE-2021-3156" ]] && [[ -n "$SUDO_VERSION" ]]; then
        # Vulnerable si es < 1.9.5p2
        if [[ "$SUDO_VERSION" < "1.9.5" ]]; then
            VULNERABLE=true
        fi
    elif [[ "$CVE" == "CVE-2022-0847" ]]; then
        # Dirty Pipe: kernel >=5.8 (tu kernel 4.18 NO es vulnerable)
        if [[ "$KERNEL_VERSION" == 5.8* ]] || [[ "$KERNEL_VERSION" > "5.8" ]]; then
            VULNERABLE=true
        fi
    elif [[ "$CVE" == "CVE-2024-27397" ]]; then
        # netfilter: kernels recientes, 4.18 probablemente NO
        if [[ "$KERNEL_VERSION" > "5.15" ]]; then
            VULNERABLE=true
        fi
    elif [[ "$CVE" == "CVE-2025-32463" ]] && [[ -n "$SUDO_VERSION" ]]; then
        # Sudo 1.9.14 a 1.9.17
        if [[ "$SUDO_VERSION" == "1.9.14"* ]] || [[ "$SUDO_VERSION" == "1.9.15"* ]] || [[ "$SUDO_VERSION" == "1.9.16"* ]] || [[ "$SUDO_VERSION" == "1.9.17"* ]]; then
            VULNERABLE=true
        fi
    elif [[ "$CVE" == "CVE-2008-0600" ]]; then
        # Kernel 2.6.17 a 2.6.24.1
        if [[ "$KERNEL_VERSION" == "2.6.17"* ]] || [[ "$KERNEL_VERSION" == "2.6.18"* ]] || [[ "$KERNEL_VERSION" == "2.6.19"* ]] || [[ "$KERNEL_VERSION" == "2.6.20"* ]] || [[ "$KERNEL_VERSION" == "2.6.21"* ]] || [[ "$KERNEL_VERSION" == "2.6.22"* ]] || [[ "$KERNEL_VERSION" == "2.6.23"* ]] || [[ "$KERNEL_VERSION" == "2.6.24"* ]]; then
            VULNERABLE=true
        fi
    elif [[ "$CVE" == "CVE-2026-24061" ]]; then
        # telnetd, requiere comprobar si está corriendo
        if pgrep -x "telnetd" > /dev/null; then
            VULNERABLE=true
            MENSAJE="Servicio telnetd detectado en ejecución. Revisa versiones 1.9.3-2.7."
        fi
    fi

    if [ "$VULNERABLE" = true ]; then
        echo -e "❌ ${ROJO}$CVE - POTENCIALMENTE VULNERABLE${SIN_COLOR}"
        echo -e "   $MENSAJE"
    else
        echo -e "✅ ${VERDE}$CVE - No parece vulnerable por versión${SIN_COLOR}"
        echo -e "   $MENSAJE"
    fi
}

echo -e "${AZUL}--- Verificando CVEs específicos ---${SIN_COLOR}"

# CVEs del repositorio (aplicables a kernel o sudo)
check_cve "CVE-2008-0600" "kernel" "Linux Kernel 2.6.17-2.6.24.1 - vmsplice LPE"
check_cve "CVE-2019-14287" "sudo" "Sudo <1.8.28 - Bypass de política con 'sudo -u #-1'"
check_cve "CVE-2021-3156" "sudo" "Sudo <1.9.5p2 - Heap overflow en sudoedit"
check_cve "CVE-2021-4034" "polkit" "pkexec (independiente de versión kernel/sudo) - Comprueba si 'pkexec' está presente y es SUID"
check_cve "CVE-2022-0847" "kernel" "Dirty Pipe - kernel >=5.8 - Sobrescritura de archivos"
check_cve "CVE-2024-27397" "kernel" "netfilter nf_tables use-after-free - kernels recientes"
check_cve "CVE-2025-32463" "sudo" "Sudo 1.9.14-1.9.17 - Chroot escape"
check_cve "CVE-2026-24061" "telnetd" "GNU InetUtils telnetd 1.9.3-2.7 - Bypass autenticación"

echo -e "\n${AZUL}--- Verificaciones adicionales ---${SIN_COLOR}"

# 1. Buscar binarios SUID (técnica genérica del repositorio)
echo -e "${AMARILLO}[+] Buscando binarios SUID (potencialmente explotables):${SIN_COLOR}"
SUID_BINS=$(find / -perm -4000 2>/dev/null | head -10)
if [ -n "$SUID_BINS" ]; then
    echo "$SUID_BINS" | while read bin; do
        echo "   🔹 $bin"
    done
    echo "   ... (mostrando primeros 10)"
else
    echo "   No se encontraron binarios SUID."
fi

# 2. Comprobar si pkexec existe y es SUID (CVE-2021-4034)
if [ -f /usr/bin/pkexec ]; then
    if [ -u /usr/bin/pkexec ]; then
        echo -e "❌ ${ROJO}/usr/bin/pkexec presente y con SUID - Verificar CVE-2021-4034${SIN_COLOR}"
    else
        echo -e "✅ ${VERDE}/usr/bin/pkexec presente pero sin SUID${SIN_COLOR}"
    fi
else
    echo -e "ℹ️  ${AMARILLO}/usr/bin/pkexec no encontrado${SIN_COLOR}"
fi

echo -e "\n${AZUL}========================================${SIN_COLOR}"
echo -e "${AZUL}  Auditoría completada${SIN_COLOR}"
echo -e "${AZUL}========================================${SIN_COLOR}"
