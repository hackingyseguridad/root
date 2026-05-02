#!/bin/sh

# Script: copyfail.sh detecta versiones de Kernel, en remoto, en red
# Uso.:  sh copyfail.sh  rango/IP
# nmap -Pn -F $1 $2 $3 --open -sV -O --osscan-guess -oN resultado.txt
# Guarda el resultado del escaneo en el fichero: resultado.txt
# @antonio_taboada - 

echo
echo "Detecta CVE-2026-31431 (Copy Fail) - Kernel >= 4.14 = potenciales vulnerables !!!"

nmap -Pn -F "$1" $2 $3 --open -sV -O --osscan-guess -oN resultado.txt  > /dev/null 2>&1
RESULT_FILE="resultado.txt"
current_host=""

while IFS= read -r line; do
    # Capturar dirección IP / hostname
    case "$line" in
        "Nmap scan report for "*)
            current_host=$(echo "$line" | sed 's/Nmap scan report for //' | sed 's/[()]//g')
            ;;
    esac

    echo "$line" | grep -i -E "OS details|Running|Kernel|Linux [0-9]" > /dev/null
    if [ $? -eq 0 ]; then
        # Extraer versión de kernel (Linux X.Y.Z o Linux X.Y)
        kernel_ver=$(echo "$line" | grep -o -E 'Linux [0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | awk '{print $2}')

        if [ -n "$kernel_ver" ]; then
            mayor=$(echo "$kernel_ver" | cut -d'.' -f1)
            menor=$(echo "$kernel_ver" | cut -d'.' -f2)

            if [ "$mayor" -gt 4 ] 2>/dev/null || [ "$mayor" -eq 4 -a "$menor" -ge 14 ] 2>/dev/null; then
                echo "¡POTENCIALMENTE VULNERABLE! Host: $current_host - Kernel: $kernel_ver (>= 4.14)"
            elif [ "$mayor" -lt 4 ] 2>/dev/null || [ "$mayor" -eq 4 -a "$menor" -lt 14 ] 2>/dev/null; then
                echo "Probablemente seguro: $current_host - Kernel: $kernel_ver (< 4.14)"
            else
                echo "❓ No se pudo determinar: $current_host - $kernel_ver"
            fi
        fi
    fi
done < "$RESULT_FILE"

echo ""
echo "Revise manualmente $RESULT_FILE para más detalles."

