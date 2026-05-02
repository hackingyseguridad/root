#!/bin/sh
# Script: check_copyfail.sh
# Uso 1 (escaneo + análisis): ./check_copyfail.sh <target>
# Uso 2 (solo análisis): ./check_copyfail.sh --read resultado.txt

echo "[*] Detector CVE-2026-31431 (Copy Fail) - Kernel >= 4.14 = potencialmente vulnerable"

# Modo solo lectura de resultado.txt existente
if [ "$1" = "--read" ] && [ -f "$2" ]; then
    RESULT_FILE="$2"
    echo "[*] Leyendo archivo existente: $RESULT_FILE"
else
    # Modo normal: ejecutar nmap y guardar en resultado.txt
    if [ -z "$1" ]; then
        echo "Uso: $0 <target> [parámetros_nmap]"
        echo "     $0 --read resultado.txt"
        echo "Ejemplo: $0 192.168.1.100"
        echo "Ejemplo con puertos: $0 192.168.1.100 -p 22,80,443"
        exit 1
    fi

    echo "[+] Ejecutando nmap -Pn -F $1 $2 $3 --open -sV -O --osscan-guess -oN resultado.txt"
    nmap -Pn -F "$1" $2 $3 --open -sV -O --osscan-guess -oN resultado.txt  > /dev/null 2>&1
    RESULT_FILE="resultado.txt"
fi

echo "[+] Analizando $RESULT_FILE..."

# Variable para almacenar el host actual
current_host=""

# Leer línea por línea el archivo resultado.txt
while IFS= read -r line; do
    # Capturar dirección IP / hostname
    case "$line" in
        "Nmap scan report for "*)
            current_host=$(echo "$line" | sed 's/Nmap scan report for //' | sed 's/[()]//g')
            ;;
    esac

    # Buscar líneas con "OS details" o "Running" o "Kernel"
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
echo "[*] Análisis completado. Revise manualmente $RESULT_FILE para más detalles."
echo "[*] Nota: La detección remota de kernel por nmap no es 100% precisa."
