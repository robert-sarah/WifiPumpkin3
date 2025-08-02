#!/bin/bash
# 🐉 Script de lancement WiFiPumpkin3 pour Kali Linux
# Optimisé pour les performances et la sécurité

set -e  # Arrêter en cas d'erreur

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction d'affichage
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Bannière
echo "🐉 WiFiPumpkin3 - Kali Linux Edition"
echo "====================================="
echo "🔧 Optimisé pour les performances WiFi"
echo "🛡️  Configuration sécurisée"
echo ""

# Vérification des privilèges root
if [ "$EUID" -ne 0 ]; then
    print_error "Ce script doit être exécuté en tant que root"
    print_warning "Utilisez: sudo $0"
    exit 1
fi

print_success "Privilèges root confirmés"

# Vérification de l'environnement Kali
if ! grep -q "kali" /etc/os-release 2>/dev/null; then
    print_warning "Ce script est optimisé pour Kali Linux"
    print_warning "Fonctionnement possible sur d'autres distributions Linux"
fi

# Vérification des outils essentiels
print_status "Vérification des outils système..."

TOOLS=("aircrack-ng" "airodump-ng" "iwconfig" "ifconfig" "iptables")
MISSING_TOOLS=()

for tool in "${TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    print_error "Outils manquants: ${MISSING_TOOLS[*]}"
    print_status "Installation des outils manquants..."
    apt update
    apt install -y aircrack-ng iwconfig ifconfig iptables
else
    print_success "Tous les outils système sont disponibles"
fi

# Vérification des interfaces WiFi
print_status "Détection des interfaces WiFi..."

INTERFACES=()
for interface in /sys/class/net/*; do
    if [ -d "$interface" ]; then
        interface_name=$(basename "$interface")
        if iwconfig "$interface_name" 2>/dev/null | grep -q "IEEE 802.11"; then
            INTERFACES+=("$interface_name")
        fi
    fi
done

if [ ${#INTERFACES[@]} -eq 0 ]; then
    print_error "Aucune interface WiFi détectée"
    print_status "Vérification des modules WiFi..."
    modprobe iwlwifi 2>/dev/null || true
    sleep 2
    
    # Nouvelle tentative
    for interface in /sys/class/net/*; do
        if [ -d "$interface" ]; then
            interface_name=$(basename "$interface")
            if iwconfig "$interface_name" 2>/dev/null | grep -q "IEEE 802.11"; then
                INTERFACES+=("$interface_name")
            fi
        fi
    done
fi

if [ ${#INTERFACES[@]} -eq 0 ]; then
    print_error "Impossible de détecter une interface WiFi"
    print_status "Interfaces disponibles:"
    ip link show | grep -E "^[0-9]+:" | cut -d: -f2
    exit 1
fi

PRIMARY_INTERFACE="${INTERFACES[0]}"
print_success "Interface WiFi principale: $PRIMARY_INTERFACE"

# Configuration de l'interface
print_status "Configuration de l'interface WiFi..."

# Arrêter NetworkManager pour éviter les conflits
if systemctl is-active --quiet NetworkManager; then
    print_status "Arrêt temporaire de NetworkManager..."
    systemctl stop NetworkManager
    NETWORKMANAGER_STOPPED=true
fi

# Activer le mode monitor
print_status "Activation du mode monitor sur $PRIMARY_INTERFACE..."
if airmon-ng start "$PRIMARY_INTERFACE" >/dev/null 2>&1; then
    MONITOR_INTERFACE="${PRIMARY_INTERFACE}mon"
    print_success "Mode monitor activé: $MONITOR_INTERFACE"
else
    print_warning "Impossible d'activer le mode monitor"
    MONITOR_INTERFACE="$PRIMARY_INTERFACE"
fi

# Vérification de l'environnement Python
print_status "Vérification de l'environnement Python..."

if [ ! -d "venv" ]; then
    print_status "Création de l'environnement virtuel..."
    python3 -m venv venv
fi

# Activation de l'environnement virtuel
source venv/bin/activate

# Installation des dépendances si nécessaire
if [ ! -f "venv/pyvenv.cfg" ]; then
    print_status "Installation des dépendances Python..."
    pip install -r requirements.txt
fi

# Configuration des permissions
print_status "Configuration des permissions..."
chmod +x *.py
chmod +x ui/*.py
chmod +x core/*.py
chmod +x utils/*.py

# Nettoyage des fichiers temporaires
print_status "Nettoyage des fichiers temporaires..."
rm -f /tmp/wifi_scan/*
rm -f /tmp/captured_credentials.json
rm -f /tmp/ssl_cert.pem
rm -f /tmp/ssl_key.pem

# Configuration du pare-feu
print_status "Configuration du pare-feu..."
iptables -F 2>/dev/null || true
iptables -t nat -F 2>/dev/null || true
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Lancement de l'application
print_success "Lancement de WiFiPumpkin3..."
echo ""

# Fonction de nettoyage
cleanup() {
    print_status "Nettoyage en cours..."
    
    # Remettre l'interface en mode managed
    if [ -n "$MONITOR_INTERFACE" ] && [ "$MONITOR_INTERFACE" != "$PRIMARY_INTERFACE" ]; then
        airmon-ng stop "$MONITOR_INTERFACE" >/dev/null 2>&1 || true
    fi
    
    # Redémarrer NetworkManager si on l'avait arrêté
    if [ "$NETWORKMANAGER_STOPPED" = true ]; then
        systemctl start NetworkManager
    fi
    
    # Nettoyer les règles iptables
    iptables -F 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    
    print_success "Nettoyage terminé"
}

# Capturer les signaux pour le nettoyage
trap cleanup EXIT INT TERM

# Lancement de l'application
python3 run.py

# Le nettoyage sera automatiquement exécuté grâce au trap 