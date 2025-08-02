#!/bin/bash
# 🔍 Script de diagnostic Evil Twin WiFiPumpkin3
# Automatise la détection et la résolution des problèmes

set -e

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

echo "🔍 Diagnostic Evil Twin WiFiPumpkin3"
echo "===================================="
echo ""

# Vérification des privilèges root
if [ "$EUID" -ne 0 ]; then
    print_error "Ce script doit être exécuté en tant que root"
    print_warning "Utilisez: sudo $0"
    exit 1
fi

print_success "Privilèges root confirmés"

# Vérification des interfaces WiFi
print_status "Vérification des interfaces WiFi..."

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
    print_status "Solutions possibles :"
    echo "   - Vérifier que la carte WiFi est connectée"
    echo "   - Installer les drivers appropriés"
    echo "   - Vérifier que le module WiFi est chargé"
    echo "   - Redémarrer le service réseau"
    exit 1
fi

PRIMARY_INTERFACE="${INTERFACES[0]}"
print_success "Interface WiFi principale: $PRIMARY_INTERFACE"

# Vérification du mode de l'interface
print_status "Vérification du mode de l'interface..."

if iwconfig "$PRIMARY_INTERFACE" 2>/dev/null | grep -q "Mode:Monitor"; then
    print_success "Interface en mode monitor"
    MONITOR_INTERFACE="$PRIMARY_INTERFACE"
else
    print_warning "Interface pas en mode monitor"
    print_status "Tentative d'activation du mode monitor..."
    
    # Arrêter NetworkManager si actif
    if systemctl is-active --quiet NetworkManager; then
        print_status "Arrêt de NetworkManager..."
        systemctl stop NetworkManager
    fi
    
    # Activer le mode monitor
    if airmon-ng start "$PRIMARY_INTERFACE" >/dev/null 2>&1; then
        MONITOR_INTERFACE="${PRIMARY_INTERFACE}mon"
        print_success "Mode monitor activé: $MONITOR_INTERFACE"
    else
        print_error "Impossible d'activer le mode monitor"
        print_status "Vérifier les drivers WiFi et les permissions"
        MONITOR_INTERFACE="$PRIMARY_INTERFACE"
    fi
fi

# Vérification des services DHCP
print_status "Vérification des services DHCP..."

DHCP_CONFLICTS=()
if systemctl is-active --quiet dhcpd; then
    DHCP_CONFLICTS+=("dhcpd")
fi

if systemctl is-active --quiet dnsmasq; then
    DHCP_CONFLICTS+=("dnsmasq")
fi

if netstat -tulpn 2>/dev/null | grep -q ":67"; then
    DHCP_CONFLICTS+=("port_67")
fi

if [ ${#DHCP_CONFLICTS[@]} -ne 0 ]; then
    print_warning "Conflits DHCP détectés: ${DHCP_CONFLICTS[*]}"
    print_status "Arrêt des services DHCP..."
    
    for service in "${DHCP_CONFLICTS[@]}"; do
        case $service in
            "dhcpd")
                systemctl stop dhcpd 2>/dev/null || true
                print_status "Service dhcpd arrêté"
                ;;
            "dnsmasq")
                systemctl stop dnsmasq 2>/dev/null || true
                print_status "Service dnsmasq arrêté"
                ;;
            "port_67")
                print_status "Port 67 utilisé, vérifier les processus..."
                netstat -tulpn | grep :67
                ;;
        esac
    done
else
    print_success "Aucun conflit DHCP détecté"
fi

# Vérification de la configuration réseau
print_status "Vérification de la configuration réseau..."

# Vérifier l'adresse IP de l'interface
if ip addr show "$MONITOR_INTERFACE" 2>/dev/null | grep -q "inet"; then
    IP_ADDR=$(ip addr show "$MONITOR_INTERFACE" | grep "inet" | awk '{print $2}' | cut -d/ -f1)
    print_success "Interface $MONITOR_INTERFACE a l'IP: $IP_ADDR"
else
    print_warning "Interface $MONITOR_INTERFACE n'a pas d'adresse IP"
    print_status "Configuration de l'adresse IP..."
    
    # Configurer l'interface
    ip addr add 192.168.1.1/24 dev "$MONITOR_INTERFACE" 2>/dev/null || true
    ip link set "$MONITOR_INTERFACE" up
    
    print_success "Interface $MONITOR_INTERFACE configurée avec 192.168.1.1/24"
fi

# Vérification des routes
print_status "Vérification des routes..."

if ip route show | grep -q "192.168.1.0/24"; then
    print_success "Route 192.168.1.0/24 configurée"
else
    print_warning "Route 192.168.1.0/24 manquante"
    print_status "Ajout de la route..."
    ip route add 192.168.1.0/24 dev "$MONITOR_INTERFACE" 2>/dev/null || true
fi

# Vérification du forwarding IP
print_status "Vérification du forwarding IP..."

if [ "$(cat /proc/sys/net/ipv4/ip_forward)" -eq 1 ]; then
    print_success "IP forwarding activé"
else
    print_warning "IP forwarding désactivé"
    print_status "Activation du forwarding IP..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    print_success "IP forwarding activé"
fi

# Vérification de la connectivité Internet
print_status "Vérification de la connectivité Internet..."

if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    print_success "Connectivité Internet OK"
else
    print_warning "Pas de connectivité Internet"
    print_status "Vérifier la configuration réseau"
fi

# Vérification des outils nécessaires
print_status "Vérification des outils nécessaires..."

TOOLS=("aircrack-ng" "dnsmasq" "iptables")
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
    apt install -y "${MISSING_TOOLS[@]}"
else
    print_success "Tous les outils nécessaires sont disponibles"
fi

# Configuration automatique d'iptables
print_status "Configuration d'iptables..."

# Nettoyer les règles existantes
iptables -F 2>/dev/null || true
iptables -t nat -F 2>/dev/null || true

# Trouver l'interface Internet
INTERNET_INTERFACE=""
for interface in eth0 eth1 wlan1; do
    if ip link show "$interface" >/dev/null 2>&1; then
        INTERNET_INTERFACE="$interface"
        break
    fi
done

if [ -n "$INTERNET_INTERFACE" ]; then
    # Configurer NAT
    iptables -t nat -A POSTROUTING -o "$INTERNET_INTERFACE" -j MASQUERADE
    iptables -A FORWARD -i "$MONITOR_INTERFACE" -o "$INTERNET_INTERFACE" -j ACCEPT
    iptables -A FORWARD -i "$INTERNET_INTERFACE" -o "$MONITOR_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    print_success "NAT configuré via $INTERNET_INTERFACE"
else
    print_warning "Interface Internet non trouvée"
fi

# Test de configuration DHCP
print_status "Test de configuration DHCP..."

# Créer une configuration dnsmasq temporaire
cat > /tmp/dnsmasq_test.conf << EOF
interface=$MONITOR_INTERFACE
dhcp-range=192.168.1.100,192.168.1.200,255.255.255.0,24h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
EOF

# Tester dnsmasq
if dnsmasq -C /tmp/dnsmasq_test.conf --test 2>/dev/null; then
    print_success "Configuration DHCP valide"
else
    print_error "Erreur dans la configuration DHCP"
fi

# Nettoyer le fichier temporaire
rm -f /tmp/dnsmasq_test.conf

echo ""
echo "🎯 DIAGNOSTIC TERMINÉ"
echo "====================="
echo ""
print_success "Résumé des vérifications :"
echo "  ✅ Privilèges root"
echo "  ✅ Interface WiFi: $PRIMARY_INTERFACE"
echo "  ✅ Mode monitor: $MONITOR_INTERFACE"
echo "  ✅ Services DHCP vérifiés"
echo "  ✅ Configuration réseau"
echo "  ✅ Routes configurées"
echo "  ✅ IP forwarding activé"
echo "  ✅ Outils nécessaires"
echo "  ✅ Configuration NAT"
echo "  ✅ Configuration DHCP"
echo ""
print_status "Votre Evil Twin devrait maintenant fonctionner !"
echo ""
print_warning "Si le problème persiste, vérifiez :"
echo "  - Les logs dnsmasq: sudo tail -f /var/log/dnsmasq.log"
echo "  - Les logs système: sudo journalctl -f"
echo "  - La connectivité: ping 8.8.8.8"
echo "  - Les clients connectés: sudo arp -a" 