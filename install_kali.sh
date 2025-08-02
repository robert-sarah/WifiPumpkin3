#!/bin/bash
# 🐉 Script d'installation WiFiPumpkin3 pour Kali Linux
# Installation automatique et configuration complète

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

echo "🐉 Installation WiFiPumpkin3 - Kali Linux"
echo "========================================="
echo ""

# Vérification des privilèges root
if [ "$EUID" -ne 0 ]; then
    print_error "Ce script doit être exécuté en tant que root"
    print_warning "Utilisez: sudo $0"
    exit 1
fi

print_success "Privilèges root confirmés"

# Vérification de l'environnement Kali
print_status "Vérification de l'environnement Kali..."

if ! grep -q "kali" /etc/os-release 2>/dev/null; then
    print_warning "Ce script est optimisé pour Kali Linux"
    print_warning "Fonctionnement possible sur d'autres distributions Linux"
fi

# Mise à jour du système
print_status "Mise à jour du système..."
apt update && apt upgrade -y

print_success "Système mis à jour"

# Installation des dépendances système
print_status "Installation des dépendances système..."

PACKAGES=(
    "python3-pip"
    "python3-venv"
    "python3-dev"
    "libpcap-dev"
    "libssl-dev"
    "libffi-dev"
    "python3-netifaces"
    "aircrack-ng"
    "hashcat"
    "dnsmasq"
    "tcpdump"
    "wireshark"
    "reaver"
    "bully"
    "pixiewps"
    "htop"
    "iotop"
    "nethogs"
)

for package in "${PACKAGES[@]}"; do
    print_status "Installation de $package..."
    apt install -y "$package" 2>/dev/null || print_warning "Package $package non installé"
done

print_success "Dépendances système installées"

# Configuration du projet
print_status "Configuration du projet..."

# Créer le répertoire d'installation
INSTALL_DIR="/opt/wifipumpkin3"
mkdir -p "$INSTALL_DIR"

# Copier les fichiers du projet
print_status "Copie des fichiers..."
cp -r . "$INSTALL_DIR/"

# Aller dans le répertoire d'installation
cd "$INSTALL_DIR"

# Créer l'environnement virtuel
print_status "Création de l'environnement virtuel..."
python3 -m venv venv

# Activer l'environnement virtuel
source venv/bin/activate

# Installer les dépendances Python
print_status "Installation des dépendances Python..."
pip install -r requirements.txt

print_success "Environnement Python configuré"

# Configuration des permissions
print_status "Configuration des permissions..."

# Donner les permissions
chown -R $SUDO_USER:$SUDO_USER "$INSTALL_DIR"
chmod +x *.py
chmod +x start_kali.sh
chmod +x evil_twin_diagnostic.sh

# Ajouter l'utilisateur au groupe netdev
usermod -a -G netdev $SUDO_USER

# Donner les permissions pour les outils WiFi
chmod +s /usr/bin/aircrack-ng 2>/dev/null || true
chmod +s /usr/bin/airodump-ng 2>/dev/null || true

print_success "Permissions configurées"

# Configuration NetworkManager
print_status "Configuration de NetworkManager..."

# Créer la configuration pour ignorer l'interface WiFi
mkdir -p /etc/NetworkManager/conf.d/
echo 'unmanaged-devices=interface-name:wlan0' > /etc/NetworkManager/conf.d/10-globally-managed-devices.conf

print_success "NetworkManager configuré"

# Optimisation des performances WiFi
print_status "Optimisation des performances WiFi..."

# Créer la configuration pour optimiser les performances
echo 'options iwlwifi power_save=0' > /etc/modprobe.d/iwlwifi.conf

# Recharger le module si possible
modprobe -r iwlwifi 2>/dev/null || true
modprobe iwlwifi 2>/dev/null || true

print_success "Performances WiFi optimisées"

# Configuration du pare-feu
print_status "Configuration du pare-feu..."

# Activer UFW
ufw --force enable

# Autoriser les ports nécessaires
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 53/udp
ufw allow 67/udp

print_success "Pare-feu configuré"

# Création du script global
print_status "Création du script global..."

cat > /usr/local/bin/wifipumpkin3 << 'EOF'
#!/bin/bash
# 🐉 WiFiPumpkin3 - Lanceur global

echo "🐉 WiFiPumpkin3 - Kali Linux"
echo "============================"

# Vérifier les privilèges
if [ "$EUID" -ne 0 ]; then
    echo "❌ Ce script doit être exécuté en tant que root"
    echo "💡 Utilisez: sudo wifipumpkin3"
    exit 1
fi

# Vérifier l'interface WiFi
INTERFACE=$(iwconfig 2>/dev/null | grep -o '^[^ ]*' | head -1)
if [ -z "$INTERFACE" ]; then
    echo "❌ Aucune interface WiFi détectée"
    echo "💡 Vérifiez votre carte WiFi"
    exit 1
fi

echo "✅ Interface WiFi détectée: $INTERFACE"

# Activer le mode monitor
echo "🔧 Activation du mode monitor..."
airmon-ng start $INTERFACE 2>/dev/null || true

# Lancer l'application
cd /opt/wifipumpkin3
source venv/bin/activate
python3 run.py

# Nettoyer à la sortie
echo "🧹 Nettoyage..."
airmon-ng stop ${INTERFACE}mon 2>/dev/null || true
EOF

chmod +x /usr/local/bin/wifipumpkin3

print_success "Script global créé"

# Création du raccourci desktop
print_status "Création du raccourci desktop..."

cat > /usr/share/applications/wifipumpkin3.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=WiFiPumpkin3
Comment=WiFi Security Testing Tool
Exec=sudo wifipumpkin3
Icon=network-wireless
Terminal=true
Categories=Network;Security;
Keywords=wifi;security;pentest;
EOF

print_success "Raccourci desktop créé"

# Création du répertoire de logs
print_status "Création du répertoire de logs..."
mkdir -p /opt/wifipumpkin3/logs
chown -R $SUDO_USER:$SUDO_USER /opt/wifipumpkin3/logs

print_success "Répertoire de logs créé"

# Test de l'installation
print_status "Test de l'installation..."

# Vérifier que les outils sont installés
TOOLS=("aircrack-ng" "hashcat" "dnsmasq" "python3")
MISSING_TOOLS=()

for tool in "${TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    print_warning "Outils manquants: ${MISSING_TOOLS[*]}"
    print_status "Installation manuelle requise"
else
    print_success "Tous les outils sont installés"
fi

# Test de l'environnement Python
if [ -f "/opt/wifipumpkin3/venv/bin/python" ]; then
    print_success "Environnement Python configuré"
else
    print_error "Environnement Python non configuré"
fi

echo ""
echo "🎯 INSTALLATION TERMINÉE"
echo "========================"
echo ""
print_success "WiFiPumpkin3 installé avec succès !"
echo ""
print_status "Méthodes de lancement :"
echo "  🚀 Lancement direct: sudo wifipumpkin3"
echo "  📁 Depuis le répertoire: cd /opt/wifipumpkin3 && sudo ./start_kali.sh"
echo "  🔍 Diagnostic: sudo ./evil_twin_diagnostic.sh"
echo ""
print_status "Fichiers importants :"
echo "  📂 Répertoire: /opt/wifipumpkin3"
echo "  📝 Logs: /opt/wifipumpkin3/logs"
echo "  ⚙️  Configuration: /opt/wifipumpkin3/config"
echo ""
print_warning "N'oubliez pas :"
echo "  - Tester uniquement sur votre propre réseau"
echo "  - Respecter la législation locale"
echo "  - Utiliser à des fins éducatives uniquement"
echo ""
print_success "Installation terminée ! Votre WiFiPumpkin3 est prêt à l'emploi ! 🎯" 