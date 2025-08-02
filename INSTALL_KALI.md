# 🐉 Installation WiFiPumpkin3 sur Kali Linux

## 📋 Prérequis

Kali Linux est la plateforme **idéale** pour WiFiPumpkin3 car tous les outils nécessaires sont disponibles !

### ✅ Outils déjà présents sur Kali :
- `aircrack-ng` (suite complète)
- `hashcat` 
- `iptables`
- `openssl`
- `dnsmasq`
- `iwconfig` / `iwlist`
- `ifconfig`

## 🚀 Installation Rapide

### 1. Mise à jour du système
```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Installation des dépendances Python
```bash
# Installation des packages Python
sudo apt install python3-pip python3-venv python3-dev

# Installation des dépendances système
sudo apt install libpcap-dev libssl-dev libffi-dev

# Installation de netifaces (plus facile sur Kali)
sudo apt install python3-netifaces
```

### 3. Installation des outils WiFi
```bash
# Outils WiFi avancés
sudo apt install aircrack-ng hashcat dnsmasq

# Outils de monitoring réseau
sudo apt install tcpdump wireshark

# Outils de pentest WiFi
sudo apt install reaver bully pixiewps
```

### 4. Configuration du projet
```bash
# Cloner ou copier le projet
cd /opt/
sudo git clone [URL_DU_PROJET] wifipumpkin3
cd wifipumpkin3

# Créer un environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances Python
pip install -r requirements.txt

# Donner les permissions
sudo chown -R $USER:$USER .
chmod +x *.py
```

## 🔧 Configuration Spéciale Kali

### 1. Interface WiFi
```bash
# Lister les interfaces WiFi
iwconfig

# Vérifier le mode monitor
sudo airmon-ng start wlan0
```

### 2. Permissions
```bash
# Ajouter l'utilisateur au groupe netdev
sudo usermod -a -G netdev $USER

# Donner les permissions pour les outils WiFi
sudo chmod +s /usr/bin/aircrack-ng
sudo chmod +s /usr/bin/airodump-ng
```

### 3. Configuration réseau
```bash
# Désactiver NetworkManager pour les tests
sudo systemctl stop NetworkManager
sudo systemctl disable NetworkManager

# Ou configurer NetworkManager pour ignorer l'interface
echo 'unmanaged-devices=interface-name:wlan0' | sudo tee -a /etc/NetworkManager/conf.d/10-globally-managed-devices.conf
```

## 🎯 Lancement sur Kali

### Mode Développeur
```bash
# Avec environnement virtuel
source venv/bin/activate
python3 run.py
```

### Mode Production
```bash
# Créer un script de lancement
sudo tee /usr/local/bin/wifipumpkin3 << 'EOF'
#!/bin/bash
cd /opt/wifipumpkin3
source venv/bin/activate
python3 run.py
EOF

sudo chmod +x /usr/local/bin/wifipumpkin3

# Lancer depuis n'importe où
wifipumpkin3
```

## 🛠️ Optimisations Kali

### 1. Performance
```bash
# Optimiser les performances WiFi
echo 'options iwlwifi power_save=0' | sudo tee -a /etc/modprobe.d/iwlwifi.conf

# Recharger le module
sudo modprobe -r iwlwifi && sudo modprobe iwlwifi
```

### 2. Sécurité
```bash
# Configurer le pare-feu
sudo ufw enable
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

### 3. Monitoring
```bash
# Installer des outils de monitoring
sudo apt install htop iotop nethogs

# Monitoring en temps réel
watch -n 1 'iwconfig wlan0'
```

## 🎮 Utilisation Avancée

### Script de lancement automatique
```bash
#!/bin/bash
# /opt/wifipumpkin3/start_kali.sh

echo "🐉 Démarrage WiFiPumpkin3 sur Kali Linux"
echo "=========================================="

# Vérifier les privilèges
if [ "$EUID" -ne 0 ]; then
    echo "❌ Ce script doit être exécuté en tant que root"
    exit 1
fi

# Vérifier l'interface WiFi
INTERFACE=$(iwconfig 2>/dev/null | grep -o '^[^ ]*' | head -1)
if [ -z "$INTERFACE" ]; then
    echo "❌ Aucune interface WiFi détectée"
    exit 1
fi

echo "✅ Interface WiFi détectée: $INTERFACE"

# Activer le mode monitor
echo "🔧 Activation du mode monitor..."
airmon-ng start $INTERFACE

# Lancer l'application
cd /opt/wifipumpkin3
source venv/bin/activate
python3 run.py

# Nettoyer à la sortie
echo "🧹 Nettoyage..."
airmon-ng stop ${INTERFACE}mon
```

## 🎯 Avantages sur Kali

1. **Performance maximale** - Tous les outils optimisés
2. **Sécurité renforcée** - Environnement isolé
3. **Compatibilité parfaite** - Drivers WiFi optimisés
4. **Outils intégrés** - Suite complète de pentest
5. **Support communautaire** - Large base d'utilisateurs

## 🚨 Notes importantes

- **Toujours utiliser en mode root** pour les attaques WiFi
- **Tester sur votre propre réseau** uniquement
- **Respecter la législation** locale
- **Utiliser à des fins éducatives** uniquement

Votre projet WiFiPumpkin3 est **parfaitement adapté** pour Kali Linux ! 🎯 