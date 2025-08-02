# 🐉 WiFiPumpkin3 - Guide Kali Linux

## 🚀 **Installation Rapide sur Kali**

### Étape 1 : Préparation du système
```bash
# Mise à jour du système
sudo apt update && sudo apt upgrade -y

# Installation des dépendances système
sudo apt install python3-pip python3-venv python3-dev
sudo apt install libpcap-dev libssl-dev libffi-dev
sudo apt install python3-netifaces

# Installation des outils WiFi
sudo apt install aircrack-ng hashcat dnsmasq
sudo apt install tcpdump wireshark
sudo apt install reaver bully pixiewps
```

### Étape 2 : Configuration du projet
```bash
# Copier le projet dans /opt/
sudo cp -r /chemin/vers/projet /opt/wifipumpkin3
cd /opt/wifipumpkin3

# Créer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances Python
pip install -r requirements.txt

# Donner les permissions
sudo chown -R $USER:$USER .
chmod +x *.py
chmod +x start_kali.sh
chmod +x evil_twin_diagnostic.sh
```

### Étape 3 : Configuration des permissions
```bash
# Ajouter l'utilisateur au groupe netdev
sudo usermod -a -G netdev $USER

# Donner les permissions pour les outils WiFi
sudo chmod +s /usr/bin/aircrack-ng
sudo chmod +s /usr/bin/airodump-ng

# Configurer NetworkManager pour ignorer l'interface
echo 'unmanaged-devices=interface-name:wlan0' | sudo tee -a /etc/NetworkManager/conf.d/10-globally-managed-devices.conf
```

## 🎯 **Lancement sur Kali**

### Mode Simple
```bash
# Lancer directement
sudo python3 run.py
```

### Mode Optimisé (Recommandé)
```bash
# Utiliser le script optimisé
sudo ./start_kali.sh
```

### Mode Diagnostic
```bash
# Diagnostic automatique
sudo ./evil_twin_diagnostic.sh
```

## 🔧 **Configuration Avancée**

### Optimisation des performances
```bash
# Optimiser les performances WiFi
echo 'options iwlwifi power_save=0' | sudo tee -a /etc/modprobe.d/iwlwifi.conf

# Recharger le module
sudo modprobe -r iwlwifi && sudo modprobe iwlwifi
```

### Configuration de sécurité
```bash
# Configurer le pare-feu
sudo ufw enable
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

### Installation d'outils supplémentaires
```bash
# Outils de monitoring
sudo apt install htop iotop nethogs

# Outils de pentest WiFi avancés
sudo apt install kismet
sudo apt install wifite
sudo apt install fern-wifi-cracker
```

## 🎮 **Utilisation des Fonctionnalités**

### 1. **Evil Twin Attack**
```bash
# Lancer l'application
sudo ./start_kali.sh

# Dans l'interface :
# 1. Aller dans l'onglet "Evil Twin"
# 2. Sélectionner l'interface WiFi
# 3. Choisir le réseau cible
# 4. Configurer le portail captif
# 5. Cliquer sur "Démarrer"
```

### 2. **Deauth Attack**
```bash
# Dans l'interface :
# 1. Aller dans l'onglet "Deauth"
# 2. Sélectionner l'interface
# 3. Choisir la cible
# 4. Configurer le nombre de paquets
# 5. Cliquer sur "Démarrer"
```

### 3. **WPA Cracking**
```bash
# Dans l'interface :
# 1. Aller dans l'onglet "WPA Cracking"
# 2. Capturer le handshake
# 3. Choisir la wordlist
# 4. Lancer le cracking
```

### 4. **DNS Spoofing**
```bash
# Dans l'interface :
# 1. Aller dans l'onglet "DNS Spoof"
# 2. Configurer les domaines
# 3. Démarrer l'attaque
```

## 🛠️ **Scripts Utilitaires**

### Script de lancement automatique
```bash
#!/bin/bash
# /usr/local/bin/wifipumpkin3

echo "🐉 WiFiPumpkin3 - Kali Linux"
echo "============================"

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

### Installation du script global
```bash
# Copier le script
sudo cp /opt/wifipumpkin3/start_kali.sh /usr/local/bin/wifipumpkin3
sudo chmod +x /usr/local/bin/wifipumpkin3

# Maintenant vous pouvez lancer depuis n'importe où
sudo wifipumpkin3
```

## 📊 **Monitoring et Logs**

### Vérification des logs
```bash
# Logs dnsmasq
sudo tail -f /var/log/dnsmasq.log

# Logs système
sudo journalctl -f

# Logs de l'application
tail -f /opt/wifipumpkin3/logs/wifipumpkin3.log
```

### Monitoring en temps réel
```bash
# Monitoring des interfaces
watch -n 1 'iwconfig'

# Monitoring des processus
htop

# Monitoring réseau
nethogs
```

## 🎯 **Scénarios d'Utilisation**

### Scénario 1 : Test de sécurité WiFi
```bash
# 1. Lancer l'application
sudo wifipumpkin3

# 2. Scanner les réseaux
# 3. Choisir une cible
# 4. Lancer Evil Twin
# 5. Capturer les credentials
```

### Scénario 2 : Audit de sécurité complet
```bash
# 1. Diagnostic automatique
sudo ./evil_twin_diagnostic.sh

# 2. Lancer l'application
sudo wifipumpkin3

# 3. Tester toutes les fonctionnalités
# 4. Générer un rapport
```

### Scénario 3 : Formation et apprentissage
```bash
# 1. Mode démonstration
sudo python3 run.py --demo

# 2. Tester les attaques
# 3. Analyser les résultats
# 4. Documenter les vulnérabilités
```

## 🚨 **Sécurité et Bonnes Pratiques**

### Règles de sécurité
```bash
# Toujours utiliser en mode root
sudo wifipumpkin3

# Tester uniquement sur votre propre réseau
# Respecter la législation locale
# Utiliser à des fins éducatives uniquement
```

### Nettoyage après utilisation
```bash
# Arrêter tous les services
sudo systemctl stop dnsmasq
sudo systemctl stop dhcpd

# Nettoyer les règles iptables
sudo iptables -F
sudo iptables -t nat -F

# Remettre l'interface en mode managed
sudo airmon-ng stop wlan0mon
```

## 🎯 **Dépannage**

### Problèmes courants
```bash
# Interface non détectée
sudo modprobe iwlwifi

# Mode monitor impossible
sudo systemctl stop NetworkManager
sudo airmon-ng start wlan0

# Conflit DHCP
sudo systemctl stop dhcpd
sudo systemctl stop dnsmasq
```

### Diagnostic automatique
```bash
# Lancer le diagnostic
sudo ./evil_twin_diagnostic.sh

# Suivre les instructions
# Résoudre les problèmes détectés
```

## 🏆 **Avantages Kali Linux**

1. **Performance maximale** - Tous les outils optimisés
2. **Sécurité renforcée** - Environnement isolé
3. **Compatibilité parfaite** - Drivers WiFi optimisés
4. **Outils intégrés** - Suite complète de pentest
5. **Support communautaire** - Large base d'utilisateurs

Votre WiFiPumpkin3 est maintenant **parfaitement configuré** pour Kali Linux ! 🎯 