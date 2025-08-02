# 🔍 Diagnostic Evil Twin - WiFiPumpkin3

## 🚨 **Problèmes Courants et Solutions**

### 1. **❌ Erreur : "Interface non trouvée"**

**Cause :** Interface WiFi non détectée ou non configurée

**Solutions :**
```bash
# Vérifier les interfaces disponibles
iwconfig

# Lister toutes les interfaces
ip link show

# Activer l'interface si nécessaire
sudo ip link set wlan0 up

# Vérifier le mode de l'interface
iwconfig wlan0
```

### 2. **❌ Erreur : "Permission denied"**

**Cause :** Pas de privilèges root

**Solutions :**
```bash
# Sur Windows - Exécuter en tant qu'administrateur
# Clic droit sur PowerShell -> "Exécuter en tant qu'administrateur"

# Sur Kali Linux
sudo python3 run.py
```

### 3. **❌ Erreur : "Mode monitor impossible"**

**Cause :** Interface en mode managed ou driver incompatible

**Solutions :**
```bash
# Arrêter NetworkManager
sudo systemctl stop NetworkManager

# Activer le mode monitor
sudo airmon-ng start wlan0

# Vérifier le nouveau nom d'interface
iwconfig
```

### 4. **❌ Erreur : "DHCP server failed"**

**Cause :** Conflit avec d'autres services DHCP

**Solutions :**
```bash
# Arrêter les services DHCP existants
sudo systemctl stop dhcpd
sudo systemctl stop dnsmasq

# Vérifier qu'aucun service n'utilise le port 67
sudo netstat -tulpn | grep :67
```

### 5. **❌ Erreur : "No clients connecting"**

**Cause :** Configuration réseau incorrecte

**Solutions :**
```bash
# Vérifier la configuration IP
sudo ip addr show wlan0

# Configurer l'interface manuellement
sudo ip addr add 192.168.1.1/24 dev wlan0
sudo ip link set wlan0 up

# Vérifier les routes
sudo ip route show
```

## 🔧 **Configuration Manuelle**

### Étape 1 : Préparation de l'interface
```bash
# Arrêter tous les services réseau
sudo systemctl stop NetworkManager
sudo systemctl stop wpa_supplicant

# Activer le mode monitor
sudo airmon-ng start wlan0

# Vérifier l'interface monitor
iwconfig wlan0mon
```

### Étape 2 : Configuration réseau
```bash
# Configurer l'interface
sudo ip addr add 192.168.1.1/24 dev wlan0mon
sudo ip link set wlan0mon up

# Configurer les routes
sudo ip route add 192.168.1.0/24 dev wlan0mon

# Activer le forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

### Étape 3 : Configuration DHCP/DNS
```bash
# Créer la configuration dnsmasq
cat > /tmp/dnsmasq.conf << EOF
interface=wlan0mon
dhcp-range=192.168.1.100,192.168.1.200,255.255.255.0,24h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
EOF

# Démarrer dnsmasq
sudo dnsmasq -C /tmp/dnsmasq.conf
```

### Étape 4 : Configuration iptables
```bash
# Nettoyer les règles existantes
sudo iptables -F
sudo iptables -t nat -F

# Configurer NAT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i wlan0mon -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o wlan0mon -m state --state RELATED,ESTABLISHED -j ACCEPT
```

## 🎯 **Test de Fonctionnement**

### Test 1 : Vérification de l'interface
```bash
# Vérifier que l'interface est en mode monitor
iwconfig wlan0mon

# Vérifier l'adresse IP
ip addr show wlan0mon

# Vérifier les routes
ip route show
```

### Test 2 : Test DHCP
```bash
# Vérifier que dnsmasq fonctionne
sudo netstat -tulpn | grep :67

# Tester le DHCP
sudo dhclient -r wlan0mon
sudo dhclient wlan0mon
```

### Test 3 : Test de connectivité
```bash
# Tester la connectivité
ping -c 3 8.8.8.8

# Vérifier les logs
sudo tail -f /var/log/dnsmasq.log
```

## 🛠️ **Script de Diagnostic Automatique**

```bash
#!/bin/bash
# evil_twin_diagnostic.sh

echo "🔍 Diagnostic Evil Twin WiFiPumpkin3"
echo "===================================="

# Vérification des privilèges
if [ "$EUID" -ne 0 ]; then
    echo "❌ Ce script doit être exécuté en tant que root"
    exit 1
fi

echo "✅ Privilèges root confirmés"

# Vérification des interfaces WiFi
echo "📡 Vérification des interfaces WiFi..."
INTERFACES=$(iwconfig 2>/dev/null | grep -o '^[^ ]*' | head -1)

if [ -z "$INTERFACES" ]; then
    echo "❌ Aucune interface WiFi détectée"
    echo "💡 Solutions :"
    echo "   - Vérifier que la carte WiFi est connectée"
    echo "   - Installer les drivers appropriés"
    echo "   - Vérifier que le module WiFi est chargé"
    exit 1
fi

echo "✅ Interface WiFi détectée: $INTERFACES"

# Vérification du mode monitor
echo "🔧 Vérification du mode monitor..."
if iwconfig $INTERFACES 2>/dev/null | grep -q "Mode:Monitor"; then
    echo "✅ Interface en mode monitor"
else
    echo "⚠️  Interface pas en mode monitor"
    echo "💡 Activer le mode monitor :"
    echo "   sudo airmon-ng start $INTERFACES"
fi

# Vérification des services
echo "🔍 Vérification des services..."
if systemctl is-active --quiet NetworkManager; then
    echo "⚠️  NetworkManager est actif (peut interférer)"
    echo "💡 Arrêter NetworkManager :"
    echo "   sudo systemctl stop NetworkManager"
fi

# Vérification des ports
echo "🔌 Vérification des ports..."
if netstat -tulpn 2>/dev/null | grep -q ":67"; then
    echo "⚠️  Port 67 (DHCP) déjà utilisé"
    echo "💡 Arrêter les services DHCP :"
    echo "   sudo systemctl stop dhcpd"
    echo "   sudo systemctl stop dnsmasq"
fi

# Vérification de la connectivité
echo "🌐 Test de connectivité..."
if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    echo "✅ Connectivité Internet OK"
else
    echo "❌ Pas de connectivité Internet"
    echo "💡 Vérifier la configuration réseau"
fi

echo ""
echo "🎯 Diagnostic terminé"
echo "📋 Consultez les solutions ci-dessus pour résoudre les problèmes"
```

## 🚨 **Problèmes Spécifiques Windows**

### Problème : "Interface non supportée"
**Solution :**
```powershell
# Vérifier les adaptateurs WiFi
netsh wlan show interfaces

# Activer le mode promiscuous
netsh wlan set hostednetwork mode=allow
```

### Problème : "Permission denied"
**Solution :**
```powershell
# Exécuter PowerShell en tant qu'administrateur
# Clic droit -> "Exécuter en tant qu'administrateur"
```

## 📊 **Checklist de Vérification**

- [ ] **Privilèges root/administrateur**
- [ ] **Interface WiFi détectée**
- [ ] **Mode monitor activé**
- [ ] **Services DHCP arrêtés**
- [ ] **Configuration IP correcte**
- [ ] **Routes configurées**
- [ ] **NAT activé**
- [ ] **Connectivité Internet**

## 🎯 **Solutions Rapides**

### Solution 1 : Redémarrage complet
```bash
sudo systemctl stop NetworkManager
sudo airmon-ng start wlan0
sudo python3 run.py
```

### Solution 2 : Configuration manuelle
```bash
sudo ip addr add 192.168.1.1/24 dev wlan0mon
sudo dnsmasq -i wlan0mon -F 192.168.1.100,192.168.1.200
```

### Solution 3 : Vérification des logs
```bash
# Vérifier les logs dnsmasq
sudo tail -f /var/log/dnsmasq.log

# Vérifier les logs système
sudo journalctl -f
```

Votre Evil Twin devrait maintenant fonctionner correctement ! 🎯 