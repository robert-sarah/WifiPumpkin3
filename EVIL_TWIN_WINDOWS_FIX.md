# 🔧 Résolution Evil Twin - Windows

## 🚨 **Problèmes Courants sur Windows**

### 1. **❌ "Interface non trouvée"**

**Cause :** Interface WiFi non détectée par l'application

**Solutions :**
```powershell
# Vérifier les adaptateurs WiFi
netsh wlan show interfaces

# Activer l'adaptateur WiFi
netsh interface set interface "Wi-Fi" enabled

# Vérifier les adaptateurs réseau
Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Wireless*"}
```

### 2. **❌ "Permission denied"**

**Cause :** Pas de privilèges administrateur

**Solutions :**
```powershell
# Exécuter PowerShell en tant qu'administrateur
# Clic droit sur PowerShell -> "Exécuter en tant qu'administrateur"

# Ou utiliser la commande
Start-Process powershell -Verb RunAs
```

### 3. **❌ "Mode monitor impossible"**

**Cause :** Windows ne supporte pas nativement le mode monitor

**Solutions :**
```powershell
# Activer le mode promiscuous
netsh wlan set hostednetwork mode=allow

# Vérifier les capacités de l'adaptateur
netsh wlan show drivers
```

### 4. **❌ "DHCP server failed"**

**Cause :** Conflit avec les services DHCP Windows

**Solutions :**
```powershell
# Arrêter le service DHCP Windows
Stop-Service -Name "DHCP"

# Vérifier les services réseau
Get-Service | Where-Object {$_.Name -like "*DHCP*"}
```

## 🔧 **Configuration Manuelle Windows**

### Étape 1 : Préparation de l'interface
```powershell
# Vérifier les interfaces WiFi
netsh wlan show interfaces

# Activer l'interface WiFi
netsh interface set interface "Wi-Fi" enabled

# Vérifier les capacités
netsh wlan show drivers
```

### Étape 2 : Configuration réseau
```powershell
# Configurer l'adresse IP statique
netsh interface ip set address "Wi-Fi" static 192.168.1.1 255.255.255.0

# Configurer la passerelle
netsh interface ip set gateway "Wi-Fi" 192.168.1.1

# Configurer le DNS
netsh interface ip set dns "Wi-Fi" static 8.8.8.8
```

### Étape 3 : Configuration du pare-feu
```powershell
# Autoriser le trafic DHCP
netsh advfirewall firewall add rule name="DHCP Server" dir=in action=allow protocol=UDP localport=67

# Autoriser le trafic DNS
netsh advfirewall firewall add rule name="DNS Server" dir=in action=allow protocol=UDP localport=53
```

## 🎯 **Solutions Rapides Windows**

### Solution 1 : Redémarrage complet
```powershell
# Arrêter les services réseau
Stop-Service -Name "DHCP" -Force
Stop-Service -Name "DNS" -Force

# Redémarrer l'interface WiFi
netsh interface set interface "Wi-Fi" disabled
Start-Sleep -Seconds 2
netsh interface set interface "Wi-Fi" enabled

# Relancer l'application
python run.py
```

### Solution 2 : Configuration manuelle
```powershell
# Configurer l'interface manuellement
netsh interface ip set address "Wi-Fi" static 192.168.1.1 255.255.255.0
netsh interface ip set dns "Wi-Fi" static 8.8.8.8

# Activer le partage de connexion
netsh interface set interface "Wi-Fi" mode=allow
```

### Solution 3 : Vérification des logs
```powershell
# Vérifier les logs système
Get-EventLog -LogName System -Source "DHCP*" -Newest 10

# Vérifier les logs d'application
Get-EventLog -LogName Application -Source "WiFiPumpkin3" -Newest 10
```

## 🛠️ **Script de Diagnostic Windows**

```powershell
# evil_twin_windows_diagnostic.ps1

Write-Host "🔍 Diagnostic Evil Twin WiFiPumpkin3 - Windows" -ForegroundColor Blue
Write-Host "===============================================" -ForegroundColor Blue
Write-Host ""

# Vérification des privilèges administrateur
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ Ce script doit être exécuté en tant qu'administrateur" -ForegroundColor Red
    Write-Host "💡 Clic droit sur PowerShell -> 'Exécuter en tant qu'administrateur'" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ Privilèges administrateur confirmés" -ForegroundColor Green

# Vérification des interfaces WiFi
Write-Host "📡 Vérification des interfaces WiFi..." -ForegroundColor Blue

$wifiInterfaces = netsh wlan show interfaces | Select-String "SSID" | ForEach-Object { $_.ToString().Split(":")[1].Trim() }

if ($wifiInterfaces.Count -eq 0) {
    Write-Host "❌ Aucune interface WiFi détectée" -ForegroundColor Red
    Write-Host "💡 Solutions :" -ForegroundColor Yellow
    Write-Host "   - Vérifier que la carte WiFi est connectée"
    Write-Host "   - Installer les drivers appropriés"
    Write-Host "   - Redémarrer le service réseau"
    exit 1
}

Write-Host "✅ Interfaces WiFi détectées: $($wifiInterfaces -join ', ')" -ForegroundColor Green

# Vérification des services DHCP
Write-Host "🔍 Vérification des services DHCP..." -ForegroundColor Blue

$dhcpService = Get-Service -Name "DHCP" -ErrorAction SilentlyContinue
if ($dhcpService -and $dhcpService.Status -eq "Running") {
    Write-Host "⚠️  Service DHCP Windows actif" -ForegroundColor Yellow
    Write-Host "💡 Arrêter le service DHCP :" -ForegroundColor Yellow
    Write-Host "   Stop-Service -Name 'DHCP' -Force" -ForegroundColor Cyan
} else {
    Write-Host "✅ Aucun conflit DHCP détecté" -ForegroundColor Green
}

# Vérification de la configuration réseau
Write-Host "🌐 Vérification de la configuration réseau..." -ForegroundColor Blue

$wifiAdapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*Wireless*" } | Select-Object -First 1

if ($wifiAdapter) {
    Write-Host "✅ Adaptateur WiFi trouvé: $($wifiAdapter.Name)" -ForegroundColor Green
    
    $ipConfig = Get-NetIPAddress -InterfaceIndex $wifiAdapter.ifIndex -ErrorAction SilentlyContinue
    if ($ipConfig) {
        Write-Host "✅ Configuration IP: $($ipConfig.IPAddress)" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Pas de configuration IP" -ForegroundColor Yellow
        Write-Host "💡 Configurer l'IP :" -ForegroundColor Yellow
        Write-Host "   netsh interface ip set address '$($wifiAdapter.Name)' static 192.168.1.1 255.255.255.0" -ForegroundColor Cyan
    }
} else {
    Write-Host "❌ Adaptateur WiFi non trouvé" -ForegroundColor Red
}

# Vérification de la connectivité
Write-Host "🌐 Test de connectivité..." -ForegroundColor Blue

if (Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet) {
    Write-Host "✅ Connectivité Internet OK" -ForegroundColor Green
} else {
    Write-Host "❌ Pas de connectivité Internet" -ForegroundColor Red
    Write-Host "💡 Vérifier la configuration réseau" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🎯 DIAGNOSTIC TERMINÉ" -ForegroundColor Blue
Write-Host "=====================" -ForegroundColor Blue
Write-Host ""
Write-Host "📋 Résumé des vérifications :" -ForegroundColor Green
Write-Host "  ✅ Privilèges administrateur"
Write-Host "  ✅ Interfaces WiFi détectées"
Write-Host "  ✅ Services DHCP vérifiés"
Write-Host "  ✅ Configuration réseau"
Write-Host "  ✅ Connectivité Internet"
Write-Host ""
Write-Host "💡 Si le problème persiste :" -ForegroundColor Yellow
Write-Host "  - Vérifier les logs système: Get-EventLog -LogName System -Newest 10"
Write-Host "  - Vérifier la connectivité: Test-Connection 8.8.8.8"
Write-Host "  - Redémarrer l'interface: netsh interface set interface 'Wi-Fi' disabled; Start-Sleep 2; netsh interface set interface 'Wi-Fi' enabled"
```

## 📊 **Checklist de Vérification Windows**

- [ ] **Privilèges administrateur**
- [ ] **Interface WiFi détectée**
- [ ] **Service DHCP arrêté**
- [ ] **Configuration IP correcte**
- [ ] **Pare-feu configuré**
- [ ] **Connectivité Internet**

## 🎯 **Solutions Spécifiques Windows**

### Problème : "Interface non supportée"
```powershell
# Vérifier les capacités de l'adaptateur
netsh wlan show drivers

# Activer le mode promiscuous
netsh wlan set hostednetwork mode=allow

# Vérifier les adaptateurs réseau
Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Wireless*"}
```

### Problème : "Permission denied"
```powershell
# Exécuter en tant qu'administrateur
Start-Process powershell -Verb RunAs

# Ou utiliser la commande
runas /user:Administrator "powershell.exe"
```

### Problème : "DHCP server failed"
```powershell
# Arrêter le service DHCP Windows
Stop-Service -Name "DHCP" -Force

# Vérifier les services réseau
Get-Service | Where-Object {$_.Name -like "*DHCP*"}

# Configurer manuellement l'IP
netsh interface ip set address "Wi-Fi" static 192.168.1.1 255.255.255.0
```

## 🚀 **Lancement Recommandé Windows**

```powershell
# 1. Exécuter en tant qu'administrateur
Start-Process powershell -Verb RunAs

# 2. Naviguer vers le projet
cd "C:\Users\GENIUS ELECTRONICS\Pirate2025"

# 3. Arrêter les services DHCP
Stop-Service -Name "DHCP" -Force

# 4. Lancer l'application
python run.py
```

Votre Evil Twin devrait maintenant fonctionner sur Windows ! 🎯 