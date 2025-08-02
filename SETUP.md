 # Guide de Configuration WiFiPumpkin3

## 🚀 Installation Rapide

### 1. Prérequis
```bash
# Système Linux recommandé
sudo apt update
sudo apt install python3 python3-pip

# Outils WiFi
sudo apt install aircrack-ng iwconfig iwlist
```

### 2. Installation
```bash
# Cloner le projet
git clone <repository>
cd Pirate2025

# Installer les dépendances
pip install -r requirements.txt

# Lancer l'installation
python install.py
```

### 3. Lancement
```bash
# Avec privilèges administrateur
sudo python main.py

# Ou utiliser le script de lancement
sudo python run.py
```

## 📁 Structure Complète

```
Pirate2025/
├── main.py                    # Point d'entrée principal
├── run.py                     # Script de lancement
├── install.py                 # Script d'installation
├── test_demo.py              # Tests de démonstration
├── requirements.txt           # Dépendances Python
├── README.md                 # Documentation principale
├── SETUP.md                  # Ce guide
├── ui/                       # Interface utilisateur
│   ├── main_window.py        # Fenêtre principale
│   └── tabs/                 # Onglets
│       ├── evil_twin_tab.py
│       ├── deauth_tab.py
│       ├── probe_tab.py
│       ├── captive_portal_tab.py
│       ├── settings_tab.py
│       └── logs_tab.py
├── core/                     # Fonctionnalités principales
│   ├── network_manager.py    # Gestionnaire réseau
│   ├── logger.py            # Système de logging
│   └── attacks/             # Modules d'attaques
│       ├── evil_twin.py
│       └── deauth_attack.py
├── utils/                    # Utilitaires
│   └── config.py            # Gestionnaire de configuration
├── tests/                    # Tests unitaires
│   ├── test_core.py
│   ├── test_integration.py
│   ├── test_performance.py
│   └── test_security.py
├── config/                   # Fichiers de configuration
├── logs/                     # Fichiers de logs
└── assets/                   # Ressources
```

## 🔧 Configuration

### Interface WiFi
- Sélection automatique de l'interface
- Mode Monitor/Managed
- Configuration des canaux

### Sécurité
- Vérification des privilèges
- Avertissements avant attaque
- Logs sécurisés

### Logs
- Niveaux configurables
- Rotation automatique
- Export possible

## 🧪 Tests

### Tests Unitaires
```bash
python -m unittest tests/test_core.py
```

### Tests d'Intégration
```bash
python tests/test_integration.py
```

### Tests de Performance
```bash
python tests/test_performance.py
```

### Tests de Sécurité
```bash
python tests/test_security.py
```

### Tests de Démo
```bash
python test_demo.py
```

## 🚨 Dépannage

### Erreurs Courantes

#### Privilèges insuffisants
```bash
sudo python main.py
```

#### Interface WiFi non détectée
```bash
iwconfig
lsusb | grep -i wireless
```

#### Dépendances manquantes
```bash
pip install --upgrade -r requirements.txt
```

#### Erreur PyQt5
```bash
sudo apt install python3-pyqt5
```

## 📊 Fonctionnalités

### Evil Twin
- Création de points d'accès malveillants
- Envoi de paquets deauth
- Portail captif intégré

### Deauth Attack
- Attaques de déconnexion
- Configuration du nombre de paquets
- Types d'attaque multiples

### Probe Request
- Sondage des réseaux WiFi
- Détection des clients
- Analyse du trafic

### Captive Portal
- Pages de connexion personnalisables
- Capture d'identifiants
- Monitoring des clients

## 🔒 Sécurité

### Bonnes Pratiques
- Testez uniquement vos propres réseaux
- Documentez toutes les activités
- Respectez la législation locale
- Obtenez les autorisations nécessaires

### Limitations
- Nécessite des privilèges administrateur
- Compatible Linux principalement
- Interface WiFi spécifique requise

## 📝 Logs

### Niveaux
- DEBUG : Informations détaillées
- INFO : Informations générales
- WARNING : Avertissements
- ERROR : Erreurs
- CRITICAL : Erreurs critiques

### Fichiers
- `logs/wifipumpkin3_YYYYMMDD.log`
- Rotation automatique
- Export possible

## ⚙️ Configuration Avancée

### Fichier de Configuration
```ini
[General]
theme = Clair
language = Français
font_size = 10

[Network]
default_interface = wlan0
default_mode = Managed

[Security]
warn_before_attack = True
check_privileges = True

[Logs]
log_level = INFO
log_folder = ./logs
```

### Variables d'Environnement
```bash
export WIFIPUMPKIN3_CONFIG_DIR=/path/to/config
export WIFIPUMPKIN3_LOG_DIR=/path/to/logs
```

## 🎯 Utilisation

### Démarrage Rapide
1. Lancez l'application avec `sudo python main.py`
2. Sélectionnez l'onglet "Evil Twin"
3. Scannez les réseaux disponibles
4. Sélectionnez un réseau cible
5. Configurez les paramètres d'attaque
6. Lancez l'attaque

### Configuration Détaillée
1. Allez dans l'onglet "Paramètres"
2. Configurez l'interface réseau
3. Ajustez les paramètres de sécurité
4. Configurez les logs
5. Sauvegardez la configuration

## 📞 Support

### Documentation
- Interface intégrée avec aide
- Exemples d'utilisation
- Guides détaillés

### Problèmes
- Logs détaillés pour diagnostic
- Tests automatiques
- Support communautaire

---

**⚠️ RAPPEL : Utilisez ce logiciel de manière responsable et éthique.**