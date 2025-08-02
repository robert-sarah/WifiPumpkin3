 # WiFiPumpkin3 - Clone avec PyQt5

Un clone complet de WiFiPumpkin3 développé avec PyQt5, organisé en plusieurs modules pour une meilleure maintenabilité.

## 🚀 Fonctionnalités

### Attaques WiFi
- **Evil Twin** : Création de points d'accès malveillants
- **Deauth Attack** : Attaques de déconnexion
- **Probe Request** : Sondage des réseaux WiFi
- **Captive Portal** : Portails captifs pour capturer des identifiants

### Interface Graphique
- Interface moderne avec PyQt5
- Onglets organisés par fonctionnalité
- Logs en temps réel
- Configuration avancée
- Statistiques détaillées

### Sécurité
- Vérification des privilèges administrateur
- Logs chiffrés optionnels
- Avertissements de sécurité
- Configuration sécurisée

## 📁 Structure du Projet

```
Pirate2025/
├── main.py                 # Point d'entrée principal
├── requirements.txt        # Dépendances Python
├── README.md              # Documentation
├── ui/                    # Interface utilisateur
│   ├── __init__.py
│   ├── main_window.py     # Fenêtre principale
│   └── tabs/             # Onglets de l'interface
│       ├── __init__.py
│       ├── evil_twin_tab.py
│       ├── deauth_tab.py
│       ├── probe_tab.py
│       ├── captive_portal_tab.py
│       ├── settings_tab.py
│       └── logs_tab.py
├── core/                  # Fonctionnalités principales
│   ├── __init__.py
│   ├── network_manager.py # Gestionnaire réseau
│   ├── logger.py          # Système de logging
│   └── attacks/          # Modules d'attaques
│       ├── __init__.py
│       ├── evil_twin.py
│       └── deauth_attack.py
├── utils/                 # Utilitaires
│   ├── __init__.py
│   └── config.py         # Gestionnaire de configuration
├── config/               # Fichiers de configuration
├── logs/                 # Fichiers de logs
└── assets/              # Ressources (icônes, etc.)
```

## 🛠️ Installation

### Prérequis
- Python 3.7+
- Privilèges administrateur
- Interface WiFi compatible

### Installation des dépendances
```bash
pip install -r requirements.txt
```

### Lancement
```bash
python main.py
```

## 🔧 Configuration

### Interface WiFi
- Sélection de l'interface par défaut
- Configuration du mode (Managed/Monitor)
- Paramètres DHCP personnalisables

### Sécurité
- Avertissements avant attaque
- Vérification des privilèges
- Chiffrement des logs optionnel

### Logs
- Niveau de log configurable
- Rotation automatique
- Export des logs

## 📊 Fonctionnalités Détaillées

### Evil Twin
- Création de points d'accès malveillants
- Envoi de paquets deauth
- Portail captif intégré
- Configuration avancée

### Deauth Attack
- Attaques de déconnexion ciblées
- Configuration du nombre de paquets
- Intervalle personnalisable
- Types d'attaque multiples

### Probe Request
- Sondage des réseaux WiFi
- Détection des clients
- Analyse du trafic
- Statistiques détaillées

### Captive Portal
- Pages de connexion personnalisables
- Capture d'identifiants
- Redirection configurable
- Monitoring des clients

## ⚠️ Avertissements

**⚠️ ATTENTION : Ce logiciel est destiné uniquement à des fins éducatives et de test de sécurité sur vos propres réseaux. L'utilisation de ce logiciel pour attaquer des réseaux sans autorisation est illégale.**

### Utilisation Responsable
- Testez uniquement vos propres réseaux
- Respectez la législation locale
- Obtenez les autorisations nécessaires
- Documentez vos tests

## 🔒 Sécurité

### Bonnes Pratiques
- Utilisez dans un environnement contrôlé
- Isolez les tests de production
- Documentez toutes les activités
- Respectez la vie privée

### Limitations
- Nécessite des privilèges administrateur
- Compatible Linux principalement
- Interface WiFi spécifique requise

## 🐛 Dépannage

### Problèmes Courants

#### Erreur de privilèges
```bash
sudo python main.py
```

#### Interface WiFi non détectée
```bash
iwconfig
```

#### Dépendances manquantes
```bash
pip install --upgrade -r requirements.txt
```

## 📝 Logs

### Niveaux de Log
- **DEBUG** : Informations détaillées
- **INFO** : Informations générales
- **WARNING** : Avertissements
- **ERROR** : Erreurs
- **CRITICAL** : Erreurs critiques

### Fichiers de Log
- `logs/wifipumpkin3_YYYYMMDD.log`
- Rotation automatique
- Export possible

## 🔄 Mises à Jour

### Vérification
- Vérification automatique des mises à jour
- Notifications intégrées
- Installation guidée

### Configuration
- Sauvegarde automatique
- Restauration possible
- Paramètres par défaut

## 📞 Support

### Documentation
- Interface intégrée
- Aide contextuelle
- Exemples d'utilisation

### Problèmes
- Logs détaillés
- Diagnostic automatique
- Support communautaire

## 📄 Licence

Ce projet est fourni à des fins éducatives uniquement. L'utilisation de ce logiciel pour des activités illégales n'est pas autorisée.

## 🤝 Contribution

### Développement
- Code modulaire
- Documentation complète
- Tests unitaires
- Standards de code

### Améliorations
- Nouvelles attaques
- Interface utilisateur
- Performance
- Sécurité

---

**⚠️ RAPPEL : Utilisez ce logiciel de manière responsable et éthique.**