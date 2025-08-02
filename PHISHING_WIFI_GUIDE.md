# 🎣 Guide - Fichier de Phishing WiFi Professionnel

## 🎯 **Vue d'Ensemble**

Le fichier `templates/phishing_wifi.html` est un template de phishing WiFi professionnel conçu pour capturer les identifiants des utilisateurs en imitant une page de connexion WiFi légitime.

## ✨ **Caractéristiques du Phishing**

### **Design Professionnel**
- **Interface moderne** avec gradients et animations
- **Responsive design** adapté mobile et desktop
- **Animations fluides** pour une expérience réaliste
- **Icônes et badges** de sécurité pour la crédibilité

### **Fonctionnalités Avancées**
- **Validation en temps réel** des champs
- **Toggle de visibilité** du mot de passe
- **Simulation de connexion** avec spinner
- **Messages d'erreur/succès** dynamiques
- **Auto-focus** sur le premier champ

### **Éléments de Crédibilité**
- **Badge de sécurité** SSL/TLS
- **Nom de réseau** réaliste (WiFi_Secure_Network)
- **Statut WPA2** pour la légitimité
- **Messages de sécurité** rassurants

## 🔧 **Utilisation**

### **1. Intégration dans WiFiPumpkin3**
```bash
# Copier le fichier dans le projet
cp templates/phishing_wifi.html /chemin/vers/projet/templates/

# Utiliser via l'interface
# 1. Onglet "Captive Portal"
# 2. Cocher "Utiliser un fichier HTML personnalisé"
# 3. Sélectionner "phishing_wifi.html"
# 4. Démarrer le portail captif
```

### **2. Configuration du Portail**
```
☑️ Utiliser un fichier HTML personnalisé
📁 Fichier HTML: [Parcourir] templates/phishing_wifi.html
🌐 Port: 80 (ou 443 pour HTTPS)
🔒 SSL: Activé (recommandé)
```

## 🎨 **Éléments Visuels**

### **Design Principal**
- **Gradient de fond** : Bleu-violet professionnel
- **Container blanc** avec ombres et bordures arrondies
- **Barre animée** en haut avec effet shimmer
- **Icône WiFi** pulsante avec emoji 📶

### **Formulaires**
- **Champs stylisés** avec transitions fluides
- **Validation visuelle** : vert pour valide, rouge pour invalide
- **Bouton de connexion** avec effets hover et animations
- **Toggle password** avec icônes 👁️/🙈

### **Messages et Feedback**
- **Loading spinner** pendant la "connexion"
- **Messages d'erreur** en rouge
- **Messages de succès** en vert
- **Info de sécurité** avec badge 🔒

## 📱 **Responsive Design**

### **Desktop (> 480px)**
- Container de 450px de largeur
- Padding de 40px
- Icône WiFi de 80px
- Typographie optimisée

### **Mobile (≤ 480px)**
- Container adaptatif avec marges
- Padding réduit à 30px/20px
- Icône WiFi de 60px
- Police ajustée

## 🔍 **Champs Capturés**

### **Champs Requis**
```html
<input name="username" required>  <!-- Nom d'utilisateur -->
<input name="password" required>  <!-- Mot de passe -->
```

### **Champs Optionnels**
```html
<input name="email" type="email">  <!-- Email -->
```

### **Données Capturées**
```json
{
  "username": "john_doe",
  "password": "secret123",
  "email": "john@example.com"
}
```

## 🛡️ **Techniques de Crédibilité**

### **1. Apparence Légitime**
- **Design professionnel** similaire aux vrais portails
- **Couleurs et typographie** standards
- **Animations subtiles** pour la modernité

### **2. Messages de Sécurité**
- **Badge SSL/TLS** pour rassurer
- **Texte de sécurité** : "Connexion sécurisée"
- **Informations confidentielles** mentionnées

### **3. Comportement Réaliste**
- **Validation en temps réel** des champs
- **Simulation de connexion** avec délai
- **Messages d'erreur** crédibles
- **Redirection** après "succès"

### **4. Détails Techniques**
- **Nom de réseau** : WiFi_Secure_Network
- **Type de sécurité** : WPA2
- **Statut** : 🔒 Réseau sécurisé
- **Autocomplete** activé pour les champs

## 🎭 **Scénarios d'Utilisation**

### **1. Evil Twin Attack**
```bash
# Configuration
1. Créer un réseau WiFi "WiFi_Secure_Network"
2. Rediriger tout le trafic vers le portail
3. Utiliser phishing_wifi.html comme page de connexion
4. Capturer les identifiants soumis
```

### **2. Captive Portal**
```bash
# Configuration
1. Démarrer le serveur de portail captif
2. Charger phishing_wifi.html
3. Intercepter les connexions HTTP
4. Rediriger vers la page de phishing
```

### **3. Man-in-the-Middle**
```bash
# Configuration
1. Positionner entre la victime et le routeur
2. Intercepter les requêtes DNS
3. Rediriger vers le serveur de phishing
4. Capturer les identifiants
```

## 🔧 **Personnalisation**

### **Modifier le Nom de Réseau**
```html
<!-- Ligne 189 -->
<div class="network-name">VOTRE_NOM_RESEAU</div>
```

### **Changer les Couleurs**
```css
/* Ligne 15 */
background: linear-gradient(135deg, #VOTRE_COULEUR1, #VOTRE_COULEUR2);
```

### **Ajouter des Champs**
```html
<!-- Après ligne 200 -->
<div class="form-group">
    <label for="phone">Téléphone</label>
    <input type="tel" id="phone" name="phone" placeholder="Votre téléphone">
</div>
```

### **Modifier les Messages**
```html
<!-- Ligne 185 -->
<p class="subtitle">VOTRE_MESSAGE_PERSONNALISE</p>
```

## 📊 **Métadonnées Capturées**

### **Automatiques**
```json
{
  "timestamp": "2024-01-15T10:30:00",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "template_used": "phishing_wifi",
  "form_data": {
    "username": "victim_user",
    "password": "victim_password",
    "email": "victim@email.com"
  }
}
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

## 🎯 **Techniques Avancées**

### **1. Détection d'Environnement**
```javascript
// Détecter si c'est un vrai navigateur
if (navigator.userAgent.includes('Headless')) {
    // Comportement différent pour les bots
}
```

### **2. Validation Côté Client**
```javascript
// Validation en temps réel
function validateField(field, isValid) {
    if (isValid) {
        field.style.borderColor = '#27ae60';
    } else {
        field.style.borderColor = '#e74c3c';
    }
}
```

### **3. Simulation de Connexion**
```javascript
// Simuler une connexion réaliste
setTimeout(() => {
    showSuccess();
    setTimeout(() => {
        form.submit();
    }, 2000);
}, 1500);
```

## 📈 **Monitoring et Logs**

### **Logs Automatiques**
```
INFO: Page de phishing chargée
INFO: Formulaire soumis par 192.168.1.100
INFO: Identifiants capturés: username=victim, password=****
SUCCESS: Redirection vers https://www.google.com
```

### **Fichier de Capture**
```json
[
  {
    "timestamp": "2024-01-15T10:30:00",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "form_data": {
      "username": "victim_user",
      "password": "victim_password",
      "email": "victim@email.com"
    },
    "template_used": "phishing_wifi"
  }
]
```

## 🎉 **Avantages du Template**

### **Professionnalisme**
- **Design moderne** et crédible
- **Animations fluides** pour la légitimité
- **Responsive** pour tous les appareils
- **Validation** en temps réel

### **Fonctionnalité**
- **Capture complète** des données
- **Simulation réaliste** de connexion
- **Messages dynamiques** d'erreur/succès
- **Auto-focus** pour l'UX

### **Sécurité**
- **Badges SSL** pour la crédibilité
- **Messages de sécurité** rassurants
- **Validation** côté client
- **Redirection** après capture

---

**🎯 Ce template de phishing WiFi offre une expérience utilisateur réaliste et professionnelle pour les tests de sécurité autorisés !** 