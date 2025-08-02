#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dashboard Temps Réel
Surveillance et statistiques en direct
"""

import time
import json
import threading
from datetime import datetime
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QPushButton, QTextEdit, QProgressBar,
                             QGroupBox, QTableWidget, QTableWidgetItem)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor
import os

class Dashboard(QWidget):
    """Dashboard temps réel pour WiFiPumpkin3"""
    
    # Signaux pour mise à jour
    update_stats = pyqtSignal(dict)
    update_networks = pyqtSignal(list)
    update_clients = pyqtSignal(list)
    update_credentials = pyqtSignal(list)
    
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.stats = {
            'networks_found': 0,
            'clients_connected': 0,
            'credentials_captured': 0,
            'attacks_active': 0,
            'traffic_mb': 0.0
        }
        
        self.setup_ui()
        self.setup_timer()
        
    def setup_ui(self):
        """Configuration de l'interface"""
        layout = QVBoxLayout(self)
        
        # Titre
        title = QLabel("📊 Dashboard WiFiPumpkin3")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Section des statistiques
        self.setup_stats_section(layout)
        
        # Section des réseaux
        self.setup_networks_section(layout)
        
        # Section des clients
        self.setup_clients_section(layout)
        
        # Section des identifiants
        self.setup_credentials_section(layout)
        
        # Section des logs temps réel
        self.setup_logs_section(layout)
        
    def setup_stats_section(self, layout):
        """Section des statistiques"""
        stats_group = QGroupBox("📈 Statistiques en Temps Réel")
        stats_layout = QGridLayout(stats_group)
        
        # Réseaux trouvés
        stats_layout.addWidget(QLabel("Réseaux trouvés:"), 0, 0)
        self.networks_label = QLabel("0")
        self.networks_label.setFont(QFont("Arial", 12, QFont.Bold))
        self.networks_label.setStyleSheet("color: #3498db;")
        stats_layout.addWidget(self.networks_label, 0, 1)
        
        # Clients connectés
        stats_layout.addWidget(QLabel("Clients connectés:"), 0, 2)
        self.clients_label = QLabel("0")
        self.clients_label.setFont(QFont("Arial", 12, QFont.Bold))
        self.clients_label.setStyleSheet("color: #e74c3c;")
        stats_layout.addWidget(self.clients_label, 0, 3)
        
        # Identifiants capturés
        stats_layout.addWidget(QLabel("Identifiants capturés:"), 1, 0)
        self.credentials_label = QLabel("0")
        self.credentials_label.setFont(QFont("Arial", 12, QFont.Bold))
        self.credentials_label.setStyleSheet("color: #27ae60;")
        stats_layout.addWidget(self.credentials_label, 1, 1)
        
        # Attaques actives
        stats_layout.addWidget(QLabel("Attaques actives:"), 1, 2)
        self.attacks_label = QLabel("0")
        self.attacks_label.setFont(QFont("Arial", 12, QFont.Bold))
        self.attacks_label.setStyleSheet("color: #f39c12;")
        stats_layout.addWidget(self.attacks_label, 1, 3)
        
        # Trafic
        stats_layout.addWidget(QLabel("Trafic (MB):"), 2, 0)
        self.traffic_label = QLabel("0.0")
        self.traffic_label.setFont(QFont("Arial", 12, QFont.Bold))
        self.traffic_label.setStyleSheet("color: #9b59b6;")
        stats_layout.addWidget(self.traffic_label, 2, 1)
        
        # Barre de progression du trafic
        self.traffic_progress = QProgressBar()
        self.traffic_progress.setMaximum(100)
        stats_layout.addWidget(self.traffic_progress, 2, 2, 1, 2)
        
        layout.addWidget(stats_group)
        
    def setup_networks_section(self, layout):
        """Section des réseaux"""
        networks_group = QGroupBox("📡 Réseaux Détectés")
        networks_layout = QVBoxLayout(networks_group)
        
        # Tableau des réseaux
        self.networks_table = QTableWidget()
        self.networks_table.setColumnCount(5)
        self.networks_table.setHorizontalHeaderLabels([
            "SSID", "BSSID", "Canal", "Signal", "Chiffrement"
        ])
        self.networks_table.setMaximumHeight(150)
        
        networks_layout.addWidget(self.networks_table)
        
        layout.addWidget(networks_group)
        
    def setup_clients_section(self, layout):
        """Section des clients"""
        clients_group = QGroupBox("👥 Clients Connectés")
        clients_layout = QVBoxLayout(clients_group)
        
        # Tableau des clients
        self.clients_table = QTableWidget()
        self.clients_table.setColumnCount(4)
        self.clients_table.setHorizontalHeaderLabels([
            "MAC", "IP", "Nom d'hôte", "Temps connecté"
        ])
        self.clients_table.setMaximumHeight(120)
        
        clients_layout.addWidget(self.clients_table)
        
        layout.addWidget(clients_group)
        
    def setup_credentials_section(self, layout):
        """Section des identifiants"""
        credentials_group = QGroupBox("🔐 Identifiants Capturés")
        credentials_layout = QVBoxLayout(credentials_group)
        
        # Tableau des identifiants
        self.credentials_table = QTableWidget()
        self.credentials_table.setColumnCount(4)
        self.credentials_table.setHorizontalHeaderLabels([
            "Timestamp", "IP", "Template", "Données"
        ])
        self.credentials_table.setMaximumHeight(120)
        
        credentials_layout.addWidget(self.credentials_table)
        
        layout.addWidget(credentials_group)
        
    def setup_logs_section(self, layout):
        """Section des logs"""
        logs_group = QGroupBox("📝 Logs Temps Réel")
        logs_layout = QVBoxLayout(logs_group)
        
        # Zone de logs
        self.logs_text = QTextEdit()
        self.logs_text.setMaximumHeight(150)
        self.logs_text.setReadOnly(True)
        self.logs_text.setFont(QFont("Courier", 9))
        
        # Configuration des couleurs
        palette = self.logs_text.palette()
        palette.setColor(QPalette.Base, QColor("#2c3e50"))
        palette.setColor(QPalette.Text, QColor("#ecf0f1"))
        self.logs_text.setPalette(palette)
        
        logs_layout.addWidget(self.logs_text)
        
        layout.addWidget(logs_group)
        
    def setup_timer(self):
        """Configure le timer pour les mises à jour"""
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_dashboard)
        self.timer.start(1000)  # Mise à jour toutes les secondes
        
        # Connexion des signaux
        self.update_stats.connect(self.update_stats_display)
        self.update_networks.connect(self.update_networks_display)
        self.update_clients.connect(self.update_clients_display)
        self.update_credentials.connect(self.update_credentials_display)
        
    def update_dashboard(self):
        """Mise à jour du dashboard"""
        try:
            # Mise à jour des statistiques
            self.update_stats.emit(self.stats)
            
            # Mise à jour des réseaux
            networks = self.get_networks()
            self.update_networks.emit(networks)
            
            # Mise à jour des clients
            clients = self.get_clients()
            self.update_clients.emit(clients)
            
            # Mise à jour des identifiants
            credentials = self.get_credentials()
            self.update_credentials.emit(credentials)
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur mise à jour dashboard: {str(e)}")
    
    def update_stats_display(self, stats):
        """Met à jour l'affichage des statistiques"""
        self.networks_label.setText(str(stats['networks_found']))
        self.clients_label.setText(str(stats['clients_connected']))
        self.credentials_label.setText(str(stats['credentials_captured']))
        self.attacks_label.setText(str(stats['attacks_active']))
        self.traffic_label.setText(f"{stats['traffic_mb']:.1f}")
        
        # Mise à jour de la barre de progression
        progress = min(int(stats['traffic_mb'] * 10), 100)
        self.traffic_progress.setValue(progress)
    
    def update_networks_display(self, networks):
        """Met à jour l'affichage des réseaux"""
        self.networks_table.setRowCount(len(networks))
        
        for i, network in enumerate(networks):
            self.networks_table.setItem(i, 0, QTableWidgetItem(network.get('ssid', '')))
            self.networks_table.setItem(i, 1, QTableWidgetItem(network.get('bssid', '')))
            self.networks_table.setItem(i, 2, QTableWidgetItem(str(network.get('channel', ''))))
            self.networks_table.setItem(i, 3, QTableWidgetItem(f"{network.get('signal', '')} dBm"))
            self.networks_table.setItem(i, 4, QTableWidgetItem(network.get('encryption', '')))
    
    def update_clients_display(self, clients):
        """Met à jour l'affichage des clients"""
        self.clients_table.setRowCount(len(clients))
        
        for i, client in enumerate(clients):
            self.clients_table.setItem(i, 0, QTableWidgetItem(client.get('mac', '')))
            self.clients_table.setItem(i, 1, QTableWidgetItem(client.get('ip', '')))
            self.clients_table.setItem(i, 2, QTableWidgetItem(client.get('hostname', '')))
            self.clients_table.setItem(i, 3, QTableWidgetItem(client.get('connected_time', '')))
    
    def update_credentials_display(self, credentials):
        """Met à jour l'affichage des identifiants"""
        self.credentials_table.setRowCount(len(credentials))
        
        for i, cred in enumerate(credentials):
            self.credentials_table.setItem(i, 0, QTableWidgetItem(cred.get('timestamp', '')))
            self.credentials_table.setItem(i, 1, QTableWidgetItem(cred.get('ip_address', '')))
            self.credentials_table.setItem(i, 2, QTableWidgetItem(cred.get('template_used', '')))
            
            # Affichage des données
            form_data = cred.get('form_data', {})
            data_text = ', '.join([f"{k}: {v}" for k, v in form_data.items()])
            self.credentials_table.setItem(i, 3, QTableWidgetItem(data_text))
    
    def get_networks(self):
        """Récupère la liste des réseaux"""
        # Simulation - à remplacer par la vraie détection
        return []
    
    def get_clients(self):
        """Récupère la liste des clients"""
        # Simulation - à remplacer par la vraie détection
        return []
    
    def get_credentials(self):
        """Récupère la liste des identifiants"""
        try:
            credentials_file = '/tmp/captured_credentials.json'
            if os.path.exists(credentials_file):
                with open(credentials_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except:
            pass
        return []
    
    def add_log(self, message, level="INFO"):
        """Ajoute un message au log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = {
            "INFO": "#3498db",
            "SUCCESS": "#27ae60", 
            "WARNING": "#f39c12",
            "ERROR": "#e74c3c"
        }.get(level, "#95a5a6")
        
        log_entry = f'<span style="color: {color}">[{timestamp}] {level}: {message}</span><br>'
        self.logs_text.insertHtml(log_entry)
        
        # Auto-scroll
        cursor = self.logs_text.textCursor()
        cursor.movePosition(cursor.End)
        self.logs_text.setTextCursor(cursor)
    
    def update_statistics(self, new_stats):
        """Met à jour les statistiques"""
        self.stats.update(new_stats) 