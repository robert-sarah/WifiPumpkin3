#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Onglet Captive Portal - Portails captifs WiFi
"""

import os
import time
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QPushButton, QComboBox, QLineEdit, QSpinBox,
                             QCheckBox, QGroupBox, QTextEdit, QTableWidget,
                             QTableWidgetItem, QMessageBox, QProgressBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont

class CaptivePortalTab(QWidget):
    """Onglet pour le portail captif"""
    
    def __init__(self, network_manager, logger):
        super().__init__()
        self.network_manager = network_manager
        self.logger = logger
        
        self.setup_ui()
        
    def setup_ui(self):
        """Configuration de l'interface utilisateur"""
        layout = QVBoxLayout(self)
        
        # Section de configuration du portail
        self.setup_portal_config_section(layout)
        
        # Section de configuration du serveur
        self.setup_server_config_section(layout)
        
        # Section de contrôle
        self.setup_control_section(layout)
        
        # Section des clients connectés
        self.setup_clients_section(layout)
        
    def setup_portal_config_section(self, layout):
        """Section de configuration du portail"""
        portal_group = QGroupBox("Configuration du Portail Captif")
        portal_layout = QGridLayout(portal_group)
        
        # Nom du réseau
        portal_layout.addWidget(QLabel("Nom du réseau:"), 0, 0)
        self.network_name = QLineEdit()
        self.network_name.setText("FreeWifi")
        portal_layout.addWidget(self.network_name, 0, 1)
        
        # Page de connexion
        portal_layout.addWidget(QLabel("Page de connexion:"), 1, 0)
        self.login_page = QComboBox()
        self.login_page.addItems([
            "Page de connexion standard",
            "Page de mise à jour",
            "Page de vérification",
            "Page personnalisée"
        ])
        portal_layout.addWidget(self.login_page, 1, 1)
        
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
        
        layout.addWidget(portal_group)
        
    def setup_server_config_section(self, layout):
        """Section de configuration du serveur"""
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
        
        layout.addWidget(server_group)
        
    def setup_control_section(self, layout):
        """Section de contrôle"""
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
        
        layout.addWidget(control_group)
        
    def setup_clients_section(self, layout):
        """Section des clients connectés"""
        clients_group = QGroupBox("Clients Connectés")
        clients_layout = QVBoxLayout(clients_group)
        
        # Tableau des clients
        self.clients_table = QTableWidget()
        self.clients_table.setColumnCount(5)
        self.clients_table.setHorizontalHeaderLabels([
            "Adresse MAC", "IP", "Nom d'hôte", "Temps connecté", "Trafic"
        ])
        
        # Zone de logs
        self.logs_text = QTextEdit()
        self.logs_text.setMaximumHeight(100)
        self.logs_text.setReadOnly(True)
        
        clients_layout.addWidget(self.clients_table)
        clients_layout.addWidget(self.logs_text)
        
        layout.addWidget(clients_group)
        
    def start_portal(self):
        """Démarre le portail captif"""
        try:
            self.logs_text.append("🌐 Démarrage du portail captif...")
            
            # Simulation du démarrage pour la démo
            self.simulate_portal_start()
            
            # Mise à jour de l'interface
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors du démarrage: {str(e)}")
            QMessageBox.critical(self, "Erreur", f"Erreur lors du démarrage:\n{str(e)}")
            
    def stop_portal(self):
        """Arrête le portail captif"""
        try:
            # Mise à jour de l'interface
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.progress_bar.setVisible(False)
            
            self.logs_text.append("🛑 Portail captif arrêté")
            
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors de l'arrêt: {str(e)}")
            
    def simulate_portal_start(self):
        """Simule le démarrage du portail pour la démo"""
        # Données de démonstration
        demo_clients = [
            {
                "mac": "aa:bb:cc:dd:ee:ff",
                "ip": "192.168.1.100",
                "hostname": "iPhone-User",
                "connected_time": "00:05:30",
                "traffic": "2.5 MB"
            },
            {
                "mac": "11:22:33:44:55:66",
                "ip": "192.168.1.101",
                "hostname": "Android-Device",
                "connected_time": "00:02:15",
                "traffic": "1.8 MB"
            },
            {
                "mac": "aa:aa:aa:aa:aa:aa",
                "ip": "192.168.1.102",
                "hostname": "Laptop-User",
                "connected_time": "00:08:45",
                "traffic": "5.2 MB"
            }
        ]
        
        # Mise à jour du tableau
        self.clients_table.setRowCount(len(demo_clients))
        
        for i, client in enumerate(demo_clients):
            self.clients_table.setItem(i, 0, QTableWidgetItem(client['mac']))
            self.clients_table.setItem(i, 1, QTableWidgetItem(client['ip']))
            self.clients_table.setItem(i, 2, QTableWidgetItem(client['hostname']))
            self.clients_table.setItem(i, 3, QTableWidgetItem(client['connected_time']))
            self.clients_table.setItem(i, 4, QTableWidgetItem(client['traffic']))
            
        self.logs_text.append(f"✅ Portail démarré - {len(demo_clients)} clients connectés")
        
    def get_portal_config(self):
        """Retourne la configuration du portail"""
        return {
            'network_name': self.network_name.text(),
            'login_page': self.login_page.currentText(),
            'custom_message': self.custom_message.text(),
            'redirect_url': self.redirect_url.text(),
            'interface': self.interface_combo.currentText(),
            'server_ip': self.server_ip.text(),
            'server_port': self.server_port.value(),
            'capture_credentials': self.capture_credentials.isChecked(),
            'log_traffic': self.log_traffic.isChecked()
        } 