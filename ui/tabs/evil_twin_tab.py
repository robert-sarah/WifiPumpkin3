#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Onglet Evil Twin - Création d'un point d'accès malveillant
"""

import os
import time
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QPushButton, QComboBox, QLineEdit, QSpinBox,
                             QCheckBox, QGroupBox, QTextEdit, QTableWidget,
                             QTableWidgetItem, QMessageBox, QProgressBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont

from core.attacks.evil_twin import EvilTwinAttack

class EvilTwinTab(QWidget):
    """Onglet pour l'attaque Evil Twin"""
    
    def __init__(self, network_manager, logger):
        super().__init__()
        self.network_manager = network_manager
        self.logger = logger
        self.evil_twin_attack = None
        self.attack_thread = None
        
        self.setup_ui()
        
    def setup_ui(self):
        """Configuration de l'interface utilisateur"""
        layout = QVBoxLayout(self)
        
        # Section de scan des réseaux
        self.setup_network_scan_section(layout)
        
        # Section de configuration de l'attaque
        self.setup_attack_config_section(layout)
        
        # Section de contrôle
        self.setup_control_section(layout)
        
        # Section de logs
        self.setup_logs_section(layout)
        
    def setup_network_scan_section(self, layout):
        """Section de scan des réseaux"""
        scan_group = QGroupBox("Scan des Réseaux WiFi")
        scan_layout = QVBoxLayout(scan_group)
        
        # Bouton de scan
        scan_btn = QPushButton("Scanner les réseaux")
        scan_btn.clicked.connect(self.scan_networks)
        scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        
        # Tableau des réseaux
        self.networks_table = QTableWidget()
        self.networks_table.setColumnCount(5)
        self.networks_table.setHorizontalHeaderLabels([
            "SSID", "BSSID", "Canal", "Puissance", "Chiffrement"
        ])
        self.networks_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.networks_table.itemSelectionChanged.connect(self.on_network_selected)
        
        scan_layout.addWidget(scan_btn)
        scan_layout.addWidget(self.networks_table)
        
        layout.addWidget(scan_group)
        
    def setup_attack_config_section(self, layout):
        """Section de configuration de l'attaque"""
        config_group = QGroupBox("Configuration de l'Attaque Evil Twin")
        config_layout = QGridLayout(config_group)
        
        # Sélection de l'interface
        config_layout.addWidget(QLabel("Interface WiFi:"), 0, 0)
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.network_manager.get_interfaces())
        config_layout.addWidget(self.interface_combo, 0, 1)
        
        # SSID cible
        config_layout.addWidget(QLabel("SSID cible:"), 1, 0)
        self.target_ssid = QLineEdit()
        self.target_ssid.setPlaceholderText("Nom du réseau à imiter")
        config_layout.addWidget(self.target_ssid, 1, 1)
        
        # Canal
        config_layout.addWidget(QLabel("Canal:"), 2, 0)
        self.channel_spin = QSpinBox()
        self.channel_spin.setRange(1, 13)
        self.channel_spin.setValue(6)
        config_layout.addWidget(self.channel_spin, 2, 1)
        
        # Options avancées
        self.deauth_checkbox = QCheckBox("Envoyer des paquets deauth")
        self.deauth_checkbox.setChecked(True)
        config_layout.addWidget(self.deauth_checkbox, 3, 0, 1, 2)
        
        self.captive_portal_checkbox = QCheckBox("Activer le portail captif")
        config_layout.addWidget(self.captive_portal_checkbox, 4, 0, 1, 2)
        
        # Page de connexion personnalisée
        config_layout.addWidget(QLabel("Page de connexion:"), 5, 0)
        self.portal_page = QLineEdit()
        self.portal_page.setPlaceholderText("URL de la page de connexion")
        config_layout.addWidget(self.portal_page, 5, 1)
        
        layout.addWidget(config_group)
        
    def setup_control_section(self, layout):
        """Section de contrôle de l'attaque"""
        control_group = QGroupBox("Contrôle de l'Attaque")
        control_layout = QHBoxLayout(control_group)
        
        # Boutons de contrôle
        self.start_btn = QPushButton("Démarrer Evil Twin")
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #229954;
            }
        """)
        self.start_btn.clicked.connect(self.start_attack)
        
        self.stop_btn = QPushButton("Arrêter")
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        self.stop_btn.clicked.connect(self.stop_attack)
        self.stop_btn.setEnabled(False)
        
        # Barre de progression
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.progress_bar)
        control_layout.addStretch()
        
        layout.addWidget(control_group)
        
    def setup_logs_section(self, layout):
        """Section des logs"""
        logs_group = QGroupBox("Logs de l'Attaque")
        logs_layout = QVBoxLayout(logs_group)
        
        self.logs_text = QTextEdit()
        self.logs_text.setMaximumHeight(150)
        self.logs_text.setReadOnly(True)
        
        logs_layout.addWidget(self.logs_text)
        
        layout.addWidget(logs_group)
        
    def scan_networks(self):
        """Scanne les réseaux WiFi disponibles"""
        try:
            self.logs_text.append("🔍 Scan des réseaux en cours...")
            networks = self.network_manager.scan_networks()
            
            # Mise à jour du tableau
            self.networks_table.setRowCount(len(networks))
            
            for i, network in enumerate(networks):
                self.networks_table.setItem(i, 0, QTableWidgetItem(network.get('ssid', '')))
                self.networks_table.setItem(i, 1, QTableWidgetItem(network.get('bssid', '')))
                self.networks_table.setItem(i, 2, QTableWidgetItem(str(network.get('channel', ''))))
                self.networks_table.setItem(i, 3, QTableWidgetItem(f"{network.get('signal', '')} dBm"))
                self.networks_table.setItem(i, 4, QTableWidgetItem(network.get('encryption', '')))
            
            self.logs_text.append(f"✅ {len(networks)} réseaux trouvés")
            
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors du scan: {str(e)}")
            QMessageBox.critical(self, "Erreur", f"Erreur lors du scan:\n{str(e)}")
            
    def on_network_selected(self):
        """Appelé quand un réseau est sélectionné"""
        current_row = self.networks_table.currentRow()
        if current_row >= 0:
            ssid = self.networks_table.item(current_row, 0).text()
            channel = self.networks_table.item(current_row, 2).text()
            
            self.target_ssid.setText(ssid)
            if channel.isdigit():
                self.channel_spin.setValue(int(channel))
                
    def start_attack(self):
        """Démarre l'attaque Evil Twin"""
        if not self.target_ssid.text():
            QMessageBox.warning(self, "Attention", "Veuillez sélectionner un réseau cible.")
            return
            
        try:
            # Configuration de l'attaque
            config = {
                'interface': self.interface_combo.currentText(),
                'ssid': self.target_ssid.text(),
                'channel': self.channel_spin.value(),
                'deauth': self.deauth_checkbox.isChecked(),
                'captive_portal': self.captive_portal_checkbox.isChecked(),
                'portal_page': self.portal_page.text() if self.portal_page.text() else None
            }
            
            # Création de l'attaque
            self.evil_twin_attack = EvilTwinAttack(self.network_manager, self.logger)
            
            # Démarrage dans un thread séparé
            self.attack_thread = AttackThread(self.evil_twin_attack, config)
            self.attack_thread.log_signal.connect(self.logs_text.append)
            self.attack_thread.finished.connect(self.on_attack_finished)
            self.attack_thread.start()
            
            # Mise à jour de l'interface
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            
            self.logs_text.append("🚀 Démarrage de l'attaque Evil Twin...")
            
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors du démarrage: {str(e)}")
            QMessageBox.critical(self, "Erreur", f"Erreur lors du démarrage:\n{str(e)}")
            
    def stop_attack(self):
        """Arrête l'attaque Evil Twin"""
        try:
            if self.evil_twin_attack:
                self.evil_twin_attack.stop()
                
            if self.attack_thread:
                self.attack_thread.quit()
                self.attack_thread.wait()
                
            # Mise à jour de l'interface
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.progress_bar.setVisible(False)
            
            self.logs_text.append("🛑 Attaque Evil Twin arrêtée")
            
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors de l'arrêt: {str(e)}")
            
    def on_attack_finished(self):
        """Appelé quand l'attaque se termine"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        
    def update_networks_list(self, networks):
        """Met à jour la liste des réseaux"""
        self.networks_table.setRowCount(len(networks))
        
        for i, network in enumerate(networks):
            self.networks_table.setItem(i, 0, QTableWidgetItem(network.get('ssid', '')))
            self.networks_table.setItem(i, 1, QTableWidgetItem(network.get('bssid', '')))
            self.networks_table.setItem(i, 2, QTableWidgetItem(str(network.get('channel', ''))))
            self.networks_table.setItem(i, 3, QTableWidgetItem(f"{network.get('signal', '')} dBm"))
            self.networks_table.setItem(i, 4, QTableWidgetItem(network.get('encryption', '')))


class AttackThread(QThread):
    """Thread pour exécuter l'attaque en arrière-plan"""
    
    log_signal = pyqtSignal(str)
    
    def __init__(self, attack, config):
        super().__init__()
        self.attack = attack
        self.config = config
        
    def run(self):
        """Exécute l'attaque"""
        try:
            self.attack.start(self.config)
        except Exception as e:
            self.log_signal.emit(f"❌ Erreur dans l'attaque: {str(e)}") 