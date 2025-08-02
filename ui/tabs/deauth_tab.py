#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Onglet Deauth Attack - Attaques de déconnexion WiFi
"""

import time
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QPushButton, QComboBox, QLineEdit, QSpinBox,
                             QCheckBox, QGroupBox, QTextEdit, QTableWidget,
                             QTableWidgetItem, QMessageBox, QProgressBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont

from core.attacks.deauth_attack import DeauthAttack

class DeauthTab(QWidget):
    """Onglet pour l'attaque Deauth"""
    
    def __init__(self, network_manager, logger):
        super().__init__()
        self.network_manager = network_manager
        self.logger = logger
        self.deauth_attack = None
        self.attack_thread = None
        
        self.setup_ui()
        
    def setup_ui(self):
        """Configuration de l'interface utilisateur"""
        layout = QVBoxLayout(self)
        
        # Section de sélection du réseau cible
        self.setup_target_section(layout)
        
        # Section de configuration de l'attaque
        self.setup_attack_config_section(layout)
        
        # Section de contrôle
        self.setup_control_section(layout)
        
        # Section de logs
        self.setup_logs_section(layout)
        
    def setup_target_section(self, layout):
        """Section de sélection de la cible"""
        target_group = QGroupBox("Réseau Cible")
        target_layout = QGridLayout(target_group)
        
        # Sélection de l'interface
        target_layout.addWidget(QLabel("Interface WiFi:"), 0, 0)
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.network_manager.get_interfaces())
        target_layout.addWidget(self.interface_combo, 0, 1)
        
        # BSSID cible
        target_layout.addWidget(QLabel("BSSID cible:"), 1, 0)
        self.target_bssid = QLineEdit()
        self.target_bssid.setPlaceholderText("00:11:22:33:44:55")
        target_layout.addWidget(self.target_bssid, 1, 1)
        
        # SSID cible
        target_layout.addWidget(QLabel("SSID cible:"), 2, 0)
        self.target_ssid = QLineEdit()
        self.target_ssid.setPlaceholderText("Nom du réseau")
        target_layout.addWidget(self.target_ssid, 2, 1)
        
        # Canal
        target_layout.addWidget(QLabel("Canal:"), 3, 0)
        self.channel_spin = QSpinBox()
        self.channel_spin.setRange(1, 13)
        self.channel_spin.setValue(6)
        target_layout.addWidget(self.channel_spin, 3, 1)
        
        layout.addWidget(target_group)
        
    def setup_attack_config_section(self, layout):
        """Section de configuration de l'attaque"""
        config_group = QGroupBox("Configuration de l'Attaque Deauth")
        config_layout = QGridLayout(config_group)
        
        # Nombre de paquets
        config_layout.addWidget(QLabel("Nombre de paquets:"), 0, 0)
        self.packet_count = QSpinBox()
        self.packet_count.setRange(1, 1000)
        self.packet_count.setValue(10)
        config_layout.addWidget(self.packet_count, 0, 1)
        
        # Intervalle entre les paquets
        config_layout.addWidget(QLabel("Intervalle (ms):"), 1, 0)
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(10, 10000)
        self.interval_spin.setValue(100)
        config_layout.addWidget(self.interval_spin, 1, 1)
        
        # Type d'attaque
        config_layout.addWidget(QLabel("Type d'attaque:"), 2, 0)
        self.attack_type = QComboBox()
        self.attack_type.addItems(["Deauth", "Disassoc", "Auth"])
        config_layout.addWidget(self.attack_type, 2, 1)
        
        # Options avancées
        self.broadcast_checkbox = QCheckBox("Attaque broadcast")
        self.broadcast_checkbox.setChecked(True)
        config_layout.addWidget(self.broadcast_checkbox, 3, 0, 1, 2)
        
        self.continuous_checkbox = QCheckBox("Attaque continue")
        config_layout.addWidget(self.continuous_checkbox, 4, 0, 1, 2)
        
        layout.addWidget(config_group)
        
    def setup_control_section(self, layout):
        """Section de contrôle de l'attaque"""
        control_group = QGroupBox("Contrôle de l'Attaque")
        control_layout = QHBoxLayout(control_group)
        
        # Boutons de contrôle
        self.start_btn = QPushButton("Démarrer Deauth")
        self.start_btn.setStyleSheet("""
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
        self.start_btn.clicked.connect(self.start_attack)
        
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
        
    def start_attack(self):
        """Démarre l'attaque Deauth"""
        if not self.target_bssid.text():
            QMessageBox.warning(self, "Attention", "Veuillez spécifier un BSSID cible.")
            return
            
        try:
            # Configuration de l'attaque
            config = {
                'interface': self.interface_combo.currentText(),
                'target_bssid': self.target_bssid.text(),
                'target_ssid': self.target_ssid.text(),
                'channel': self.channel_spin.value(),
                'packet_count': self.packet_count.value(),
                'interval': self.interval_spin.value(),
                'attack_type': self.attack_type.currentText(),
                'broadcast': self.broadcast_checkbox.isChecked(),
                'continuous': self.continuous_checkbox.isChecked()
            }
            
            # Création de l'attaque
            self.deauth_attack = DeauthAttack(self.network_manager, self.logger)
            
            # Démarrage dans un thread séparé
            self.attack_thread = DeauthAttackThread(self.deauth_attack, config)
            self.attack_thread.log_signal.connect(self.logs_text.append)
            self.attack_thread.finished.connect(self.on_attack_finished)
            self.attack_thread.start()
            
            # Mise à jour de l'interface
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            
            self.logs_text.append("🚀 Démarrage de l'attaque Deauth...")
            
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors du démarrage: {str(e)}")
            QMessageBox.critical(self, "Erreur", f"Erreur lors du démarrage:\n{str(e)}")
            
    def stop_attack(self):
        """Arrête l'attaque Deauth"""
        try:
            if self.deauth_attack:
                self.deauth_attack.stop()
                
            if self.attack_thread:
                self.attack_thread.quit()
                self.attack_thread.wait()
                
            # Mise à jour de l'interface
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.progress_bar.setVisible(False)
            
            self.logs_text.append("🛑 Attaque Deauth arrêtée")
            
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors de l'arrêt: {str(e)}")
            
    def on_attack_finished(self):
        """Appelé quand l'attaque se termine"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)


class DeauthAttackThread(QThread):
    """Thread pour exécuter l'attaque Deauth en arrière-plan"""
    
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