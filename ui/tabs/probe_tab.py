#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Onglet Probe Request - Attaques de sondage WiFi
"""

import time
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QPushButton, QComboBox, QLineEdit, QSpinBox,
                             QCheckBox, QGroupBox, QTextEdit, QTableWidget,
                             QTableWidgetItem, QMessageBox, QProgressBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont

class ProbeTab(QWidget):
    """Onglet pour l'attaque Probe Request"""
    
    def __init__(self, network_manager, logger):
        super().__init__()
        self.network_manager = network_manager
        self.logger = logger
        
        self.setup_ui()
        
    def setup_ui(self):
        """Configuration de l'interface utilisateur"""
        layout = QVBoxLayout(self)
        
        # Section de configuration
        self.setup_config_section(layout)
        
        # Section de contrôle
        self.setup_control_section(layout)
        
        # Section de résultats
        self.setup_results_section(layout)
        
    def setup_config_section(self, layout):
        """Section de configuration"""
        config_group = QGroupBox("Configuration de l'Attaque Probe")
        config_layout = QGridLayout(config_group)
        
        # Interface
        config_layout.addWidget(QLabel("Interface WiFi:"), 0, 0)
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.network_manager.get_interfaces())
        config_layout.addWidget(self.interface_combo, 0, 1)
        
        # SSID à sonder
        config_layout.addWidget(QLabel("SSID à sonder:"), 1, 0)
        self.probe_ssid = QLineEdit()
        self.probe_ssid.setPlaceholderText("Nom du réseau à sonder")
        config_layout.addWidget(self.probe_ssid, 1, 1)
        
        # Nombre de sondes
        config_layout.addWidget(QLabel("Nombre de sondes:"), 2, 0)
        self.probe_count = QSpinBox()
        self.probe_count.setRange(1, 1000)
        self.probe_count.setValue(10)
        config_layout.addWidget(self.probe_count, 2, 1)
        
        # Intervalle
        config_layout.addWidget(QLabel("Intervalle (ms):"), 3, 0)
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(100, 10000)
        self.interval_spin.setValue(500)
        config_layout.addWidget(self.interval_spin, 3, 1)
        
        layout.addWidget(config_group)
        
    def setup_control_section(self, layout):
        """Section de contrôle"""
        control_group = QGroupBox("Contrôle de l'Attaque")
        control_layout = QHBoxLayout(control_group)
        
        # Boutons
        self.start_btn = QPushButton("Démarrer Probe")
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        self.start_btn.clicked.connect(self.start_probe)
        
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
        self.stop_btn.clicked.connect(self.stop_probe)
        self.stop_btn.setEnabled(False)
        
        # Barre de progression
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.progress_bar)
        control_layout.addStretch()
        
        layout.addWidget(control_group)
        
    def setup_results_section(self, layout):
        """Section des résultats"""
        results_group = QGroupBox("Résultats des Sondes")
        results_layout = QVBoxLayout(results_group)
        
        # Tableau des résultats
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels([
            "SSID", "BSSID", "Canal", "Puissance"
        ])
        
        # Zone de logs
        self.logs_text = QTextEdit()
        self.logs_text.setMaximumHeight(100)
        self.logs_text.setReadOnly(True)
        
        results_layout.addWidget(self.results_table)
        results_layout.addWidget(self.logs_text)
        
        layout.addWidget(results_group)
        
    def start_probe(self):
        """Démarre l'attaque Probe"""
        if not self.probe_ssid.text():
            QMessageBox.warning(self, "Attention", "Veuillez spécifier un SSID à sonder.")
            return
            
        try:
            self.logs_text.append("🔍 Démarrage de l'attaque Probe...")
            
            # Simulation de l'attaque pour la démo
            self.simulate_probe_attack()
            
            # Mise à jour de l'interface
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors du démarrage: {str(e)}")
            QMessageBox.critical(self, "Erreur", f"Erreur lors du démarrage:\n{str(e)}")
            
    def stop_probe(self):
        """Arrête l'attaque Probe"""
        try:
            # Mise à jour de l'interface
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.progress_bar.setVisible(False)
            
            self.logs_text.append("🛑 Attaque Probe arrêtée")
            
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors de l'arrêt: {str(e)}")
            
    def simulate_probe_attack(self):
        """Simule une attaque Probe pour la démo"""
        # Données de démonstration
        demo_results = [
            {"ssid": "FreeWifi", "bssid": "00:11:22:33:44:55", "channel": 6, "signal": "-45"},
            {"ssid": "Orange_WiFi", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 11, "signal": "-52"},
            {"ssid": "SFR_WiFi_Fon", "bssid": "11:22:33:44:55:66", "channel": 1, "signal": "-67"}
        ]
        
        # Mise à jour du tableau
        self.results_table.setRowCount(len(demo_results))
        
        for i, result in enumerate(demo_results):
            self.results_table.setItem(i, 0, QTableWidgetItem(result['ssid']))
            self.results_table.setItem(i, 1, QTableWidgetItem(result['bssid']))
            self.results_table.setItem(i, 2, QTableWidgetItem(str(result['channel'])))
            self.results_table.setItem(i, 3, QTableWidgetItem(f"{result['signal']} dBm"))
            
        self.logs_text.append(f"✅ {len(demo_results)} réseaux trouvés") 