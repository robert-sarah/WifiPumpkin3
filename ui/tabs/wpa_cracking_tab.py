#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Onglet WPA Cracking - Attaques WPA/WPA2
"""

import os
import time
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QPushButton, QComboBox, QLineEdit, QSpinBox,
                             QCheckBox, QGroupBox, QTextEdit, QTableWidget,
                             QTableWidgetItem, QMessageBox, QProgressBar, QFileDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont

from core.attacks.wpa_cracker import WPACracker

class WPACrackingTab(QWidget):
    """Onglet pour le cracking WPA/WPA2"""
    
    def __init__(self, network_manager, logger):
        super().__init__()
        self.network_manager = network_manager
        self.logger = logger
        self.wpa_cracker = WPACracker(logger)
        self.crack_thread = None
        
        self.setup_ui()
        
    def setup_ui(self):
        """Configuration de l'interface utilisateur"""
        layout = QVBoxLayout(self)
        
        # Section de sélection du réseau
        self.setup_target_section(layout)
        
        # Section de configuration du cracking
        self.setup_cracking_config_section(layout)
        
        # Section de contrôle
        self.setup_control_section(layout)
        
        # Section de résultats
        self.setup_results_section(layout)
        
    def setup_target_section(self, layout):
        """Section de sélection de la cible"""
        target_group = QGroupBox("🎯 Réseau Cible")
        target_layout = QGridLayout(target_group)
        
        # Interface WiFi
        target_layout.addWidget(QLabel("Interface WiFi:"), 0, 0)
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.network_manager.get_interfaces())
        target_layout.addWidget(self.interface_combo, 0, 1)
        
        # BSSID cible
        target_layout.addWidget(QLabel("BSSID cible:"), 1, 0)
        self.target_bssid = QLineEdit()
        self.target_bssid.setPlaceholderText("00:11:22:33:44:55")
        target_layout.addWidget(self.target_bssid, 1, 1)
        
        # Canal
        target_layout.addWidget(QLabel("Canal:"), 2, 0)
        self.channel_spin = QSpinBox()
        self.channel_spin.setRange(1, 13)
        self.channel_spin.setValue(6)
        target_layout.addWidget(self.channel_spin, 2, 1)
        
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
        target_layout.addWidget(scan_btn, 3, 0, 1, 2)
        
        # Tableau des réseaux
        self.networks_table = QTableWidget()
        self.networks_table.setColumnCount(5)
        self.networks_table.setHorizontalHeaderLabels([
            "SSID", "BSSID", "Canal", "Chiffrement", "Signal"
        ])
        self.networks_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.networks_table.itemSelectionChanged.connect(self.on_network_selected)
        target_layout.addWidget(self.networks_table, 4, 0, 1, 2)
        
        layout.addWidget(target_group)
        
    def setup_cracking_config_section(self, layout):
        """Section de configuration du cracking"""
        config_group = QGroupBox("🔓 Configuration du Cracking")
        config_layout = QGridLayout(config_group)
        
        # Méthode de cracking
        config_layout.addWidget(QLabel("Méthode:"), 0, 0)
        self.method_combo = QComboBox()
        self.method_combo.addItems(["Dictionnaire", "Force brute", "GPU (Hashcat)"])
        config_layout.addWidget(self.method_combo, 0, 1)
        
        # Wordlist
        config_layout.addWidget(QLabel("Wordlist:"), 1, 0)
        self.wordlist_layout = QHBoxLayout()
        self.wordlist_path = QLineEdit()
        self.wordlist_path.setPlaceholderText("Chemin vers la wordlist")
        self.wordlist_layout.addWidget(self.wordlist_path)
        
        browse_btn = QPushButton("Parcourir")
        browse_btn.clicked.connect(self.browse_wordlist)
        self.wordlist_layout.addWidget(browse_btn)
        config_layout.addLayout(self.wordlist_layout, 1, 1)
        
        # Configuration force brute
        config_layout.addWidget(QLabel("Caractères:"), 2, 0)
        self.charset_edit = QLineEdit()
        self.charset_edit.setText("abcdefghijklmnopqrstuvwxyz0123456789")
        self.charset_edit.setPlaceholderText("Caractères à utiliser")
        config_layout.addWidget(self.charset_edit, 2, 1)
        
        # Longueur min/max
        config_layout.addWidget(QLabel("Longueur min:"), 3, 0)
        self.min_length = QSpinBox()
        self.min_length.setRange(4, 12)
        self.min_length.setValue(6)
        config_layout.addWidget(self.min_length, 3, 1)
        
        config_layout.addWidget(QLabel("Longueur max:"), 4, 0)
        self.max_length = QSpinBox()
        self.max_length.setRange(4, 12)
        self.max_length.setValue(8)
        config_layout.addWidget(self.max_length, 4, 1)
        
        # Options avancées
        self.capture_handshake_checkbox = QCheckBox("Capturer le handshake")
        self.capture_handshake_checkbox.setChecked(True)
        config_layout.addWidget(self.capture_handshake_checkbox, 5, 0, 1, 2)
        
        self.use_gpu_checkbox = QCheckBox("Utiliser GPU (si disponible)")
        config_layout.addWidget(self.use_gpu_checkbox, 6, 0, 1, 2)
        
        layout.addWidget(config_group)
        
    def setup_control_section(self, layout):
        """Section de contrôle"""
        control_group = QGroupBox("🎮 Contrôle du Cracking")
        control_layout = QHBoxLayout(control_group)
        
        # Boutons de contrôle
        self.start_btn = QPushButton("Démarrer Cracking")
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
        self.start_btn.clicked.connect(self.start_cracking)
        
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
        self.stop_btn.clicked.connect(self.stop_cracking)
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
        results_group = QGroupBox("📊 Résultats du Cracking")
        results_layout = QVBoxLayout(results_group)
        
        # Zone de logs
        self.logs_text = QTextEdit()
        self.logs_text.setMaximumHeight(200)
        self.logs_text.setReadOnly(True)
        
        # Tableau des résultats
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels([
            "Réseau", "Méthode", "Mot de passe", "Temps"
        ])
        
        results_layout.addWidget(self.logs_text)
        results_layout.addWidget(self.results_table)
        
        layout.addWidget(results_group)
        
    def scan_networks(self):
        """Scanne les réseaux WiFi"""
        try:
            self.logs_text.append("🔍 Démarrage du scan des réseaux...")
            
            interface = self.interface_combo.currentText()
            if not interface:
                self.logs_text.append("❌ Veuillez sélectionner une interface")
                return
            
            # Scan avec le network manager
            networks = self.network_manager.scan_networks()
            
            if networks:
                self.update_networks_table(networks)
                self.logs_text.append(f"✅ {len(networks)} réseaux trouvés")
            else:
                self.logs_text.append("⚠️ Aucun réseau trouvé")
                
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors du scan: {str(e)}")
    
    def update_networks_table(self, networks):
        """Met à jour le tableau des réseaux"""
        self.networks_table.setRowCount(len(networks))
        
        for i, network in enumerate(networks):
            self.networks_table.setItem(i, 0, QTableWidgetItem(network.get('ssid', '')))
            self.networks_table.setItem(i, 1, QTableWidgetItem(network.get('bssid', '')))
            self.networks_table.setItem(i, 2, QTableWidgetItem(str(network.get('channel', ''))))
            self.networks_table.setItem(i, 3, QTableWidgetItem(network.get('encryption', '')))
            self.networks_table.setItem(i, 4, QTableWidgetItem(f"{network.get('signal', '')} dBm"))
    
    def on_network_selected(self):
        """Appelé quand un réseau est sélectionné"""
        current_row = self.networks_table.currentRow()
        if current_row >= 0:
            bssid = self.networks_table.item(current_row, 1).text()
            channel = self.networks_table.item(current_row, 2).text()
            
            self.target_bssid.setText(bssid)
            if channel.isdigit():
                self.channel_spin.setValue(int(channel))
    
    def browse_wordlist(self):
        """Ouvre un dialogue pour sélectionner une wordlist"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Sélectionner une wordlist", "/usr/share/wordlists/", 
            "Text files (*.txt *.lst);;All files (*)"
        )
        if file_path:
            self.wordlist_path.setText(file_path)
    
    def start_cracking(self):
        """Démarre le cracking"""
        if not self.target_bssid.text():
            QMessageBox.warning(self, "Attention", "Veuillez sélectionner un réseau cible.")
            return
        
        try:
            # Configuration du cracking
            config = {
                'interface': self.interface_combo.currentText(),
                'bssid': self.target_bssid.text(),
                'channel': self.channel_spin.value(),
                'method': self.method_combo.currentText().lower(),
                'wordlist': self.wordlist_path.text() if self.wordlist_path.text() else None,
                'charset': self.charset_edit.text(),
                'min_length': self.min_length.value(),
                'max_length': self.max_length.value(),
                'capture_handshake': self.capture_handshake_checkbox.isChecked(),
                'use_gpu': self.use_gpu_checkbox.isChecked()
            }
            
            # Démarrage du cracking dans un thread
            self.crack_thread = CrackingThread(self.wpa_cracker, config, self.logger)
            self.crack_thread.password_found.connect(self.on_password_found)
            self.crack_thread.log_signal.connect(self.logs_text.append)
            self.crack_thread.finished.connect(self.on_cracking_finished)
            self.crack_thread.start()
            
            # Mise à jour de l'interface
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            
            self.logs_text.append("🚀 Démarrage du cracking WPA...")
            
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors du démarrage: {str(e)}")
            QMessageBox.critical(self, "Erreur", f"Erreur lors du démarrage:\n{str(e)}")
    
    def stop_cracking(self):
        """Arrête le cracking"""
        try:
            if self.wpa_cracker:
                self.wpa_cracker.stop_cracking()
            
            if self.crack_thread:
                self.crack_thread.quit()
                self.crack_thread.wait()
            
            # Mise à jour de l'interface
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.progress_bar.setVisible(False)
            
            self.logs_text.append("🛑 Cracking arrêté")
            
        except Exception as e:
            self.logs_text.append(f"❌ Erreur lors de l'arrêt: {str(e)}")
    
    def on_password_found(self, password, method, time_taken):
        """Appelé quand un mot de passe est trouvé"""
        # Ajout au tableau des résultats
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        self.results_table.setItem(row, 0, QTableWidgetItem(self.target_bssid.text()))
        self.results_table.setItem(row, 1, QTableWidgetItem(method))
        self.results_table.setItem(row, 2, QTableWidgetItem(password))
        self.results_table.setItem(row, 3, QTableWidgetItem(f"{time_taken:.1f}s"))
        
        self.logs_text.append(f"🎉 Mot de passe trouvé: {password}")
        QMessageBox.information(self, "Succès", f"Mot de passe trouvé: {password}")
    
    def on_cracking_finished(self):
        """Appelé quand le cracking se termine"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)


class CrackingThread(QThread):
    """Thread pour le cracking WPA"""
    
    password_found = pyqtSignal(str, str, float)
    log_signal = pyqtSignal(str)
    
    def __init__(self, wpa_cracker, config, logger):
        super().__init__()
        self.wpa_cracker = wpa_cracker
        self.config = config
        self.logger = logger
        self.start_time = None
        
    def run(self):
        """Exécute le cracking"""
        try:
            self.start_time = time.time()
            
            # Démarrage du cracking
            password = self.wpa_cracker.start_cracking(
                bssid=self.config['bssid'],
                interface=self.config['interface'],
                method=self.config['method'],
                wordlist=self.config['wordlist'],
                charset=self.config['charset'],
                min_length=self.config['min_length'],
                max_length=self.config['max_length']
            )
            
            if password:
                time_taken = time.time() - self.start_time
                self.password_found.emit(password, self.config['method'], time_taken)
            else:
                time_taken = time.time() - self.start_time
                self.log_signal.emit(f"❌ Aucun mot de passe trouvé ({time_taken:.1f}s)")
                
        except Exception as e:
            self.log_signal.emit(f"❌ Erreur dans le cracking: {str(e)}") 