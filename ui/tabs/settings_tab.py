#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Onglet Paramètres - Configuration de l'application
"""

import os
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QPushButton, QComboBox, QLineEdit, QSpinBox,
                             QCheckBox, QGroupBox, QTextEdit, QFileDialog,
                             QMessageBox, QTabWidget)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

class SettingsTab(QWidget):
    """Onglet pour les paramètres de l'application"""
    
    def __init__(self, config):
        super().__init__()
        self.config = config
        
        self.setup_ui()
        
    def setup_ui(self):
        """Configuration de l'interface utilisateur"""
        layout = QVBoxLayout(self)
        
        # Onglets de paramètres
        self.settings_tabs = QTabWidget()
        
        # Onglet Général
        self.setup_general_tab()
        
        # Onglet Réseau
        self.setup_network_tab()
        
        # Onglet Sécurité
        self.setup_security_tab()
        
        # Onglet Logs
        self.setup_logs_tab()
        
        layout.addWidget(self.settings_tabs)
        
        # Boutons de contrôle
        self.setup_control_buttons(layout)
        
    def setup_general_tab(self):
        """Onglet des paramètres généraux"""
        general_widget = QWidget()
        general_layout = QVBoxLayout(general_widget)
        
        # Interface utilisateur
        ui_group = QGroupBox("Interface Utilisateur")
        ui_layout = QGridLayout(ui_group)
        
        # Thème
        ui_layout.addWidget(QLabel("Thème:"), 0, 0)
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Clair", "Sombre", "Système"])
        ui_layout.addWidget(self.theme_combo, 0, 1)
        
        # Langue
        ui_layout.addWidget(QLabel("Langue:"), 1, 0)
        self.language_combo = QComboBox()
        self.language_combo.addItems(["Français", "English", "Español"])
        ui_layout.addWidget(self.language_combo, 1, 1)
        
        # Taille de police
        ui_layout.addWidget(QLabel("Taille de police:"), 2, 0)
        self.font_size = QSpinBox()
        self.font_size.setRange(8, 20)
        self.font_size.setValue(10)
        ui_layout.addWidget(self.font_size, 2, 1)
        
        general_layout.addWidget(ui_group)
        
        # Comportement
        behavior_group = QGroupBox("Comportement")
        behavior_layout = QGridLayout(behavior_group)
        
        # Démarrage automatique
        self.auto_start = QCheckBox("Démarrer automatiquement")
        behavior_layout.addWidget(self.auto_start, 0, 0, 1, 2)
        
        # Minimiser au démarrage
        self.minimize_startup = QCheckBox("Minimiser au démarrage")
        behavior_layout.addWidget(self.minimize_startup, 1, 0, 1, 2)
        
        # Vérifier les mises à jour
        self.check_updates = QCheckBox("Vérifier les mises à jour")
        self.check_updates.setChecked(True)
        behavior_layout.addWidget(self.check_updates, 2, 0, 1, 2)
        
        general_layout.addWidget(behavior_group)
        
        general_layout.addStretch()
        
        self.settings_tabs.addTab(general_widget, "Général")
        
    def setup_network_tab(self):
        """Onglet des paramètres réseau"""
        network_widget = QWidget()
        network_layout = QVBoxLayout(network_widget)
        
        # Interface par défaut
        interface_group = QGroupBox("Interface Réseau")
        interface_layout = QGridLayout(interface_group)
        
        # Interface WiFi par défaut
        interface_layout.addWidget(QLabel("Interface WiFi par défaut:"), 0, 0)
        self.default_interface = QComboBox()
        self.default_interface.addItems(["wlan0", "wlan1", "wifi0"])
        interface_layout.addWidget(self.default_interface, 0, 1)
        
        # Mode par défaut
        interface_layout.addWidget(QLabel("Mode par défaut:"), 1, 0)
        self.default_mode = QComboBox()
        self.default_mode.addItems(["Managed", "Monitor"])
        interface_layout.addWidget(self.default_mode, 1, 1)
        
        network_layout.addWidget(interface_group)
        
        # Configuration DHCP
        dhcp_group = QGroupBox("Configuration DHCP")
        dhcp_layout = QGridLayout(dhcp_group)
        
        # Plage d'adresses
        dhcp_layout.addWidget(QLabel("Plage d'adresses:"), 0, 0)
        self.dhcp_range_start = QLineEdit()
        self.dhcp_range_start.setText("192.168.1.100")
        dhcp_layout.addWidget(self.dhcp_range_start, 0, 1)
        
        dhcp_layout.addWidget(QLabel("à:"), 0, 2)
        self.dhcp_range_end = QLineEdit()
        self.dhcp_range_end.setText("192.168.1.200")
        dhcp_layout.addWidget(self.dhcp_range_end, 0, 3)
        
        # Passerelle
        dhcp_layout.addWidget(QLabel("Passerelle:"), 1, 0)
        self.gateway = QLineEdit()
        self.gateway.setText("192.168.1.1")
        dhcp_layout.addWidget(self.gateway, 1, 1)
        
        # DNS
        dhcp_layout.addWidget(QLabel("Serveurs DNS:"), 2, 0)
        self.dns_servers = QLineEdit()
        self.dns_servers.setText("8.8.8.8, 8.8.4.4")
        dhcp_layout.addWidget(self.dns_servers, 2, 1)
        
        network_layout.addWidget(dhcp_group)
        
        network_layout.addStretch()
        
        self.settings_tabs.addTab(network_widget, "Réseau")
        
    def setup_security_tab(self):
        """Onglet des paramètres de sécurité"""
        security_widget = QWidget()
        security_layout = QVBoxLayout(security_widget)
        
        # Avertissements
        warnings_group = QGroupBox("Avertissements de Sécurité")
        warnings_layout = QGridLayout(warnings_group)
        
        # Avertissement avant attaque
        self.warn_before_attack = QCheckBox("Avertir avant de lancer une attaque")
        self.warn_before_attack.setChecked(True)
        warnings_layout.addWidget(self.warn_before_attack, 0, 0, 1, 2)
        
        # Confirmation d'arrêt
        self.confirm_stop = QCheckBox("Demander confirmation pour arrêter")
        self.confirm_stop.setChecked(True)
        warnings_layout.addWidget(self.confirm_stop, 1, 0, 1, 2)
        
        # Vérification des privilèges
        self.check_privileges = QCheckBox("Vérifier les privilèges administrateur")
        self.check_privileges.setChecked(True)
        warnings_layout.addWidget(self.check_privileges, 2, 0, 1, 2)
        
        security_layout.addWidget(warnings_group)
        
        # Chiffrement
        encryption_group = QGroupBox("Chiffrement")
        encryption_layout = QGridLayout(encryption_group)
        
        # Chiffrer les logs
        self.encrypt_logs = QCheckBox("Chiffrer les fichiers de logs")
        encryption_layout.addWidget(self.encrypt_logs, 0, 0, 1, 2)
        
        # Chiffrer les captures
        self.encrypt_captures = QCheckBox("Chiffrer les captures de trafic")
        encryption_layout.addWidget(self.encrypt_captures, 1, 0, 1, 2)
        
        # Clé de chiffrement
        encryption_layout.addWidget(QLabel("Clé de chiffrement:"), 2, 0)
        self.encryption_key = QLineEdit()
        self.encryption_key.setEchoMode(QLineEdit.Password)
        encryption_layout.addWidget(self.encryption_key, 2, 1)
        
        security_layout.addWidget(encryption_group)
        
        security_layout.addStretch()
        
        self.settings_tabs.addTab(security_widget, "Sécurité")
        
    def setup_logs_tab(self):
        """Onglet des paramètres de logs"""
        logs_widget = QWidget()
        logs_layout = QVBoxLayout(logs_widget)
        
        # Configuration des logs
        log_config_group = QGroupBox("Configuration des Logs")
        log_config_layout = QGridLayout(log_config_group)
        
        # Niveau de log
        log_config_layout.addWidget(QLabel("Niveau de log:"), 0, 0)
        self.log_level = QComboBox()
        self.log_level.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self.log_level.setCurrentText("INFO")
        log_config_layout.addWidget(self.log_level, 0, 1)
        
        # Dossier de logs
        log_config_layout.addWidget(QLabel("Dossier de logs:"), 1, 0)
        self.log_folder = QLineEdit()
        self.log_folder.setText("./logs")
        log_config_layout.addWidget(self.log_folder, 1, 1)
        
        # Bouton de sélection
        self.browse_log_btn = QPushButton("Parcourir...")
        self.browse_log_btn.clicked.connect(self.browse_log_folder)
        log_config_layout.addWidget(self.browse_log_btn, 1, 2)
        
        # Rotation des logs
        log_config_layout.addWidget(QLabel("Rotation (jours):"), 2, 0)
        self.log_rotation = QSpinBox()
        self.log_rotation.setRange(1, 365)
        self.log_rotation.setValue(7)
        log_config_layout.addWidget(self.log_rotation, 2, 1)
        
        logs_layout.addWidget(log_config_group)
        
        # Options de logs
        log_options_group = QGroupBox("Options de Logs")
        log_options_layout = QGridLayout(log_options_group)
        
        # Logger les attaques
        self.log_attacks = QCheckBox("Logger toutes les attaques")
        self.log_attacks.setChecked(True)
        log_options_layout.addWidget(self.log_attacks, 0, 0, 1, 2)
        
        # Logger les erreurs
        self.log_errors = QCheckBox("Logger les erreurs")
        self.log_errors.setChecked(True)
        log_options_layout.addWidget(self.log_errors, 1, 0, 1, 2)
        
        # Logger le trafic
        self.log_traffic = QCheckBox("Logger le trafic réseau")
        log_options_layout.addWidget(self.log_traffic, 2, 0, 1, 2)
        
        # Timestamp détaillé
        self.detailed_timestamp = QCheckBox("Timestamps détaillés")
        self.detailed_timestamp.setChecked(True)
        log_options_layout.addWidget(self.detailed_timestamp, 3, 0, 1, 2)
        
        logs_layout.addWidget(log_options_group)
        
        logs_layout.addStretch()
        
        self.settings_tabs.addTab(logs_widget, "Logs")
        
    def setup_control_buttons(self, layout):
        """Boutons de contrôle des paramètres"""
        button_layout = QHBoxLayout()
        
        # Bouton Sauvegarder
        self.save_btn = QPushButton("Sauvegarder")
        self.save_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
        """)
        self.save_btn.clicked.connect(self.save_settings)
        
        # Bouton Restaurer
        self.restore_btn = QPushButton("Restaurer")
        self.restore_btn.setStyleSheet("""
            QPushButton {
                background-color: #f39c12;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #e67e22;
            }
        """)
        self.restore_btn.clicked.connect(self.restore_settings)
        
        # Bouton Par défaut
        self.default_btn = QPushButton("Par défaut")
        self.default_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        self.default_btn.clicked.connect(self.reset_to_default)
        
        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.restore_btn)
        button_layout.addWidget(self.default_btn)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
    def browse_log_folder(self):
        """Ouvre le dialogue de sélection de dossier"""
        folder = QFileDialog.getExistingDirectory(self, "Sélectionner le dossier de logs")
        if folder:
            self.log_folder.setText(folder)
            
    def save_settings(self):
        """Sauvegarde les paramètres"""
        try:
            # Récupération des paramètres depuis l'interface
            settings = self.get_current_settings()
            
            # Sauvegarde dans la configuration
            self.config.save_settings(settings)
            
            QMessageBox.information(self, "Succès", "Paramètres sauvegardés avec succès.")
            
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de la sauvegarde:\n{str(e)}")
            
    def restore_settings(self):
        """Restaure les paramètres"""
        try:
            # Chargement des paramètres depuis la configuration
            settings = self.config.load_settings()
            
            # Application des paramètres à l'interface
            self.apply_settings(settings)
            
            QMessageBox.information(self, "Succès", "Paramètres restaurés avec succès.")
            
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de la restauration:\n{str(e)}")
            
    def reset_to_default(self):
        """Remet les paramètres par défaut"""
        reply = QMessageBox.question(self, "Confirmation", 
                                   "Voulez-vous vraiment remettre tous les paramètres par défaut ?",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            try:
                # Application des paramètres par défaut
                self.apply_default_settings()
                
                QMessageBox.information(self, "Succès", "Paramètres remis par défaut.")
                
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Erreur lors de la remise à zéro:\n{str(e)}")
                
    def get_current_settings(self):
        """Récupère les paramètres actuels de l'interface"""
        return {
            'theme': self.theme_combo.currentText(),
            'language': self.language_combo.currentText(),
            'font_size': self.font_size.value(),
            'auto_start': self.auto_start.isChecked(),
            'minimize_startup': self.minimize_startup.isChecked(),
            'check_updates': self.check_updates.isChecked(),
            'default_interface': self.default_interface.currentText(),
            'default_mode': self.default_mode.currentText(),
            'dhcp_range_start': self.dhcp_range_start.text(),
            'dhcp_range_end': self.dhcp_range_end.text(),
            'gateway': self.gateway.text(),
            'dns_servers': self.dns_servers.text(),
            'warn_before_attack': self.warn_before_attack.isChecked(),
            'confirm_stop': self.confirm_stop.isChecked(),
            'check_privileges': self.check_privileges.isChecked(),
            'encrypt_logs': self.encrypt_logs.isChecked(),
            'encrypt_captures': self.encrypt_captures.isChecked(),
            'encryption_key': self.encryption_key.text(),
            'log_level': self.log_level.currentText(),
            'log_folder': self.log_folder.text(),
            'log_rotation': self.log_rotation.value(),
            'log_attacks': self.log_attacks.isChecked(),
            'log_errors': self.log_errors.isChecked(),
            'log_traffic': self.log_traffic.isChecked(),
            'detailed_timestamp': self.detailed_timestamp.isChecked()
        }
        
    def apply_settings(self, settings):
        """Applique les paramètres à l'interface"""
        # Application des paramètres généraux
        if 'theme' in settings:
            self.theme_combo.setCurrentText(settings['theme'])
        if 'language' in settings:
            self.language_combo.setCurrentText(settings['language'])
        if 'font_size' in settings:
            self.font_size.setValue(settings['font_size'])
            
        # Application des paramètres réseau
        if 'default_interface' in settings:
            self.default_interface.setCurrentText(settings['default_interface'])
        if 'default_mode' in settings:
            self.default_mode.setCurrentText(settings['default_mode'])
        if 'dhcp_range_start' in settings:
            self.dhcp_range_start.setText(settings['dhcp_range_start'])
        if 'dhcp_range_end' in settings:
            self.dhcp_range_end.setText(settings['dhcp_range_end'])
        if 'gateway' in settings:
            self.gateway.setText(settings['gateway'])
        if 'dns_servers' in settings:
            self.dns_servers.setText(settings['dns_servers'])
            
        # Application des paramètres de sécurité
        if 'warn_before_attack' in settings:
            self.warn_before_attack.setChecked(settings['warn_before_attack'])
        if 'confirm_stop' in settings:
            self.confirm_stop.setChecked(settings['confirm_stop'])
        if 'check_privileges' in settings:
            self.check_privileges.setChecked(settings['check_privileges'])
        if 'encrypt_logs' in settings:
            self.encrypt_logs.setChecked(settings['encrypt_logs'])
        if 'encrypt_captures' in settings:
            self.encrypt_captures.setChecked(settings['encrypt_captures'])
        if 'encryption_key' in settings:
            self.encryption_key.setText(settings['encryption_key'])
            
        # Application des paramètres de logs
        if 'log_level' in settings:
            self.log_level.setCurrentText(settings['log_level'])
        if 'log_folder' in settings:
            self.log_folder.setText(settings['log_folder'])
        if 'log_rotation' in settings:
            self.log_rotation.setValue(settings['log_rotation'])
        if 'log_attacks' in settings:
            self.log_attacks.setChecked(settings['log_attacks'])
        if 'log_errors' in settings:
            self.log_errors.setChecked(settings['log_errors'])
        if 'log_traffic' in settings:
            self.log_traffic.setChecked(settings['log_traffic'])
        if 'detailed_timestamp' in settings:
            self.detailed_timestamp.setChecked(settings['detailed_timestamp'])
            
    def apply_default_settings(self):
        """Applique les paramètres par défaut"""
        # Paramètres par défaut
        default_settings = {
            'theme': 'Clair',
            'language': 'Français',
            'font_size': 10,
            'auto_start': False,
            'minimize_startup': False,
            'check_updates': True,
            'default_interface': 'wlan0',
            'default_mode': 'Managed',
            'dhcp_range_start': '192.168.1.100',
            'dhcp_range_end': '192.168.1.200',
            'gateway': '192.168.1.1',
            'dns_servers': '8.8.8.8, 8.8.4.4',
            'warn_before_attack': True,
            'confirm_stop': True,
            'check_privileges': True,
            'encrypt_logs': False,
            'encrypt_captures': False,
            'encryption_key': '',
            'log_level': 'INFO',
            'log_folder': './logs',
            'log_rotation': 7,
            'log_attacks': True,
            'log_errors': True,
            'log_traffic': False,
            'detailed_timestamp': True
        }
        
        self.apply_settings(default_settings) 