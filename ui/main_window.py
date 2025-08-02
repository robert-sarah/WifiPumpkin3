#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fenêtre principale de WiFiPumpkin3
Interface graphique avec tous les modules
"""

import os
import sys
from PyQt5.QtWidgets import (QMainWindow, QTabWidget, QVBoxLayout, QHBoxLayout,
                             QWidget, QLabel, QPushButton, QTextEdit, QComboBox,
                             QLineEdit, QSpinBox, QCheckBox, QGroupBox, QGridLayout,
                             QMessageBox, QProgressBar, QTableWidget, QTableWidgetItem,
                             QSplitter, QFrame, QStatusBar, QMenuBar, QMenu, QAction)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QIcon, QPixmap

# Import des modules d'interface
from ui.tabs.evil_twin_tab import EvilTwinTab
from ui.tabs.deauth_tab import DeauthTab
from ui.tabs.probe_tab import ProbeTab
from ui.tabs.captive_portal_tab import CaptivePortalTab
from ui.tabs.wpa_cracking_tab import WPACrackingTab
from ui.dashboard import Dashboard
from ui.tabs.settings_tab import SettingsTab
from ui.tabs.logs_tab import LogsTab

class MainWindow(QMainWindow):
    """Fenêtre principale de l'application"""
    
    def __init__(self, network_manager, logger, config):
        super().__init__()
        self.network_manager = network_manager
        self.logger = logger
        self.config = config
        
        # Initialisation des modules avancés
        self.setup_advanced_modules()
        
        self.setup_ui()
        self.setup_menu()
        self.setup_status_bar()
        
    def setup_ui(self):
        """Configuration de l'interface utilisateur"""
        self.setWindowTitle("WiFiPumpkin3 - Outil de Test de Sécurité WiFi")
        self.setGeometry(100, 100, 1200, 800)
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout principal
        main_layout = QVBoxLayout(central_widget)
        
        # En-tête
        self.setup_header(main_layout)
        
        # Onglets principaux
        self.setup_tabs(main_layout)
        
        # Barre de statut
        self.setup_status_bar()
        
    def setup_header(self, layout):
        """Configuration de l'en-tête"""
        header_frame = QFrame()
        header_frame.setFrameStyle(QFrame.StyledPanel)
        header_layout = QHBoxLayout(header_frame)
        
        # Logo et titre
        title_label = QLabel("WiFiPumpkin3")
        title_font = QFont("Arial", 16, QFont.Bold)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #2c3e50;")
        
        # Informations système
        system_info = QLabel(f"Interface: {self.network_manager.get_primary_interface()}")
        system_info.setStyleSheet("color: #7f8c8d;")
        
        # Boutons de contrôle
        start_btn = QPushButton("Démarrer")
        start_btn.setStyleSheet("""
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
        start_btn.clicked.connect(self.start_attack)
        
        stop_btn = QPushButton("Arrêter")
        stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        stop_btn.clicked.connect(self.stop_attack)
        
        # Ajout des éléments à l'en-tête
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(system_info)
        header_layout.addWidget(start_btn)
        header_layout.addWidget(stop_btn)
        
        layout.addWidget(header_frame)
        
    def setup_tabs(self, layout):
        """Configuration des onglets"""
        self.tab_widget = QTabWidget()
        
        # Création des onglets
        self.dashboard_tab = Dashboard(self.logger)
        self.evil_twin_tab = EvilTwinTab(self.network_manager, self.logger)
        self.deauth_tab = DeauthTab(self.network_manager, self.logger)
        self.probe_tab = ProbeTab(self.network_manager, self.logger)
        self.captive_portal_tab = CaptivePortalTab(self.network_manager, self.logger)
        self.wpa_cracking_tab = WPACrackingTab(self.network_manager, self.logger)
        self.settings_tab = SettingsTab(self.config)
        self.logs_tab = LogsTab(self.logger)
        
        # Ajout des onglets
        self.tab_widget.addTab(self.dashboard_tab, "📊 Dashboard")
        self.tab_widget.addTab(self.evil_twin_tab, "Evil Twin")
        self.tab_widget.addTab(self.deauth_tab, "Deauth Attack")
        self.tab_widget.addTab(self.probe_tab, "Probe Request")
        self.tab_widget.addTab(self.captive_portal_tab, "Captive Portal")
        self.tab_widget.addTab(self.wpa_cracking_tab, "🔓 WPA Cracking")
        self.tab_widget.addTab(self.settings_tab, "Paramètres")
        self.tab_widget.addTab(self.logs_tab, "Logs")
        
        layout.addWidget(self.tab_widget)
        
    def setup_advanced_modules(self):
        """Initialise les modules avancés"""
        try:
            # Import des modules avancés
            from core.attacks.wpa_cracker import WPACracker
            from core.attacks.dns_spoof import DNSSpoofer
            from core.stealth.anti_detection import AntiDetection
            
            # Initialisation des modules
            self.wpa_cracker = WPACracker(self.logger)
            self.dns_spoofer = DNSSpoofer(self.logger)
            self.anti_detection = AntiDetection(self.logger)
            
            self.logger.log("INFO", "Modules avancés initialisés avec succès")
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors de l'initialisation des modules avancés: {str(e)}")
        
    def setup_menu(self):
        """Configuration du menu"""
        menubar = self.menuBar()
        
        # Menu Fichier
        file_menu = menubar.addMenu('Fichier')
        
        exit_action = QAction('Quitter', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Menu Outils
        tools_menu = menubar.addMenu('Outils')
        
        scan_action = QAction('Scanner les réseaux', self)
        scan_action.triggered.connect(self.scan_networks)
        tools_menu.addAction(scan_action)
        
        # Menu des modules avancés
        advanced_menu = menubar.addMenu('Modules Avancés')
        
        # WPA Cracking
        wpa_action = QAction('WPA Cracking', self)
        wpa_action.triggered.connect(self.open_wpa_cracking)
        advanced_menu.addAction(wpa_action)
        
        # DNS Spoofing
        dns_action = QAction('DNS Spoofing', self)
        dns_action.triggered.connect(self.open_dns_spoofing)
        advanced_menu.addAction(dns_action)
        
        # Anti-Détection
        stealth_action = QAction('Mode Furtif', self)
        stealth_action.triggered.connect(self.toggle_stealth_mode)
        advanced_menu.addAction(stealth_action)
        
        # Dashboard
        dashboard_action = QAction('Dashboard', self)
        dashboard_action.triggered.connect(self.open_dashboard)
        advanced_menu.addAction(dashboard_action)
        
        # Menu Aide
        help_menu = menubar.addMenu('Aide')
        
        about_action = QAction('À propos', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def setup_status_bar(self):
        """Configuration de la barre de statut"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Indicateurs de statut
        self.status_label = QLabel("Prêt")
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        self.status_bar.addWidget(self.status_label)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
    def start_attack(self):
        """Démarre l'attaque sélectionnée"""
        current_tab = self.tab_widget.currentWidget()
        
        if hasattr(current_tab, 'start_attack'):
            try:
                current_tab.start_attack()
                self.status_label.setText("Attaque en cours...")
                self.progress_bar.setVisible(True)
                self.progress_bar.setRange(0, 0)  # Indéterminé
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Erreur lors du démarrage de l'attaque:\n{str(e)}")
        else:
            QMessageBox.information(self, "Information", "Cette fonctionnalité n'est pas encore implémentée.")
            
    def stop_attack(self):
        """Arrête l'attaque en cours"""
        current_tab = self.tab_widget.currentWidget()
        
        if hasattr(current_tab, 'stop_attack'):
            try:
                current_tab.stop_attack()
                self.status_label.setText("Attaque arrêtée")
                self.progress_bar.setVisible(False)
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Erreur lors de l'arrêt de l'attaque:\n{str(e)}")
        else:
            QMessageBox.information(self, "Information", "Aucune attaque en cours.")
            
    def scan_networks(self):
        """Scanne les réseaux WiFi disponibles"""
        try:
            networks = self.network_manager.scan_networks()
            self.evil_twin_tab.update_networks_list(networks)
            self.status_label.setText(f"{len(networks)} réseaux trouvés")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors du scan:\n{str(e)}")
    
    def open_wpa_cracking(self):
        """Ouvre l'onglet WPA Cracking"""
        try:
            # Changement vers l'onglet WPA Cracking
            for i in range(self.tab_widget.count()):
                if "WPA Cracking" in self.tab_widget.tabText(i):
                    self.tab_widget.setCurrentIndex(i)
                    break
            self.logger.log("INFO", "Onglet WPA Cracking ouvert")
        except Exception as e:
            self.logger.log("ERROR", f"Erreur ouverture WPA Cracking: {str(e)}")
    
    def open_dns_spoofing(self):
        """Ouvre l'onglet DNS Spoofing"""
        try:
            # Changement vers l'onglet DNS Spoofing (si disponible)
            self.logger.log("INFO", "Fonctionnalité DNS Spoofing accessible via l'interface")
        except Exception as e:
            self.logger.log("ERROR", f"Erreur ouverture DNS Spoofing: {str(e)}")
    
    def toggle_stealth_mode(self):
        """Active/désactive le mode furtif"""
        try:
            if hasattr(self, 'anti_detection'):
                # Interface pour activer le mode furtif
                interface = self.network_manager.get_primary_interface()
                if interface:
                    self.anti_detection.setup_stealth_mode(interface)
                    self.logger.log("INFO", "Mode furtif activé")
                    QMessageBox.information(self, "Mode Furtif", "Mode furtif activé avec succès")
                else:
                    QMessageBox.warning(self, "Attention", "Aucune interface WiFi détectée")
            else:
                QMessageBox.warning(self, "Attention", "Module anti-détection non disponible")
        except Exception as e:
            self.logger.log("ERROR", f"Erreur mode furtif: {str(e)}")
            QMessageBox.critical(self, "Erreur", f"Erreur lors de l'activation du mode furtif:\n{str(e)}")
    
    def open_dashboard(self):
        """Ouvre l'onglet Dashboard"""
        try:
            # Changement vers l'onglet Dashboard
            for i in range(self.tab_widget.count()):
                if "Dashboard" in self.tab_widget.tabText(i):
                    self.tab_widget.setCurrentIndex(i)
                    break
            self.logger.log("INFO", "Dashboard ouvert")
        except Exception as e:
            self.logger.log("ERROR", f"Erreur ouverture Dashboard: {str(e)}")
            
    def show_about(self):
        """Affiche la boîte de dialogue À propos"""
        QMessageBox.about(self, "À propos de WiFiPumpkin3",
                         "WiFiPumpkin3 v3.0.0\n\n"
                         "Outil de test de sécurité WiFi avancé\n"
                         "Développé avec PyQt5\n\n"
                         "🚀 Nouvelles fonctionnalités:\n"
                         "• WPA/WPA2 Cracking\n"
                         "• DNS Spoofing\n"
                         "• Mode Furtif\n"
                         "• Dashboard Temps Réel\n"
                         "• SSL/TLS Support\n\n"
                         "⚠️ Utilisez uniquement sur vos propres réseaux !") 