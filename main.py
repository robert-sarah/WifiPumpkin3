#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFiPumpkin3 - Clone avec PyQt5
Interface graphique pour les attaques WiFi
"""

import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QIcon, QFont

# Import des modules personnalisés
try:
    from ui.main_window import MainWindow
    from core.network_manager import NetworkManager
    from core.logger import Logger
    from utils.config import Config
except ImportError as e:
    print(f"Erreur d'import: {e}")
    print("Vérifiez que tous les modules sont présents")
    sys.exit(1)

# Import des nouveaux modules avancés avec gestion d'erreur
try:
    from core.attacks.wpa_cracker import WPACracker
    from core.attacks.dns_spoof import DNSSpoofer
    from core.stealth.anti_detection import AntiDetection
    from ui.dashboard import Dashboard
    ADVANCED_MODULES_AVAILABLE = True
except ImportError as e:
    print(f"Modules avancés non disponibles: {e}")
    ADVANCED_MODULES_AVAILABLE = False

class WiFiPumpkin3App:
    """Application principale WiFiPumpkin3"""
    
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.app.setApplicationName("WiFiPumpkin3")
        self.app.setApplicationVersion("3.0.0")
        self.app.setOrganizationName("WiFiPumpkin3")
        
        # Configuration de l'application
        self.setup_application()
        
        # Initialisation des composants
        self.logger = Logger()
        self.config = Config()
        self.network_manager = NetworkManager()
        
        # Initialisation des nouveaux modules avancés
        if ADVANCED_MODULES_AVAILABLE:
            try:
                self.wpa_cracker = WPACracker(self.logger)
                self.dns_spoofer = DNSSpoofer(self.logger)
                self.anti_detection = AntiDetection(self.logger)
                self.dashboard = Dashboard(self.logger)
                self.logger.log("INFO", "Modules avancés initialisés avec succès")
            except Exception as e:
                self.logger.log("ERROR", f"Erreur lors de l'initialisation des modules avancés: {str(e)}")
                self.wpa_cracker = None
                self.dns_spoofer = None
                self.anti_detection = None
                self.dashboard = None
        else:
            self.wpa_cracker = None
            self.dns_spoofer = None
            self.anti_detection = None
            self.dashboard = None
            self.logger.log("WARNING", "Modules avancés non disponibles")
        
        # Création de la fenêtre principale
        self.main_window = MainWindow(self.network_manager, self.logger, self.config)
        
    def setup_application(self):
        """Configuration de l'application"""
        # Style de l'application
        self.app.setStyle('Fusion')
        
        # Police par défaut
        font = QFont("Segoe UI", 9)
        self.app.setFont(font)
        
        # Icône de l'application
        icon_path = os.path.join(os.path.dirname(__file__), "assets", "icon.png")
        if os.path.exists(icon_path):
            self.app.setWindowIcon(QIcon(icon_path))
    
    def run(self):
        """Lance l'application"""
        try:
            # Vérification des privilèges administrateur
            if not self.check_admin_privileges():
                QMessageBox.critical(None, "Erreur", 
                                   "WiFiPumpkin3 nécessite des privilèges administrateur pour fonctionner.")
                return 1
            
            # Initialisation des modules avancés
            self.logger.log("INFO", "Initialisation des modules avancés...")
            
            # Vérification des outils système requis
            self.check_system_requirements()
            
            # Affichage de la fenêtre principale
            self.main_window.show()
            
            # Lancement de l'application
            return self.app.exec_()
            
        except Exception as e:
            QMessageBox.critical(None, "Erreur Critique", 
                               f"Erreur lors du lancement de l'application:\n{str(e)}")
            return 1
    
    def check_system_requirements(self):
        """Vérifie les outils système requis"""
        try:
            import subprocess
            
            # Outils requis pour les nouvelles fonctionnalités
            required_tools = [
                'aircrack-ng',
                'hashcat',
                'dnsmasq',
                'openssl',
                'iptables'
            ]
            
            missing_tools = []
            for tool in required_tools:
                try:
                    subprocess.run([tool, '--version'], capture_output=True, timeout=5)
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    missing_tools.append(tool)
            
            if missing_tools:
                self.logger.log("WARNING", f"Outils manquants: {', '.join(missing_tools)}")
                self.logger.log("INFO", "Certaines fonctionnalités avancées peuvent ne pas être disponibles")
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors de la vérification des outils: {str(e)}")
    
    def check_admin_privileges(self):
        """Vérifie si l'application a les privilèges administrateur"""
        try:
            # Sur Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            # Sur Linux/Mac
            return os.geteuid() == 0

def main():
    """Point d'entrée principal"""
    app = WiFiPumpkin3App()
    sys.exit(app.run())

if __name__ == "__main__":
    main() 