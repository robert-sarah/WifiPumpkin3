#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFiPumpkin3 - Version Windows
Interface graphique pour les attaques WiFi (Optimisé Windows)
"""

import sys
import os
import platform
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox, QSplashScreen
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QIcon, QFont, QPixmap

# Import des modules personnalisés avec gestion d'erreur
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

class WindowsSplashScreen(QSplashScreen):
    """Écran de démarrage personnalisé pour Windows"""
    
    def __init__(self):
        # Création d'un splash screen simple
        pixmap = QPixmap(400, 300)
        pixmap.fill(Qt.white)
        super().__init__(pixmap)
        
        self.setWindowTitle("WiFiPumpkin3 - Démarrage")
        self.showMessage("Initialisation...", Qt.AlignBottom | Qt.AlignCenter, Qt.black)

class WiFiPumpkin3WindowsApp:
    """Application principale WiFiPumpkin3 optimisée pour Windows"""
    
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.app.setApplicationName("WiFiPumpkin3")
        self.app.setApplicationVersion("3.0.0")
        self.app.setOrganizationName("WiFiPumpkin3")
        
        # Vérification de la plateforme
        if platform.system() != "Windows":
            QMessageBox.warning(None, "Attention", 
                              "Cette version est optimisée pour Windows.\n"
                              "Utilisez main.py pour les autres plateformes.")
        
        # Configuration de l'application
        self.setup_application()
        
        # Affichage du splash screen
        self.splash = WindowsSplashScreen()
        self.splash.show()
        
        # Initialisation des composants
        self.initialize_components()
        
        # Création de la fenêtre principale
        self.main_window = MainWindow(self.network_manager, self.logger, self.config)
        
        # Fermeture du splash screen
        self.splash.finish(self.main_window)
        
    def setup_application(self):
        """Configuration de l'application pour Windows"""
        # Style de l'application
        self.app.setStyle('Fusion')
        
        # Police par défaut pour Windows
        font = QFont("Segoe UI", 9)
        self.app.setFont(font)
        
        # Icône de l'application
        icon_path = os.path.join(os.path.dirname(__file__), "assets", "icon.png")
        if os.path.exists(icon_path):
            self.app.setWindowIcon(QIcon(icon_path))
        
        # Configuration spécifique Windows
        self.setup_windows_specific()
    
    def setup_windows_specific(self):
        """Configuration spécifique à Windows"""
        try:
            # Désactiver les messages d'erreur Windows
            import ctypes
            ctypes.windll.kernel32.SetErrorMode(0x0001)
            
            # Configuration des dpi pour Windows
            self.app.setAttribute(Qt.AA_EnableHighDpiScaling, True)
            self.app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
            
        except Exception as e:
            print(f"Configuration Windows spécifique échouée: {e}")
    
    def initialize_components(self):
        """Initialisation des composants avec progression"""
        try:
            # Mise à jour du splash screen
            self.splash.showMessage("Initialisation du logger...", Qt.AlignBottom | Qt.AlignCenter, Qt.black)
            self.app.processEvents()
            self.logger = Logger()
            
            self.splash.showMessage("Chargement de la configuration...", Qt.AlignBottom | Qt.AlignCenter, Qt.black)
            self.app.processEvents()
            self.config = Config()
            
            self.splash.showMessage("Initialisation du gestionnaire réseau...", Qt.AlignBottom | Qt.AlignCenter, Qt.black)
            self.app.processEvents()
            self.network_manager = NetworkManager()
            
            # Initialisation des nouveaux modules avancés
            if ADVANCED_MODULES_AVAILABLE:
                self.splash.showMessage("Chargement des modules avancés...", Qt.AlignBottom | Qt.AlignCenter, Qt.black)
                self.app.processEvents()
                
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
            
            self.splash.showMessage("Initialisation terminée...", Qt.AlignBottom | Qt.AlignCenter, Qt.black)
            self.app.processEvents()
            
        except Exception as e:
            QMessageBox.critical(None, "Erreur d'Initialisation", 
                               f"Erreur lors de l'initialisation des composants:\n{str(e)}")
            raise
    
    def run(self):
        """Lance l'application"""
        try:
            # Vérification des privilèges administrateur
            if not self.check_admin_privileges():
                QMessageBox.critical(None, "Erreur", 
                                   "WiFiPumpkin3 nécessite des privilèges administrateur pour fonctionner.\n"
                                   "Veuillez exécuter en tant qu'administrateur.")
                return 1
            
            # Vérification des outils système requis
            self.check_windows_requirements()
            
            # Affichage de la fenêtre principale
            self.main_window.show()
            
            # Lancement de l'application
            return self.app.exec_()
            
        except Exception as e:
            QMessageBox.critical(None, "Erreur Critique", 
                               f"Erreur lors du lancement de l'application:\n{str(e)}")
            return 1
    
    def check_windows_requirements(self):
        """Vérifie les outils système requis pour Windows"""
        try:
            import subprocess
            
            # Outils requis pour Windows
            required_tools = [
                'netsh',  # Outil réseau Windows
                'ipconfig',  # Configuration IP
                'ping'  # Test de connectivité
            ]
            
            # Outils optionnels pour les fonctionnalités avancées
            optional_tools = [
                'aircrack-ng',
                'hashcat',
                'openssl'
            ]
            
            missing_required = []
            missing_optional = []
            
            # Vérification des outils requis
            for tool in required_tools:
                try:
                    subprocess.run([tool, '/?'], capture_output=True, timeout=5)
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    missing_required.append(tool)
            
            # Vérification des outils optionnels
            for tool in optional_tools:
                try:
                    subprocess.run([tool, '--version'], capture_output=True, timeout=5)
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    missing_optional.append(tool)
            
            if missing_required:
                self.logger.log("ERROR", f"Outils Windows requis manquants: {', '.join(missing_required)}")
                QMessageBox.warning(None, "Outils Manquants", 
                                  f"Certains outils Windows sont manquants:\n{', '.join(missing_required)}\n"
                                  "L'application peut ne pas fonctionner correctement.")
            
            if missing_optional:
                self.logger.log("WARNING", f"Outils optionnels manquants: {', '.join(missing_optional)}")
                self.logger.log("INFO", "Certaines fonctionnalités avancées peuvent ne pas être disponibles")
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors de la vérification des outils Windows: {str(e)}")
    
    def check_admin_privileges(self):
        """Vérifie si l'application a les privilèges administrateur sur Windows"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            # Fallback pour les autres plateformes
            return os.geteuid() == 0

def main():
    """Point d'entrée principal pour Windows"""
    try:
        app = WiFiPumpkin3WindowsApp()
        sys.exit(app.run())
    except Exception as e:
        QMessageBox.critical(None, "Erreur Fatale", 
                           f"Erreur fatale lors du démarrage:\n{str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 