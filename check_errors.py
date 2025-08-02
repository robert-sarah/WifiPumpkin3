#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de vérification des erreurs WiFiPumpkin3
Diagnostique les problèmes courants et propose des solutions
"""

import sys
import os
import platform
import subprocess
import importlib

class ErrorChecker:
    """Classe pour vérifier et diagnostiquer les erreurs"""
    
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.fixes = []
    
    def check_python_version(self):
        """Vérifie la version de Python"""
        if sys.version_info < (3, 7):
            self.errors.append("Python 3.7+ requis")
            self.fixes.append("Mettez à jour Python vers la version 3.7 ou supérieure")
        else:
            print(f"✅ Version Python: {sys.version}")
    
    def check_dependencies(self):
        """Vérifie les dépendances principales"""
        required_modules = [
            'PyQt5',
            'scapy',
            'netifaces',
            'psutil',
            'requests',
            'flask',
            'flask_cors'
        ]
        
        for module in required_modules:
            try:
                importlib.import_module(module)
                print(f"✅ {module} installé")
            except ImportError:
                self.errors.append(f"{module} non installé")
                self.fixes.append(f"Installez {module}: pip install {module}")
    
    def check_file_structure(self):
        """Vérifie la structure des fichiers"""
        required_files = [
            'main.py',
            'main_windows.py',
            'requirements.txt',
            'README.md'
        ]
        
        required_dirs = [
            'core',
            'ui',
            'utils',
            'templates',
            'config'
        ]
        
        for file in required_files:
            if not os.path.exists(file):
                self.errors.append(f"Fichier manquant: {file}")
                self.fixes.append(f"Créez le fichier {file}")
            else:
                print(f"✅ Fichier présent: {file}")
        
        for directory in required_dirs:
            if not os.path.isdir(directory):
                self.errors.append(f"Dossier manquant: {directory}")
                self.fixes.append(f"Créez le dossier {directory}")
            else:
                print(f"✅ Dossier présent: {directory}")
    
    def check_core_modules(self):
        """Vérifie les modules core"""
        core_modules = [
            'core.network_manager',
            'core.logger',
            'core.captive_portal_server'
        ]
        
        for module in core_modules:
            try:
                importlib.import_module(module)
                print(f"✅ Module core: {module}")
            except ImportError as e:
                self.errors.append(f"Module core manquant: {module}")
                self.fixes.append(f"Vérifiez le fichier {module.replace('.', '/')}.py")
    
    def check_ui_modules(self):
        """Vérifie les modules UI"""
        ui_modules = [
            'ui.main_window',
            'ui.dashboard'
        ]
        
        for module in ui_modules:
            try:
                importlib.import_module(module)
                print(f"✅ Module UI: {module}")
            except ImportError as e:
                self.errors.append(f"Module UI manquant: {module}")
                self.fixes.append(f"Vérifiez le fichier {module.replace('.', '/')}.py")
    
    def check_attack_modules(self):
        """Vérifie les modules d'attaques"""
        attack_modules = [
            'core.attacks.evil_twin',
            'core.attacks.deauth_attack',
            'core.attacks.wpa_cracker',
            'core.attacks.dns_spoof'
        ]
        
        for module in attack_modules:
            try:
                importlib.import_module(module)
                print(f"✅ Module d'attaque: {module}")
            except ImportError as e:
                self.warnings.append(f"Module d'attaque manquant: {module}")
                self.fixes.append(f"Vérifiez le fichier {module.replace('.', '/')}.py")
    
    def check_system_tools(self):
        """Vérifie les outils système"""
        system_tools = [
            'aircrack-ng',
            'hashcat',
            'dnsmasq',
            'openssl',
            'iptables'
        ]
        
        for tool in system_tools:
            try:
                subprocess.run([tool, '--version'], capture_output=True, timeout=5)
                print(f"✅ Outil système: {tool}")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                self.warnings.append(f"Outil système manquant: {tool}")
                self.fixes.append(f"Installez {tool} via votre gestionnaire de paquets")
    
    def check_permissions(self):
        """Vérifie les permissions"""
        if platform.system() == "Windows":
            try:
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    self.warnings.append("Privilèges administrateur recommandés")
                    self.fixes.append("Exécutez en tant qu'administrateur")
                else:
                    print("✅ Privilèges administrateur")
            except:
                pass
        else:
            if os.geteuid() != 0:
                self.warnings.append("Privilèges root recommandés")
                self.fixes.append("Exécutez avec sudo")
            else:
                print("✅ Privilèges root")
    
    def check_network_interface(self):
        """Vérifie l'interface réseau"""
        try:
            import netifaces
            interfaces = netifaces.interfaces()
            if interfaces:
                print(f"✅ Interfaces réseau détectées: {len(interfaces)}")
            else:
                self.warnings.append("Aucune interface réseau détectée")
        except ImportError:
            self.warnings.append("Module netifaces non disponible")
    
    def run_all_checks(self):
        """Exécute toutes les vérifications"""
        print("🔍 Vérification des erreurs WiFiPumpkin3")
        print("=" * 50)
        
        self.check_python_version()
        self.check_dependencies()
        self.check_file_structure()
        self.check_core_modules()
        self.check_ui_modules()
        self.check_attack_modules()
        self.check_system_tools()
        self.check_permissions()
        self.check_network_interface()
        
        self.print_report()
    
    def print_report(self):
        """Affiche le rapport de vérification"""
        print("\n" + "=" * 50)
        print("📊 RAPPORT DE VÉRIFICATION")
        print("=" * 50)
        
        if not self.errors and not self.warnings:
            print("🎉 Aucune erreur détectée ! Le projet est prêt.")
            return
        
        if self.errors:
            print("\n❌ ERREURS CRITIQUES:")
            for i, error in enumerate(self.errors, 1):
                print(f"  {i}. {error}")
                if i <= len(self.fixes):
                    print(f"     💡 Solution: {self.fixes[i-1]}")
        
        if self.warnings:
            print("\n⚠️  AVERTISSEMENTS:")
            for i, warning in enumerate(self.warnings, 1):
                print(f"  {i}. {warning}")
                if len(self.errors) + i <= len(self.fixes):
                    print(f"     💡 Solution: {self.fixes[len(self.errors) + i - 1]}")
        
        print("\n🔧 ACTIONS RECOMMANDÉES:")
        print("1. Installez les dépendances: pip install -r requirements.txt")
        print("2. Vérifiez les privilèges administrateur")
        print("3. Installez les outils système manquants")
        print("4. Relancez l'application: python run.py")

def main():
    """Point d'entrée principal"""
    checker = ErrorChecker()
    checker.run_all_checks()

if __name__ == "__main__":
    main() 