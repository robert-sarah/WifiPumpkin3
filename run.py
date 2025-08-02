#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de lancement WiFiPumpkin3
Détecte automatiquement la plateforme et lance la version appropriée
"""

import sys
import os
import platform
import subprocess

def detect_platform():
    """Détecte la plateforme et retourne la version appropriée"""
    system = platform.system()
    
    if system == "Windows":
        return "windows"
    elif system == "Linux":
        return "linux"
    elif system == "Darwin":  # macOS
        return "macos"
    else:
        return "generic"

def check_python_version():
    """Vérifie la version de Python"""
    if sys.version_info < (3, 7):
        print("❌ Erreur: Python 3.7+ requis")
        print(f"Version actuelle: {sys.version}")
        return False
    return True

def check_dependencies():
    """Vérifie les dépendances de base"""
    try:
        import PyQt5
        return True
    except ImportError:
        print("❌ Erreur: PyQt5 non installé")
        print("Installez avec: pip install PyQt5")
        return False

def launch_application():
    """Lance l'application appropriée"""
    platform_type = detect_platform()
    
    print(f"🖥️  Plateforme détectée: {platform_type}")
    print(f"🐍 Version Python: {sys.version}")
    
    # Vérifications préliminaires
    if not check_python_version():
        return 1
    
    if not check_dependencies():
        return 1
    
    # Sélection du fichier principal
    if platform_type == "windows":
        main_file = "main_windows.py"
        print("🚀 Lancement de la version Windows...")
    else:
        main_file = "main.py"
        print("🚀 Lancement de la version générique...")
    
    # Vérification de l'existence du fichier
    if not os.path.exists(main_file):
        print(f"❌ Erreur: Fichier {main_file} non trouvé")
        return 1
    
    try:
        # Lancement de l'application
        result = subprocess.run([sys.executable, main_file], 
                              capture_output=False, 
                              text=True)
        return result.returncode
    except Exception as e:
        print(f"❌ Erreur lors du lancement: {e}")
        return 1

def main():
    """Point d'entrée principal"""
    print("🎣 WiFiPumpkin3 - Lancement")
    print("=" * 40)
    
    # Vérification des privilèges administrateur
    if platform.system() == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("⚠️  Attention: Privilèges administrateur recommandés")
        except:
            pass
    else:
        if os.geteuid() != 0:
            print("⚠️  Attention: Privilèges root recommandés")
    
    # Lancement de l'application
    return launch_application()

if __name__ == "__main__":
    sys.exit(main())