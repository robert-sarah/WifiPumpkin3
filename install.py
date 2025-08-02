 #!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script d'installation pour WiFiPumpkin3
"""

import os
import sys
import subprocess
import platform

def check_python_version():
    """Vérifie la version de Python"""
    if sys.version_info < (3, 7):
        print("❌ Python 3.7+ requis")
        return False
    print("✅ Version Python compatible")
    return True

def check_admin_privileges():
    """Vérifie les privilèges administrateur"""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:  # Linux/Mac
            return os.geteuid() == 0
    except:
        return False

def install_dependencies():
    """Installe les dépendances Python"""
    try:
        print("📦 Installation des dépendances...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dépendances installées")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur lors de l'installation: {e}")
        return False

def create_directories():
    """Crée les répertoires nécessaires"""
    directories = [
        "config",
        "logs", 
        "assets",
        "captures"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Répertoire créé: {directory}")

def check_system_requirements():
    """Vérifie les prérequis système"""
    print("🔍 Vérification des prérequis système...")
    
    # Vérification de la version Python
    if not check_python_version():
        return False
    
    # Vérification des privilèges
    if not check_admin_privileges():
        print("⚠️  Privilèges administrateur recommandés")
    
    # Vérification du système d'exploitation
    system = platform.system()
    if system not in ['Linux', 'Darwin']:
        print(f"⚠️  Système non testé: {system}")
    
    print("✅ Prérequis système vérifiés")
    return True

def install_system_tools():
    """Installe les outils système nécessaires"""
    system = platform.system()
    
    if system == 'Linux':
        print("🔧 Installation des outils système Linux...")
        tools = [
            "iwconfig",
            "iwlist", 
            "aircrack-ng",
            "dhcpd"
        ]
        
        for tool in tools:
            try:
                subprocess.run(["which", tool], check=True, capture_output=True)
                print(f"✅ {tool} trouvé")
            except subprocess.CalledProcessError:
                print(f"⚠️  {tool} non trouvé - installation manuelle requise")
    
    elif system == 'Darwin':  # macOS
        print("🔧 Installation des outils système macOS...")
        try:
            subprocess.run(["brew", "install", "aircrack-ng"], check=True)
            print("✅ Outils système installés")
        except subprocess.CalledProcessError:
            print("⚠️  Installation manuelle des outils requise")

def main():
    """Fonction principale d'installation"""
    print("🚀 Installation de WiFiPumpkin3")
    print("=" * 40)
    
    # Vérification des prérequis
    if not check_system_requirements():
        print("❌ Prérequis non satisfaits")
        sys.exit(1)
    
    # Installation des dépendances Python
    if not install_dependencies():
        print("❌ Échec de l'installation des dépendances")
        sys.exit(1)
    
    # Création des répertoires
    print("📁 Création des répertoires...")
    create_directories()
    
    # Installation des outils système
    install_system_tools()
    
    print("\n✅ Installation terminée!")
    print("\nPour lancer l'application:")
    print("  python main.py")
    print("  ou")
    print("  python run.py")
    
    print("\n⚠️  RAPPEL: Utilisez ce logiciel de manière responsable et éthique!")

if __name__ == "__main__":
    main()