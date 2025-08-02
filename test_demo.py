 #!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de test/démo pour WiFiPumpkin3
"""

import sys
import os
import time
from datetime import datetime

# Ajout du répertoire courant au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Teste les imports des modules"""
    print("🔍 Test des imports...")
    
    try:
        from core.network_manager import NetworkManager
        print("✅ NetworkManager importé")
    except ImportError as e:
        print(f"❌ Erreur import NetworkManager: {e}")
        return False
    
    try:
        from core.logger import Logger
        print("✅ Logger importé")
    except ImportError as e:
        print(f"❌ Erreur import Logger: {e}")
        return False
    
    try:
        from utils.config import Config
        print("✅ Config importé")
    except ImportError as e:
        print(f"❌ Erreur import Config: {e}")
        return False
    
    try:
        from ui.main_window import MainWindow
        print("✅ MainWindow importé")
    except ImportError as e:
        print(f"❌ Erreur import MainWindow: {e}")
        return False
    
    return True

def test_network_manager():
    """Teste le gestionnaire de réseau"""
    print("\n🔍 Test du NetworkManager...")
    
    try:
        from core.network_manager import NetworkManager
        
        nm = NetworkManager()
        interfaces = nm.get_interfaces()
        
        print(f"✅ Interfaces détectées: {interfaces}")
        
        if interfaces:
            primary = nm.get_primary_interface()
            print(f"✅ Interface principale: {primary}")
        else:
            print("⚠️  Aucune interface WiFi détectée")
        
        return True
    except Exception as e:
        print(f"❌ Erreur NetworkManager: {e}")
        return False

def test_logger():
    """Teste le système de logging"""
    print("\n🔍 Test du Logger...")
    
    try:
        from core.logger import Logger
        
        logger = Logger()
        
        # Test des différents niveaux
        logger.debug("Test message DEBUG")
        logger.info("Test message INFO")
        logger.warning("Test message WARNING")
        logger.error("Test message ERROR")
        
        print("✅ Messages de log envoyés")
        
        # Test des statistiques
        stats = logger.get_log_stats()
        print(f"✅ Statistiques récupérées: {stats['total_entries']} entrées")
        
        return True
    except Exception as e:
        print(f"❌ Erreur Logger: {e}")
        return False

def test_config():
    """Teste le système de configuration"""
    print("\n🔍 Test du Config...")
    
    try:
        from utils.config import Config
        
        config = Config()
        
        # Test de récupération de paramètres
        theme = config.get('General', 'theme', 'Clair')
        print(f"✅ Thème récupéré: {theme}")
        
        # Test de modification
        config.set('General', 'test_param', 'test_value')
        test_value = config.get('General', 'test_param', 'default')
        print(f"✅ Paramètre testé: {test_value}")
        
        # Test des configurations spécialisées
        network_config = config.get_network_config()
        print(f"✅ Configuration réseau: {network_config['default_interface']}")
        
        return True
    except Exception as e:
        print(f"❌ Erreur Config: {e}")
        return False

def test_ui_components():
    """Teste les composants de l'interface"""
    print("\n🔍 Test des composants UI...")
    
    try:
        from PyQt5.QtWidgets import QApplication
        from ui.tabs.evil_twin_tab import EvilTwinTab
        from core.network_manager import NetworkManager
        from core.logger import Logger
        
        # Création d'une application Qt minimale
        app = QApplication([])
        
        # Test de création des onglets
        nm = NetworkManager()
        logger = Logger()
        
        evil_twin_tab = EvilTwinTab(nm, logger)
        print("✅ Onglet Evil Twin créé")
        
        return True
    except Exception as e:
        print(f"❌ Erreur UI: {e}")
        return False

def demo_network_scan():
    """Démo du scan de réseaux"""
    print("\n🔍 Démo du scan de réseaux...")
    
    try:
        from core.network_manager import NetworkManager
        
        nm = NetworkManager()
        networks = nm.scan_networks()
        
        print(f"✅ {len(networks)} réseaux trouvés:")
        for i, network in enumerate(networks[:3], 1):  # Affiche les 3 premiers
            print(f"  {i}. {network['ssid']} ({network['bssid']}) - Canal {network['channel']}")
        
        return True
    except Exception as e:
        print(f"❌ Erreur scan: {e}")
        return False

def main():
    """Fonction principale de test"""
    print("🧪 Tests de WiFiPumpkin3")
    print("=" * 40)
    
    tests = [
        ("Imports", test_imports),
        ("NetworkManager", test_network_manager),
        ("Logger", test_logger),
        ("Config", test_config),
        ("UI Components", test_ui_components),
        ("Network Scan Demo", demo_network_scan)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: SUCCÈS")
            else:
                print(f"❌ {test_name}: ÉCHEC")
        except Exception as e:
            print(f"❌ {test_name}: ERREUR - {e}")
    
    print(f"\n{'='*50}")
    print(f"📊 Résultats: {passed}/{total} tests réussis")
    
    if passed == total:
        print("🎉 Tous les tests sont passés!")
        print("\n✅ L'application est prête à être utilisée")
    else:
        print("⚠️  Certains tests ont échoué")
        print("🔧 Vérifiez les dépendances et la configuration")
    
    print("\n🚀 Pour lancer l'application:")
    print("  python main.py")

if __name__ == "__main__":
    main()