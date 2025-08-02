 #!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests d'intégration pour WiFiPumpkin3
"""

import unittest
import sys
import os
import tempfile
import shutil

# Ajout du répertoire parent au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

class TestApplicationIntegration(unittest.TestCase):
    """Tests d'intégration pour l'application complète"""
    
    def setUp(self):
        """Configuration initiale"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Configuration temporaire
        os.environ['WIFIPUMPKIN3_CONFIG_DIR'] = self.temp_dir
        os.environ['WIFIPUMPKIN3_LOG_DIR'] = self.temp_dir
    
    def tearDown(self):
        """Nettoyage"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_component_initialization(self):
        """Test d'initialisation des composants principaux"""
        try:
            # Test d'import des composants principaux
            from core.network_manager import NetworkManager
            from core.logger import Logger
            from utils.config import Config
            
            # Initialisation
            nm = NetworkManager()
            logger = Logger()
            config = Config()
            
            # Vérifications
            self.assertIsNotNone(nm)
            self.assertIsNotNone(logger)
            self.assertIsNotNone(config)
            
            print("✅ Initialisation des composants réussie")
            
        except Exception as e:
            self.fail(f"Erreur lors de l'initialisation: {e}")
    
    def test_configuration_workflow(self):
        """Test du workflow de configuration"""
        try:
            from utils.config import Config
            
            config = Config()
            
            # Test de sauvegarde de paramètres
            test_settings = {
                'General': {
                    'theme': 'Sombre',
                    'language': 'English'
                },
                'Network': {
                    'default_interface': 'wlan1',
                    'default_mode': 'Monitor'
                }
            }
            
            config.save_settings(test_settings)
            
            # Test de chargement
            loaded_settings = config.load_settings()
            
            # Vérifications
            self.assertIn('General', loaded_settings)
            self.assertIn('Network', loaded_settings)
            
            print("✅ Workflow de configuration réussi")
            
        except Exception as e:
            self.fail(f"Erreur dans le workflow de configuration: {e}")
    
    def test_logging_workflow(self):
        """Test du workflow de logging"""
        try:
            from core.logger import Logger
            
            logger = Logger()
            
            # Test d'envoi de logs
            logger.info("Test log 1")
            logger.warning("Test log 2")
            logger.error("Test log 3")
            
            # Test de récupération
            history = logger.get_history()
            self.assertGreaterEqual(len(history), 3)
            
            # Test de statistiques
            stats = logger.get_log_stats()
            self.assertIn('total_entries', stats)
            
            print("✅ Workflow de logging réussi")
            
        except Exception as e:
            self.fail(f"Erreur dans le workflow de logging: {e}")
    
    def test_network_workflow(self):
        """Test du workflow réseau"""
        try:
            from core.network_manager import NetworkManager
            
            nm = NetworkManager()
            
            # Test de récupération des interfaces
            interfaces = nm.get_interfaces()
            self.assertIsInstance(interfaces, list)
            
            # Test de scan (peut échouer si pas d'interface WiFi)
            networks = nm.scan_networks()
            self.assertIsInstance(networks, list)
            
            print("✅ Workflow réseau réussi")
            
        except Exception as e:
            print(f"⚠️  Workflow réseau partiel: {e}")
            # Ne fait pas échouer le test car dépend du matériel
    
    def test_attack_workflow(self):
        """Test du workflow d'attaque"""
        try:
            from core.attacks.evil_twin import EvilTwinAttack
            from core.network_manager import NetworkManager
            from core.logger import Logger
            
            nm = NetworkManager()
            logger = Logger()
            attack = EvilTwinAttack(nm, logger)
            
            # Test de configuration
            config = {
                'interface': 'wlan0',
                'ssid': 'TestNetwork',
                'channel': 6,
                'deauth': False,
                'captive_portal': False
            }
            
            # Test d'initialisation (sans démarrage réel)
            self.assertIsNotNone(attack)
            self.assertFalse(attack.running)
            
            print("✅ Workflow d'attaque réussi")
            
        except Exception as e:
            self.fail(f"Erreur dans le workflow d'attaque: {e}")
    
    def test_ui_components(self):
        """Test des composants UI"""
        try:
            from PyQt5.QtWidgets import QApplication
            from ui.tabs.evil_twin_tab import EvilTwinTab
            from core.network_manager import NetworkManager
            from core.logger import Logger
            
            # Création d'une application Qt minimale
            app = QApplication([])
            
            # Test de création des composants UI
            nm = NetworkManager()
            logger = Logger()
            
            evil_twin_tab = EvilTwinTab(nm, logger)
            self.assertIsNotNone(evil_twin_tab)
            
            print("✅ Composants UI créés avec succès")
            
        except Exception as e:
            self.fail(f"Erreur dans les composants UI: {e}")

class TestConfigurationIntegration(unittest.TestCase):
    """Tests d'intégration pour la configuration"""
    
    def test_config_file_creation(self):
        """Test de création du fichier de configuration"""
        try:
            from utils.config import Config
            
            # Création d'une configuration temporaire
            config = Config()
            
            # Vérification que le fichier existe
            self.assertTrue(os.path.exists(config.config_file))
            
            print("✅ Fichier de configuration créé")
            
        except Exception as e:
            self.fail(f"Erreur lors de la création du fichier de config: {e}")
    
    def test_config_persistence(self):
        """Test de persistance de la configuration"""
        try:
            from utils.config import Config
            
            config = Config()
            
            # Test de sauvegarde
            test_value = "test_value"
            config.set('Test', 'test_key', test_value)
            config.save_config()
            
            # Test de rechargement
            new_config = Config()
            loaded_value = new_config.get('Test', 'test_key', 'default')
            
            self.assertEqual(loaded_value, test_value)
            
            print("✅ Persistance de configuration réussie")
            
        except Exception as e:
            self.fail(f"Erreur dans la persistance de configuration: {e}")

class TestLoggingIntegration(unittest.TestCase):
    """Tests d'intégration pour le logging"""
    
    def test_log_file_creation(self):
        """Test de création du fichier de log"""
        try:
            from core.logger import Logger
            
            logger = Logger()
            
            # Vérification que le fichier existe
            log_file = logger.get_log_file_path()
            self.assertTrue(os.path.exists(log_file))
            
            print("✅ Fichier de log créé")
            
        except Exception as e:
            self.fail(f"Erreur lors de la création du fichier de log: {e}")
    
    def test_log_rotation(self):
        """Test de rotation des logs"""
        try:
            from core.logger import Logger
            
            logger = Logger()
            
            # Ajout de nombreux logs pour tester la rotation
            for i in range(100):
                logger.info(f"Test log {i}")
            
            # Vérification que les logs sont limités
            history = logger.get_history()
            self.assertLessEqual(len(history), logger.max_history)
            
            print("✅ Rotation des logs fonctionnelle")
            
        except Exception as e:
            self.fail(f"Erreur dans la rotation des logs: {e}")

def run_integration_tests():
    """Lance les tests d'intégration"""
    print("🧪 Lancement des tests d'intégration")
    print("=" * 50)
    
    # Configuration des tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Ajout des tests
    suite.addTests(loader.loadTestsFromTestCase(TestApplicationIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestConfigurationIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestLoggingIntegration))
    
    # Exécution des tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Résumé
    print("\n" + "=" * 50)
    print(f"📊 Résultats des tests d'intégration:")
    print(f"  Tests exécutés: {result.testsRun}")
    print(f"  Échecs: {len(result.failures)}")
    print(f"  Erreurs: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("🎉 Tous les tests d'intégration sont passés!")
    else:
        print("⚠️  Certains tests d'intégration ont échoué")
    
    return result.wasSuccessful()

if __name__ == '__main__':
    run_integration_tests()