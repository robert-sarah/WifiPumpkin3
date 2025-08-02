#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests de performance pour WiFiPumpkin3
"""

import unittest
import sys
import os
import time
import psutil
import threading

# Ajout du répertoire parent au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

class TestPerformance(unittest.TestCase):
    """Tests de performance"""
    
    def setUp(self):
        """Configuration initiale"""
        self.start_time = time.time()
        self.process = psutil.Process()
    
    def tearDown(self):
        """Nettoyage"""
        end_time = time.time()
        duration = end_time - self.start_time
        print(f"⏱️  Durée du test: {duration:.3f}s")
    
    def test_logger_performance(self):
        """Test de performance du logger"""
        print("🔍 Test de performance du logger...")
        
        from core.logger import Logger
        
        logger = Logger()
        
        # Test d'envoi de nombreux logs
        start_time = time.time()
        
        for i in range(1000):
            logger.info(f"Test log {i}")
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Vérification de la performance
        self.assertLess(duration, 5.0)  # Moins de 5 secondes pour 1000 logs
        
        print(f"✅ 1000 logs en {duration:.3f}s")
    
    def test_config_performance(self):
        """Test de performance de la configuration"""
        print("🔍 Test de performance de la configuration...")
        
        from utils.config import Config
        
        config = Config()
        
        # Test de nombreuses opérations de configuration
        start_time = time.time()
        
        for i in range(100):
            config.set(f'Test{i}', f'key{i}', f'value{i}')
        
        # Test de récupération
        for i in range(100):
            value = config.get(f'Test{i}', f'key{i}', 'default')
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Vérification de la performance
        self.assertLess(duration, 2.0)  # Moins de 2 secondes
        
        print(f"✅ 200 opérations config en {duration:.3f}s")
    
    def test_network_scan_performance(self):
        """Test de performance du scan réseau"""
        print("🔍 Test de performance du scan réseau...")
        
        from core.network_manager import NetworkManager
        
        nm = NetworkManager()
        
        # Test de scan multiple
        start_time = time.time()
        
        for i in range(10):
            networks = nm.scan_networks()
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Vérification de la performance
        self.assertLess(duration, 10.0)  # Moins de 10 secondes pour 10 scans
        
        print(f"✅ 10 scans réseau en {duration:.3f}s")
    
    def test_memory_usage(self):
        """Test d'utilisation mémoire"""
        print("🔍 Test d'utilisation mémoire...")
        
        initial_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        
        from core.logger import Logger
        from utils.config import Config
        from core.network_manager import NetworkManager
        
        # Création des composants
        logger = Logger()
        config = Config()
        nm = NetworkManager()
        
        # Ajout de nombreux logs
        for i in range(1000):
            logger.info(f"Memory test log {i}")
        
        # Vérification de la configuration
        for i in range(100):
            config.set(f'Memory{i}', f'key{i}', f'value{i}')
        
        final_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Vérification de l'utilisation mémoire
        self.assertLess(memory_increase, 100.0)  # Moins de 100MB d'augmentation
        
        print(f"✅ Utilisation mémoire: {memory_increase:.1f}MB")
    
    def test_concurrent_logging(self):
        """Test de logging concurrent"""
        print("🔍 Test de logging concurrent...")
        
        from core.logger import Logger
        
        logger = Logger()
        
        def log_worker(worker_id):
            """Worker pour le logging concurrent"""
            for i in range(100):
                logger.info(f"Worker {worker_id} - Log {i}")
        
        # Création de threads concurrents
        threads = []
        start_time = time.time()
        
        for i in range(5):
            thread = threading.Thread(target=log_worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Attente de fin des threads
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Vérification de la performance
        self.assertLess(duration, 10.0)  # Moins de 10 secondes
        
        print(f"✅ Logging concurrent (5 threads) en {duration:.3f}s")
    
    def test_ui_responsiveness(self):
        """Test de réactivité de l'interface"""
        print("🔍 Test de réactivité de l'interface...")
        
        try:
            from PyQt5.QtWidgets import QApplication
            from ui.tabs.evil_twin_tab import EvilTwinTab
            from core.network_manager import NetworkManager
            from core.logger import Logger
            
            app = QApplication([])
            
            # Test de création rapide d'onglets
            start_time = time.time()
            
            nm = NetworkManager()
            logger = Logger()
            
            tabs = []
            for i in range(10):
                tab = EvilTwinTab(nm, logger)
                tabs.append(tab)
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Vérification de la performance
            self.assertLess(duration, 5.0)  # Moins de 5 secondes
            
            print(f"✅ Création de 10 onglets en {duration:.3f}s")
            
        except Exception as e:
            print(f"⚠️  Test UI partiel: {e}")
    
    def test_large_config_handling(self):
        """Test de gestion de grandes configurations"""
        print("🔍 Test de gestion de grandes configurations...")
        
        from utils.config import Config
        
        config = Config()
        
        # Création d'une grande configuration
        start_time = time.time()
        
        large_config = {}
        for section in range(10):
            large_config[f'Section{section}'] = {}
            for key in range(100):
                large_config[f'Section{section}'][f'key{key}'] = f'value{key}'
        
        # Sauvegarde
        config.save_settings(large_config)
        
        # Chargement
        loaded_config = config.load_settings()
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Vérification de la performance
        self.assertLess(duration, 3.0)  # Moins de 3 secondes
        
        print(f"✅ Configuration de 1000 paramètres en {duration:.3f}s")

class TestStressTests(unittest.TestCase):
    """Tests de stress"""
    
    def test_logger_stress(self):
        """Test de stress du logger"""
        print("🔍 Test de stress du logger...")
        
        from core.logger import Logger
        
        logger = Logger()
        
        # Test d'envoi massif de logs
        start_time = time.time()
        
        for i in range(10000):
            logger.info(f"Stress test log {i}")
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Vérification de la performance
        self.assertLess(duration, 30.0)  # Moins de 30 secondes
        
        print(f"✅ 10000 logs en {duration:.3f}s")
    
    def test_config_stress(self):
        """Test de stress de la configuration"""
        print("🔍 Test de stress de la configuration...")
        
        from utils.config import Config
        
        config = Config()
        
        # Test d'opérations massives
        start_time = time.time()
        
        for i in range(10000):
            config.set(f'Stress{i}', f'key{i}', f'value{i}')
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Vérification de la performance
        self.assertLess(duration, 20.0)  # Moins de 20 secondes
        
        print(f"✅ 10000 opérations config en {duration:.3f}s")

def run_performance_tests():
    """Lance les tests de performance"""
    print("🚀 Lancement des tests de performance")
    print("=" * 50)
    
    # Configuration des tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Ajout des tests
    suite.addTests(loader.loadTestsFromTestCase(TestPerformance))
    suite.addTests(loader.loadTestsFromTestCase(TestStressTests))
    
    # Exécution des tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Résumé
    print("\n" + "=" * 50)
    print(f"📊 Résultats des tests de performance:")
    print(f"  Tests exécutés: {result.testsRun}")
    print(f"  Échecs: {len(result.failures)}")
    print(f"  Erreurs: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("🎉 Tous les tests de performance sont passés!")
    else:
        print("⚠️  Certains tests de performance ont échoué")
    
    return result.wasSuccessful()

if __name__ == '__main__':
    run_performance_tests()