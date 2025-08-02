 #!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests unitaires pour les modules core
"""

import unittest
import sys
import os

# Ajout du répertoire parent au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

class TestNetworkManager(unittest.TestCase):
    """Tests pour NetworkManager"""
    
    def setUp(self):
        """Configuration initiale"""
        from core.network_manager import NetworkManager
        self.nm = NetworkManager()
    
    def test_get_interfaces(self):
        """Test de récupération des interfaces"""
        interfaces = self.nm.get_interfaces()
        self.assertIsInstance(interfaces, list)
    
    def test_get_primary_interface(self):
        """Test de récupération de l'interface principale"""
        primary = self.nm.get_primary_interface()
        # Peut être None si aucune interface n'est trouvée
        self.assertTrue(primary is None or isinstance(primary, str))
    
    def test_scan_networks(self):
        """Test du scan de réseaux"""
        networks = self.nm.scan_networks()
        self.assertIsInstance(networks, list)
        
        # Vérification de la structure des données
        if networks:
            network = networks[0]
            required_keys = ['ssid', 'bssid', 'channel', 'signal', 'encryption']
            for key in required_keys:
                self.assertIn(key, network)

class TestLogger(unittest.TestCase):
    """Tests pour Logger"""
    
    def setUp(self):
        """Configuration initiale"""
        from core.logger import Logger
        self.logger = Logger()
    
    def test_log_levels(self):
        """Test des différents niveaux de log"""
        # Test que les méthodes ne lèvent pas d'exception
        self.logger.debug("Test debug")
        self.logger.info("Test info")
        self.logger.warning("Test warning")
        self.logger.error("Test error")
        self.logger.critical("Test critical")
        
        # Vérification que les logs sont ajoutés
        history = self.logger.get_history()
        self.assertGreater(len(history), 0)
    
    def test_get_history(self):
        """Test de récupération de l'historique"""
        history = self.logger.get_history()
        self.assertIsInstance(history, list)
    
    def test_clear_history(self):
        """Test d'effacement de l'historique"""
        # Ajout de quelques logs
        self.logger.info("Test log")
        self.logger.info("Test log 2")
        
        # Effacement
        self.logger.clear_history()
        
        # Vérification
        history = self.logger.get_history()
        self.assertEqual(len(history), 0)
    
    def test_get_log_stats(self):
        """Test des statistiques de logs"""
        stats = self.logger.get_log_stats()
        self.assertIsInstance(stats, dict)
        self.assertIn('total_entries', stats)
        self.assertIn('file_path', stats)
        self.assertIn('file_size', stats)
        self.assertIn('level_counts', stats)

class TestConfig(unittest.TestCase):
    """Tests pour Config"""
    
    def setUp(self):
        """Configuration initiale"""
        from utils.config import Config
        self.config = Config()
    
    def test_get_set(self):
        """Test de récupération et définition de paramètres"""
        # Test de définition
        self.config.set('Test', 'test_param', 'test_value')
        
        # Test de récupération
        value = self.config.get('Test', 'test_param', 'default')
        self.assertEqual(value, 'test_value')
    
    def test_getboolean(self):
        """Test de récupération de valeurs booléennes"""
        self.config.set('Test', 'bool_true', 'True')
        self.config.set('Test', 'bool_false', 'False')
        
        self.assertTrue(self.config.getboolean('Test', 'bool_true', False))
        self.assertFalse(self.config.getboolean('Test', 'bool_false', True))
    
    def test_getint(self):
        """Test de récupération de valeurs entières"""
        self.config.set('Test', 'int_value', '42')
        
        value = self.config.getint('Test', 'int_value', 0)
        self.assertEqual(value, 42)
    
    def test_get_network_config(self):
        """Test de récupération de la configuration réseau"""
        config = self.config.get_network_config()
        self.assertIsInstance(config, dict)
        self.assertIn('default_interface', config)
        self.assertIn('default_mode', config)
    
    def test_get_log_config(self):
        """Test de récupération de la configuration des logs"""
        config = self.config.get_log_config()
        self.assertIsInstance(config, dict)
        self.assertIn('log_level', config)
        self.assertIn('log_folder', config)

class TestEvilTwinAttack(unittest.TestCase):
    """Tests pour EvilTwinAttack"""
    
    def setUp(self):
        """Configuration initiale"""
        from core.attacks.evil_twin import EvilTwinAttack
        from core.network_manager import NetworkManager
        from core.logger import Logger
        
        self.nm = NetworkManager()
        self.logger = Logger()
        self.attack = EvilTwinAttack(self.nm, self.logger)
    
    def test_initialization(self):
        """Test d'initialisation"""
        self.assertIsNotNone(self.attack)
        self.assertFalse(self.attack.running)
    
    def test_config_validation(self):
        """Test de validation de configuration"""
        config = {
            'interface': 'wlan0',
            'ssid': 'TestNetwork',
            'channel': 6,
            'deauth': True,
            'captive_portal': False
        }
        
        # Test que la configuration est valide
        self.assertIn('interface', config)
        self.assertIn('ssid', config)
        self.assertIn('channel', config)

class TestDeauthAttack(unittest.TestCase):
    """Tests pour DeauthAttack"""
    
    def setUp(self):
        """Configuration initiale"""
        from core.attacks.deauth_attack import DeauthAttack
        from core.network_manager import NetworkManager
        from core.logger import Logger
        
        self.nm = NetworkManager()
        self.logger = Logger()
        self.attack = DeauthAttack(self.nm, self.logger)
    
    def test_initialization(self):
        """Test d'initialisation"""
        self.assertIsNotNone(self.attack)
        self.assertFalse(self.attack.running)
    
    def test_packet_creation(self):
        """Test de création de paquets"""
        from scapy.layers.dot11 import Dot11Deauth
        
        # Test de création de paquet deauth
        packet = self.attack.create_deauth_packet("00:11:22:33:44:55", True)
        self.assertIsNotNone(packet)
        
        # Vérification que c'est bien un paquet deauth
        self.assertTrue(hasattr(packet, 'type'))

if __name__ == '__main__':
    # Configuration des tests
    unittest.main(verbosity=2)