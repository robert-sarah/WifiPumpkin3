#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module de configuration pour WiFiPumpkin3
"""

import os
import json
from pathlib import Path
import configparser
from datetime import datetime

class Config:
    """Gestionnaire de configuration de l'application"""
    
    def __init__(self, config_file=None):
        if not config_file:
            config_dir = os.path.join(os.path.dirname(__file__), '..', 'config')
            os.makedirs(config_dir, exist_ok=True)
            config_file = os.path.join(config_dir, 'wifipumpkin3.conf')
            
        self.config_file = config_file
        
        # Définition du fichier de configuration avancée
        config_dir = os.path.join(os.path.dirname(__file__), '..', 'config')
        self.advanced_config_file = os.path.join(config_dir, 'advanced_modules.json')
        
        self.config = configparser.ConfigParser()
        
        # Chargement de la configuration
        self.load_config()
        self.load_advanced_config()
        
    def load_config(self):
        """Charge la configuration depuis le fichier"""
        try:
            if os.path.exists(self.config_file):
                self.config.read(self.config_file, encoding='utf-8')
            else:
                # Création de la configuration par défaut
                self.create_default_config()
                
        except Exception as e:
            print(f"Erreur lors du chargement de la configuration: {str(e)}")
            self.create_default_config()
    
    def load_advanced_config(self):
        """Charge la configuration des modules avancés"""
        try:
            if os.path.exists(self.advanced_config_file):
                with open(self.advanced_config_file, 'r', encoding='utf-8') as f:
                    self.advanced_config = json.load(f)
            else:
                # Configuration par défaut pour les modules avancés
                self.advanced_config = {
                    "wpa_cracking": {"enabled": True},
                    "dns_spoofing": {"enabled": True},
                    "stealth": {"enabled": True},
                    "ssl": {"enabled": True},
                    "dashboard": {"enabled": True}
                }
        except Exception as e:
            print(f"Erreur lors du chargement de la configuration avancée: {str(e)}")
            self.advanced_config = {}
            
    def create_default_config(self):
        """Crée une configuration par défaut"""
        # Section Général
        if not self.config.has_section('General'):
            self.config.add_section('General')
            
        self.config.set('General', 'theme', 'Clair')
        self.config.set('General', 'language', 'Français')
        self.config.set('General', 'font_size', '10')
        self.config.set('General', 'auto_start', 'False')
        self.config.set('General', 'minimize_startup', 'False')
        self.config.set('General', 'check_updates', 'True')
        
        # Section Réseau
        if not self.config.has_section('Network'):
            self.config.add_section('Network')
            
        self.config.set('Network', 'default_interface', 'wlan0')
        self.config.set('Network', 'default_mode', 'Managed')
        self.config.set('Network', 'dhcp_range_start', '192.168.1.100')
        self.config.set('Network', 'dhcp_range_end', '192.168.1.200')
        self.config.set('Network', 'gateway', '192.168.1.1')
        self.config.set('Network', 'dns_servers', '8.8.8.8, 8.8.4.4')
        
        # Section Sécurité
        if not self.config.has_section('Security'):
            self.config.add_section('Security')
            
        self.config.set('Security', 'warn_before_attack', 'True')
        self.config.set('Security', 'confirm_stop', 'True')
        self.config.set('Security', 'check_privileges', 'True')
        self.config.set('Security', 'encrypt_logs', 'False')
        self.config.set('Security', 'encrypt_captures', 'False')
        self.config.set('Security', 'encryption_key', '')
        
        # Section Logs
        if not self.config.has_section('Logs'):
            self.config.add_section('Logs')
            
        self.config.set('Logs', 'log_level', 'INFO')
        self.config.set('Logs', 'log_folder', './logs')
        self.config.set('Logs', 'log_rotation', '7')
        self.config.set('Logs', 'log_attacks', 'True')
        self.config.set('Logs', 'log_errors', 'True')
        self.config.set('Logs', 'log_traffic', 'False')
        self.config.set('Logs', 'detailed_timestamp', 'True')
        
        # Section Attaques
        if not self.config.has_section('Attacks'):
            self.config.add_section('Attacks')
            
        self.config.set('Attacks', 'evil_twin_deauth', 'True')
        self.config.set('Attacks', 'evil_twin_portal', 'True')
        self.config.set('Attacks', 'deauth_packet_count', '10')
        self.config.set('Attacks', 'deauth_interval', '100')
        self.config.set('Attacks', 'probe_interval', '500')
        
        # Sauvegarde de la configuration par défaut
        self.save_config()
        
    def save_config(self):
        """Sauvegarde la configuration dans le fichier"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                self.config.write(f)
        except Exception as e:
            print(f"Erreur lors de la sauvegarde de la configuration: {str(e)}")
            
    def get(self, section, option, fallback=None):
        """Récupère une valeur de configuration"""
        try:
            return self.config.get(section, option)
        except:
            return fallback
    
    def get_advanced_config(self, module_name=None):
        """Récupère la configuration des modules avancés"""
        if module_name:
            return self.advanced_config.get(module_name, {})
        return self.advanced_config
            
    def getboolean(self, section, option, fallback=False):
        """Récupère une valeur booléenne de configuration"""
        try:
            return self.config.getboolean(section, option)
        except:
            return fallback
            
    def getint(self, section, option, fallback=0):
        """Récupère une valeur entière de configuration"""
        try:
            return self.config.getint(section, option)
        except:
            return fallback
            
    def set(self, section, option, value):
        """Définit une valeur de configuration"""
        if not self.config.has_section(section):
            self.config.add_section(section)
            
        self.config.set(section, option, str(value))
        
    def save_settings(self, settings):
        """Sauvegarde un dictionnaire de paramètres"""
        try:
            # Mise à jour de la configuration avec les nouveaux paramètres
            for section, options in settings.items():
                if isinstance(options, dict):
                    for option, value in options.items():
                        self.set(section, option, value)
                else:
                    # Si c'est un paramètre simple, on le met dans la section General
                    self.set('General', section, options)
                    
            # Sauvegarde
            self.save_config()
            
        except Exception as e:
            print(f"Erreur lors de la sauvegarde des paramètres: {str(e)}")
            raise
            
    def load_settings(self):
        """Charge tous les paramètres dans un dictionnaire"""
        settings = {}
        
        try:
            for section in self.config.sections():
                settings[section] = {}
                for option in self.config.options(section):
                    value = self.config.get(section, option)
                    
                    # Conversion des types
                    if value.lower() in ('true', 'false'):
                        settings[section][option] = value.lower() == 'true'
                    elif value.isdigit():
                        settings[section][option] = int(value)
                    else:
                        settings[section][option] = value
                        
        except Exception as e:
            print(f"Erreur lors du chargement des paramètres: {str(e)}")
            
        return settings
        
    def get_attack_config(self, attack_name):
        """Récupère la configuration d'une attaque spécifique"""
        config = {}
        
        if attack_name == 'evil_twin':
            config = {
                'deauth': self.getboolean('Attacks', 'evil_twin_deauth', True),
                'portal': self.getboolean('Attacks', 'evil_twin_portal', True),
                'interface': self.get('Network', 'default_interface', 'wlan0'),
                'channel': 6
            }
        elif attack_name == 'deauth':
            config = {
                'packet_count': self.getint('Attacks', 'deauth_packet_count', 10),
                'interval': self.getint('Attacks', 'deauth_interval', 100),
                'interface': self.get('Network', 'default_interface', 'wlan0')
            }
        elif attack_name == 'probe':
            config = {
                'interval': self.getint('Attacks', 'probe_interval', 500),
                'interface': self.get('Network', 'default_interface', 'wlan0')
            }
            
        return config
        
    def get_network_config(self):
        """Récupère la configuration réseau"""
        return {
            'default_interface': self.get('Network', 'default_interface', 'wlan0'),
            'default_mode': self.get('Network', 'default_mode', 'Managed'),
            'dhcp_range_start': self.get('Network', 'dhcp_range_start', '192.168.1.100'),
            'dhcp_range_end': self.get('Network', 'dhcp_range_end', '192.168.1.200'),
            'gateway': self.get('Network', 'gateway', '192.168.1.1'),
            'dns_servers': self.get('Network', 'dns_servers', '8.8.8.8, 8.8.4.4')
        }
        
    def get_log_config(self):
        """Récupère la configuration des logs"""
        return {
            'log_level': self.get('Logs', 'log_level', 'INFO'),
            'log_folder': self.get('Logs', 'log_folder', './logs'),
            'log_rotation': self.getint('Logs', 'log_rotation', 7),
            'log_attacks': self.getboolean('Logs', 'log_attacks', True),
            'log_errors': self.getboolean('Logs', 'log_errors', True),
            'log_traffic': self.getboolean('Logs', 'log_traffic', False),
            'detailed_timestamp': self.getboolean('Logs', 'detailed_timestamp', True)
        }
        
    def get_security_config(self):
        """Récupère la configuration de sécurité"""
        return {
            'warn_before_attack': self.getboolean('Security', 'warn_before_attack', True),
            'confirm_stop': self.getboolean('Security', 'confirm_stop', True),
            'check_privileges': self.getboolean('Security', 'check_privileges', True),
            'encrypt_logs': self.getboolean('Security', 'encrypt_logs', False),
            'encrypt_captures': self.getboolean('Security', 'encrypt_captures', False),
            'encryption_key': self.get('Security', 'encryption_key', '')
        }
        
    def get_ui_config(self):
        """Récupère la configuration de l'interface utilisateur"""
        return {
            'theme': self.get('General', 'theme', 'Clair'),
            'language': self.get('General', 'language', 'Français'),
            'font_size': self.getint('General', 'font_size', 10),
            'auto_start': self.getboolean('General', 'auto_start', False),
            'minimize_startup': self.getboolean('General', 'minimize_startup', False),
            'check_updates': self.getboolean('General', 'check_updates', True)
        }
        
    def reset_to_default(self):
        """Remet la configuration par défaut"""
        try:
            # Suppression du fichier de configuration
            if os.path.exists(self.config_file):
                os.remove(self.config_file)
                
            # Recréation de la configuration par défaut
            self.create_default_config()
            
        except Exception as e:
            print(f"Erreur lors de la remise à zéro: {str(e)}")
            
    def export_config(self, filename):
        """Exporte la configuration vers un fichier"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                self.config.write(f)
            return True
        except Exception as e:
            print(f"Erreur lors de l'export de la configuration: {str(e)}")
            return False
            
    def import_config(self, filename):
        """Importe la configuration depuis un fichier"""
        try:
            if os.path.exists(filename):
                self.config.read(filename, encoding='utf-8')
                self.save_config()
                return True
            return False
        except Exception as e:
            print(f"Erreur lors de l'import de la configuration: {str(e)}")
            return False