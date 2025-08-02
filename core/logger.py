#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Système de logging pour WiFiPumpkin3
"""

import os
import time
import logging
from datetime import datetime
from PyQt5.QtCore import QObject, pyqtSignal

class Logger(QObject):
    """Système de logging centralisé"""
    
    log_signal = pyqtSignal(str)
    
    def __init__(self, log_file=None):
        super().__init__()
        
        # Configuration du fichier de log
        if not log_file:
            log_dir = os.path.join(os.path.dirname(__file__), '..', 'logs')
            os.makedirs(log_dir, exist_ok=True)
            log_file = os.path.join(log_dir, f'wifipumpkin3_{datetime.now().strftime("%Y%m%d")}.log')
            
        self.log_file = log_file
        
        # Configuration du logging
        self.setup_logging()
        
        # Historique des logs pour l'interface
        self.log_history = []
        self.max_history = 1000
        
    def setup_logging(self):
        """Configure le système de logging"""
        # Configuration du logger principal
        self.logger = logging.getLogger('WiFiPumpkin3')
        self.logger.setLevel(logging.DEBUG)
        
        # Handler pour fichier
        file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        
        # Handler pour console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Format des logs
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Ajout des handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
    def log(self, level, message, **kwargs):
        """Enregistre un message de log"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # Formatage du message
        if kwargs:
            message = f"{message} - {kwargs}"
            
        # Ajout au logger Python
        if level.upper() == 'DEBUG':
            self.logger.debug(message)
        elif level.upper() == 'INFO':
            self.logger.info(message)
        elif level.upper() == 'WARNING':
            self.logger.warning(message)
        elif level.upper() == 'ERROR':
            self.logger.error(message)
        elif level.upper() == 'CRITICAL':
            self.logger.critical(message)
        else:
            self.logger.info(message)
            
        # Ajout à l'historique pour l'interface
        log_entry = f"[{timestamp}] {level.upper()}: {message}"
        self.log_history.append(log_entry)
        
        # Limitation de l'historique
        if len(self.log_history) > self.max_history:
            self.log_history = self.log_history[-self.max_history:]
            
        # Émission du signal pour l'interface
        self.log_signal.emit(log_entry)
        
    def debug(self, message, **kwargs):
        """Log de niveau DEBUG"""
        self.log('DEBUG', message, **kwargs)
        
    def info(self, message, **kwargs):
        """Log de niveau INFO"""
        self.log('INFO', message, **kwargs)
        
    def warning(self, message, **kwargs):
        """Log de niveau WARNING"""
        self.log('WARNING', message, **kwargs)
        
    def error(self, message, **kwargs):
        """Log de niveau ERROR"""
        self.log('ERROR', message, **kwargs)
        
    def critical(self, message, **kwargs):
        """Log de niveau CRITICAL"""
        self.log('CRITICAL', message, **kwargs)
        
    def get_history(self, limit=None):
        """Récupère l'historique des logs"""
        if limit:
            return self.log_history[-limit:]
        return self.log_history.copy()
        
    def clear_history(self):
        """Efface l'historique des logs"""
        self.log_history.clear()
        
    def export_logs(self, filename):
        """Exporte les logs vers un fichier"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write('\n'.join(self.log_history))
            return True
        except Exception as e:
            self.error(f"Erreur lors de l'export des logs: {str(e)}")
            return False
            
    def get_log_file_path(self):
        """Retourne le chemin du fichier de log"""
        return self.log_file
        
    def get_log_stats(self):
        """Retourne les statistiques des logs"""
        stats = {
            'total_entries': len(self.log_history),
            'file_path': self.log_file,
            'file_size': os.path.getsize(self.log_file) if os.path.exists(self.log_file) else 0
        }
        
        # Comptage par niveau
        level_counts = {}
        for entry in self.log_history:
            if 'DEBUG:' in entry:
                level_counts['DEBUG'] = level_counts.get('DEBUG', 0) + 1
            elif 'INFO:' in entry:
                level_counts['INFO'] = level_counts.get('INFO', 0) + 1
            elif 'WARNING:' in entry:
                level_counts['WARNING'] = level_counts.get('WARNING', 0) + 1
            elif 'ERROR:' in entry:
                level_counts['ERROR'] = level_counts.get('ERROR', 0) + 1
            elif 'CRITICAL:' in entry:
                level_counts['CRITICAL'] = level_counts.get('CRITICAL', 0) + 1
                
        stats['level_counts'] = level_counts
        return stats


class AttackLogger:
    """Logger spécialisé pour les attaques"""
    
    def __init__(self, main_logger, attack_name):
        self.main_logger = main_logger
        self.attack_name = attack_name
        self.start_time = None
        self.end_time = None
        
    def start_attack(self):
        """Marque le début d'une attaque"""
        self.start_time = datetime.now()
        self.main_logger.info(f"Démarrage de l'attaque {self.attack_name}")
        
    def end_attack(self):
        """Marque la fin d'une attaque"""
        self.end_time = datetime.now()
        duration = self.end_time - self.start_time if self.start_time else None
        
        if duration:
            self.main_logger.info(f"Fin de l'attaque {self.attack_name} (durée: {duration})")
        else:
            self.main_logger.info(f"Fin de l'attaque {self.attack_name}")
            
    def log_packet(self, packet_type, target=None, **kwargs):
        """Log un paquet envoyé/reçu"""
        message = f"[{self.attack_name}] {packet_type}"
        if target:
            message += f" -> {target}"
        if kwargs:
            message += f" ({kwargs})"
            
        self.main_logger.debug(message)
        
    def log_client_connected(self, mac_address):
        """Log la connexion d'un client"""
        self.main_logger.info(f"[{self.attack_name}] Client connecté: {mac_address}")
        
    def log_client_disconnected(self, mac_address):
        """Log la déconnexion d'un client"""
        self.main_logger.info(f"[{self.attack_name}] Client déconnecté: {mac_address}")
        
    def log_credentials_captured(self, username, password):
        """Log la capture d'identifiants"""
        self.main_logger.warning(f"[{self.attack_name}] Identifiants capturés - User: {username}")
        
    def log_error(self, error_message):
        """Log une erreur d'attaque"""
        self.main_logger.error(f"[{self.attack_name}] Erreur: {error_message}")
        
    def get_attack_duration(self):
        """Retourne la durée de l'attaque"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        elif self.start_time:
            return datetime.now() - self.start_time
        return None 