#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scanner de réseaux WiFi réel
Détection et analyse des réseaux WiFi disponibles
"""

import os
import time
import subprocess
import re
import json
from datetime import datetime
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt

class NetworkScanner:
    """Scanner de réseaux WiFi réel"""
    
    def __init__(self, logger):
        self.logger = logger
        self.networks = []
        self.scanning = False
        
    def scan_networks(self, interface, duration=10):
        """Scanne les réseaux WiFi disponibles"""
        try:
            self.logger.log("INFO", f"Démarrage du scan WiFi sur {interface}")
            self.scanning = True
            self.networks = []
            
            # Mise en mode monitor
            self.set_monitor_mode(interface)
            
            # Démarrage du scan avec airodump-ng
            self.scan_with_airodump(interface, duration)
            
            # Alternative avec scapy si airodump-ng échoue
            if not self.networks:
                self.scan_with_scapy(interface, duration)
            
            self.logger.log("INFO", f"Scan terminé - {len(self.networks)} réseaux trouvés")
            return self.networks
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors du scan: {str(e)}")
            return []
    
    def set_monitor_mode(self, interface):
        """Met l'interface en mode monitor"""
        try:
            # Arrêt de l'interface
            subprocess.run(['ifconfig', interface, 'down'], 
                         capture_output=True, text=True)
            
            # Mise en mode monitor
            subprocess.run(['iwconfig', interface, 'mode', 'monitor'], 
                         capture_output=True, text=True)
            
            # Démarrage de l'interface
            subprocess.run(['ifconfig', interface, 'up'], 
                         capture_output=True, text=True)
            
            self.logger.log("INFO", f"Interface {interface} mise en mode monitor")
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur mode monitor: {str(e)}")
    
    def scan_with_airodump(self, interface, duration):
        """Scan avec airodump-ng"""
        try:
            # Création du répertoire de sortie
            output_dir = '/tmp/wifi_scan'
            os.makedirs(output_dir, exist_ok=True)
            
            # Lancement d'airodump-ng
            cmd = [
                'airodump-ng',
                '--output-format', 'csv',
                '--write', f'{output_dir}/scan',
                '--write-interval', '1',
                interface
            ]
            
            # Démarrage du processus
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Attente de la durée du scan
            time.sleep(duration)
            
            # Arrêt du processus
            process.terminate()
            process.wait()
            
            # Lecture des résultats
            self.parse_airodump_results(output_dir)
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur airodump-ng: {str(e)}")
    
    def parse_airodump_results(self, output_dir):
        """Parse les résultats d'airodump-ng"""
        try:
            # Lecture du fichier CSV
            csv_file = f'{output_dir}/scan-01.csv'
            if os.path.exists(csv_file):
                with open(csv_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                # Parsing des lignes
                for line in lines:
                    if line.strip() and ',' in line:
                        parts = line.split(',')
                        if len(parts) >= 15:
                            try:
                                network = {
                                    'bssid': parts[0].strip(),
                                    'ssid': parts[13].strip(),
                                    'channel': int(parts[3].strip()) if parts[3].strip().isdigit() else 0,
                                    'encryption': parts[6].strip(),
                                    'signal': parts[8].strip(),
                                    'beacons': int(parts[9].strip()) if parts[9].strip().isdigit() else 0,
                                    'ivs': int(parts[10].strip()) if parts[10].strip().isdigit() else 0,
                                    'clients': int(parts[14].strip()) if parts[14].strip().isdigit() else 0
                                }
                                
                                # Filtrage des réseaux valides
                                if network['bssid'] and network['bssid'] != 'BSSID':
                                    self.networks.append(network)
                                    
                            except (ValueError, IndexError):
                                continue
                                
        except Exception as e:
            self.logger.log("ERROR", f"Erreur parsing airodump: {str(e)}")
    
    def scan_with_scapy(self, interface, duration):
        """Scan avec Scapy en fallback"""
        try:
            self.logger.log("INFO", "Utilisation de Scapy pour le scan")
            
            # Fonction de callback pour capturer les beacons
            def beacon_handler(pkt):
                if pkt.haslayer(Dot11Beacon):
                    try:
                        # Extraction des informations du beacon
                        bssid = pkt[Dot11].addr2
                        ssid = None
                        channel = None
                        encryption = "Unknown"
                        
                        # Recherche du SSID
                        if pkt.haslayer(Dot11Elt):
                            for layer in pkt[Dot11Elt]:
                                if layer.ID == 0:  # SSID
                                    ssid = layer.info.decode('utf-8', errors='ignore')
                                elif layer.ID == 3:  # Channel
                                    channel = ord(layer.info)
                        
                        # Recherche du type d'encryption
                        if pkt.haslayer(Dot11Elt):
                            for layer in pkt[Dot11Elt]:
                                if layer.ID == 48:  # RSN
                                    encryption = "WPA2"
                                elif layer.ID == 221:  # Vendor specific
                                    if b'WPA' in layer.info:
                                        encryption = "WPA"
                        
                        # Création de l'entrée réseau
                        if ssid and bssid:
                            network = {
                                'bssid': bssid,
                                'ssid': ssid,
                                'channel': channel or 0,
                                'encryption': encryption,
                                'signal': 'N/A',
                                'beacons': 1,
                                'ivs': 0,
                                'clients': 0
                            }
                            
                            # Ajout si pas déjà présent
                            if not any(n['bssid'] == bssid for n in self.networks):
                                self.networks.append(network)
                                
                    except Exception as e:
                        pass
            
            # Capture des paquets
            sniff(iface=interface, prn=beacon_handler, timeout=duration, store=0)
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur scan Scapy: {str(e)}")
    
    def get_network_details(self, bssid, interface):
        """Récupère les détails d'un réseau spécifique"""
        try:
            # Utilisation d'aircrack-ng pour les détails
            cmd = ['airodump-ng', '--bssid', bssid, '--channel', '1', interface]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Parsing des détails
                lines = result.stdout.split('\n')
                details = {
                    'bssid': bssid,
                    'clients': [],
                    'signal_strength': 'N/A',
                    'encryption_details': 'N/A'
                }
                
                for line in lines:
                    if bssid in line:
                        parts = line.split()
                        if len(parts) >= 8:
                            details['signal_strength'] = parts[8]
                            details['encryption_details'] = parts[6]
                    elif 'Station' in line:
                        # Détection des clients
                        pass
                
                return details
                
        except Exception as e:
            self.logger.log("ERROR", f"Erreur détails réseau: {str(e)}")
        
        return None
    
    def get_connected_clients(self, bssid, interface):
        """Récupère la liste des clients connectés"""
        try:
            clients = []
            
            # Utilisation d'aircrack-ng pour détecter les clients
            cmd = ['airodump-ng', '--bssid', bssid, '--channel', '1', '--output-format', 'csv', interface]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                
                for line in lines:
                    if ',' in line and bssid not in line:
                        parts = line.split(',')
                        if len(parts) >= 6:
                            client_mac = parts[0].strip()
                            if client_mac and client_mac != 'Station MAC':
                                clients.append({
                                    'mac': client_mac,
                                    'first_seen': parts[1].strip(),
                                    'last_seen': parts[2].strip(),
                                    'power': parts[3].strip(),
                                    'packets': parts[4].strip(),
                                    'bssid': parts[5].strip()
                                })
            
            return clients
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur clients connectés: {str(e)}")
            return []
    
    def get_network_channels(self):
        """Récupère les canaux disponibles"""
        try:
            channels = []
            
            # Lecture des canaux depuis iwlist
            result = subprocess.run(['iwlist', 'scan'], capture_output=True, text=True)
            
            if result.returncode == 0:
                # Parsing des canaux
                for line in result.stdout.split('\n'):
                    if 'Channel' in line:
                        match = re.search(r'Channel (\d+)', line)
                        if match:
                            channel = int(match.group(1))
                            if channel not in channels:
                                channels.append(channel)
            
            return sorted(channels)
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur canaux: {str(e)}")
            return list(range(1, 14))  # Canaux par défaut
    
    def export_networks(self, filename):
        """Exporte la liste des réseaux"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.networks, f, indent=2, ensure_ascii=False)
            
            self.logger.log("INFO", f"Réseaux exportés vers {filename}")
            return True
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur export: {str(e)}")
            return False
    
    def get_network_statistics(self):
        """Retourne les statistiques des réseaux"""
        if not self.networks:
            return {}
        
        stats = {
            'total_networks': len(self.networks),
            'open_networks': len([n for n in self.networks if 'OPN' in n.get('encryption', '')]),
            'wpa_networks': len([n for n in self.networks if 'WPA' in n.get('encryption', '')]),
            'wpa2_networks': len([n for n in self.networks if 'WPA2' in n.get('encryption', '')]),
            'wep_networks': len([n for n in self.networks if 'WEP' in n.get('encryption', '')]),
            'channels_used': list(set([n.get('channel', 0) for n in self.networks])),
            'strongest_signal': max([n.get('signal', 0) for n in self.networks]) if self.networks else 0
        }
        
        return stats 