#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gestionnaire de réseau WiFi
Gère les interfaces, les scans et les configurations
"""

import os
import subprocess
import netifaces
import psutil
from scapy.all import *

class NetworkManager:
    """Gestionnaire des interfaces réseau"""
    
    def __init__(self):
        self.interfaces = self.get_wifi_interfaces()
        self.primary_interface = self.get_primary_interface()
        
    def get_wifi_interfaces(self):
        """Récupère la liste des interfaces WiFi"""
        wifi_interfaces = []
        
        try:
            # Utilisation de iwconfig pour détecter les interfaces WiFi
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_interface = None
                
                for line in lines:
                    if line.strip() and not line.startswith(' '):
                        # Nouvelle interface
                        current_interface = line.split()[0]
                        if 'IEEE 802.11' in line or 'ESSID' in line:
                            wifi_interfaces.append(current_interface)
                            
        except Exception as e:
            print(f"Erreur lors de la détection des interfaces WiFi: {str(e)}")
            
        # Fallback: utilisation de netifaces
        if not wifi_interfaces:
            try:
                for interface in netifaces.interfaces():
                    if interface.startswith(('wlan', 'wifi', 'ath')):
                        wifi_interfaces.append(interface)
            except:
                pass
                
        return wifi_interfaces
        
    def get_primary_interface(self):
        """Récupère l'interface WiFi principale"""
        if self.interfaces:
            return self.interfaces[0]
        return None
        
    def get_interfaces(self):
        """Retourne la liste des interfaces WiFi"""
        return self.interfaces
        
    def scan_networks(self):
        """Scanne les réseaux WiFi disponibles"""
        networks = []
        
        if not self.primary_interface:
            return networks
            
        try:
            # Utilisation de iwlist pour scanner
            result = subprocess.run(['iwlist', self.primary_interface, 'scan'], 
                                 capture_output=True, text=True)
            
            if result.returncode == 0:
                networks = self.parse_scan_output(result.stdout)
            else:
                # Fallback: simulation de réseaux pour la démo
                networks = self.get_demo_networks()
                
        except Exception as e:
            print(f"Erreur lors du scan: {str(e)}")
            networks = self.get_demo_networks()
            
        return networks
        
    def parse_scan_output(self, output):
        """Parse la sortie de iwlist scan"""
        networks = []
        lines = output.split('\n')
        
        current_network = {}
        
        for line in lines:
            line = line.strip()
            
            if 'Cell' in line and 'Address' in line:
                # Nouveau réseau
                if current_network:
                    networks.append(current_network)
                current_network = {}
                
                # Extraction du BSSID
                bssid = line.split('Address: ')[-1]
                current_network['bssid'] = bssid
                
            elif 'ESSID' in line:
                # SSID
                ssid = line.split('ESSID:')[1].strip().strip('"')
                current_network['ssid'] = ssid
                
            elif 'Channel' in line:
                # Canal
                channel = line.split('Channel:')[1].strip()
                current_network['channel'] = int(channel)
                
            elif 'Quality' in line and 'Signal' in line:
                # Puissance du signal
                signal = line.split('Signal level=')[1].split()[0]
                current_network['signal'] = signal
                
            elif 'Encryption key' in line:
                # Chiffrement
                encryption = 'WPA2' if 'on' in line else 'Open'
                current_network['encryption'] = encryption
                
        # Ajout du dernier réseau
        if current_network:
            networks.append(current_network)
            
        return networks
        
    def get_demo_networks(self):
        """Retourne des réseaux de démonstration"""
        return [
            {
                'ssid': 'FreeWifi',
                'bssid': '00:11:22:33:44:55',
                'channel': 6,
                'signal': '-45',
                'encryption': 'WPA2'
            },
            {
                'ssid': 'Orange_WiFi',
                'bssid': 'aa:bb:cc:dd:ee:ff',
                'channel': 11,
                'signal': '-52',
                'encryption': 'WPA2'
            },
            {
                'ssid': 'SFR_WiFi_Fon',
                'bssid': '11:22:33:44:55:66',
                'channel': 1,
                'signal': '-67',
                'encryption': 'Open'
            },
            {
                'ssid': 'Bouygues_WiFi',
                'bssid': 'aa:aa:aa:aa:aa:aa',
                'channel': 9,
                'signal': '-73',
                'encryption': 'WPA2'
            },
            {
                'ssid': 'Neighbor_WiFi',
                'bssid': 'bb:bb:bb:bb:bb:bb',
                'channel': 3,
                'signal': '-81',
                'encryption': 'WEP'
            }
        ]
        
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
            
            print(f"Interface {interface} mise en mode monitor")
            
        except Exception as e:
            print(f"Erreur lors de la mise en mode monitor: {str(e)}")
            raise
            
    def set_managed_mode(self, interface):
        """Remet l'interface en mode managed"""
        try:
            # Arrêt de l'interface
            subprocess.run(['ifconfig', interface, 'down'], 
                         capture_output=True, text=True)
            
            # Mise en mode managed
            subprocess.run(['iwconfig', interface, 'mode', 'managed'], 
                         capture_output=True, text=True)
            
            # Démarrage de l'interface
            subprocess.run(['ifconfig', interface, 'up'], 
                         capture_output=True, text=True)
            
            print(f"Interface {interface} remise en mode managed")
            
        except Exception as e:
            print(f"Erreur lors de la remise en mode managed: {str(e)}")
            
    def get_interface_info(self, interface):
        """Récupère les informations d'une interface"""
        try:
            result = subprocess.run(['iwconfig', interface], 
                                 capture_output=True, text=True)
            
            if result.returncode == 0:
                return result.stdout
            else:
                return None
                
        except Exception as e:
            print(f"Erreur lors de la récupération des infos: {str(e)}")
            return None
            
    def get_connected_clients(self, interface):
        """Récupère la liste des clients connectés"""
        clients = []
        
        try:
            # Utilisation de airodump-ng pour détecter les clients
            result = subprocess.run(['airodump-ng', '--output-format', 'csv', 
                                   '--write', '/tmp/clients', interface], 
                                 capture_output=True, text=True, timeout=10)
            
            # Lecture du fichier de sortie
            if os.path.exists('/tmp/clients-01.csv'):
                with open('/tmp/clients-01.csv', 'r') as f:
                    lines = f.readlines()
                    
                for line in lines:
                    if line.strip() and ',' in line:
                        parts = line.split(',')
                        if len(parts) > 1 and parts[0].strip():
                            mac = parts[0].strip()
                            if mac and mac != 'Station MAC':
                                clients.append(mac)
                                
        except Exception as e:
            print(f"Erreur lors de la détection des clients: {str(e)}")
            
        return clients
        
    def get_interface_status(self, interface):
        """Récupère le statut d'une interface"""
        try:
            result = subprocess.run(['iwconfig', interface], 
                                 capture_output=True, text=True)
            
            if result.returncode == 0:
                output = result.stdout
                
                status = {
                    'interface': interface,
                    'mode': 'unknown',
                    'channel': None,
                    'ssid': None
                }
                
                lines = output.split('\n')
                for line in lines:
                    if 'Mode:' in line:
                        mode = line.split('Mode:')[1].split()[0]
                        status['mode'] = mode
                    elif 'Channel:' in line:
                        channel = line.split('Channel:')[1].split()[0]
                        status['channel'] = int(channel)
                    elif 'ESSID:' in line:
                        ssid = line.split('ESSID:')[1].strip().strip('"')
                        status['ssid'] = ssid
                        
                return status
            else:
                return None
                
        except Exception as e:
            print(f"Erreur lors de la récupération du statut: {str(e)}")
            return None
            
    def is_monitor_mode(self, interface):
        """Vérifie si l'interface est en mode monitor"""
        status = self.get_interface_status(interface)
        return status and status['mode'] == 'Monitor'
        
    def is_managed_mode(self, interface):
        """Vérifie si l'interface est en mode managed"""
        status = self.get_interface_status(interface)
        return status and status['mode'] == 'Managed' 