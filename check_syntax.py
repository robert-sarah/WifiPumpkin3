#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de vérification de syntaxe pour tous les fichiers Python
"""

import os
import sys
import py_compile
from pathlib import Path

def check_syntax(file_path):
    """Vérifie la syntaxe d'un fichier Python"""
    try:
        py_compile.compile(file_path, doraise=True)
        return True, None
    except SyntaxError as e:
        return False, f"SyntaxError: {e}"
    except Exception as e:
        return False, f"Erreur: {e}"

def find_python_files(directory):
    """Trouve tous les fichiers Python dans un répertoire"""
    python_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))
    return python_files

def main():
    """Point d'entrée principal"""
    print("🔍 Vérification de la syntaxe des fichiers Python")
    print("=" * 50)
    
    # Répertoire courant
    current_dir = os.getcwd()
    python_files = find_python_files(current_dir)
    
    errors = []
    success_count = 0
    
    for file_path in python_files:
        # Ignorer les fichiers dans .git et .venv
        if '.git' in file_path or '.venv' in file_path:
            continue
            
        print(f"Vérification: {file_path}")
        is_valid, error = check_syntax(file_path)
        
        if is_valid:
            print(f"  ✅ OK")
            success_count += 1
        else:
            print(f"  ❌ ERREUR: {error}")
            errors.append((file_path, error))
    
    print("\n" + "=" * 50)
    print("📊 RAPPORT DE VÉRIFICATION")
    print("=" * 50)
    
    print(f"Fichiers vérifiés: {len(python_files)}")
    print(f"Fichiers valides: {success_count}")
    print(f"Fichiers avec erreurs: {len(errors)}")
    
    if errors:
        print("\n❌ FICHIERS AVEC ERREURS:")
        for file_path, error in errors:
            print(f"  📁 {file_path}")
            print(f"     ❌ {error}")
            print()
    else:
        print("\n🎉 Tous les fichiers Python sont syntaxiquement corrects !")
    
    return len(errors) == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 