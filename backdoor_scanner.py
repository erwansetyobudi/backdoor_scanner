#!/usr/bin/env python3
"""
Tools Deteksi Backdoor Terselubung - FIXED VERSION
"""

import os
import hashlib
import argparse
from pathlib import Path
import json
from datetime import datetime

class BackdoorScanner:
    def __init__(self):
        self.suspicious_extensions = {
            'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'],
            'document': ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'],
            'archive': ['.zip', '.rar', '.tar', '.gz', '.7z'],
            'executable': ['.php', '.php3', '.php4', '.php5', '.php7', '.phtml',
                          '.asp', '.aspx', '.jsp', '.py', '.pl', '.cgi', '.sh',
                          '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs']
        }
        
        self.suspicious_patterns = [
            b'<?php', b'eval(', b'base64_decode', b'system(', b'exec(',
            b'shell_exec', b'passthru', b'assert(', b'preg_replace',
            b'$_GET', b'$_POST', b'$_REQUEST', b'include(', b'require(',
            b'file_put_contents', b'fwrite', b'move_uploaded_file'
        ]
        
        self.scan_results = {
            'suspicious_files': [],
            'mismatched_files': [],
            'executable_images': [],
            'scan_time': None,
            'total_files_scanned': 0
        }

    def get_file_type(self, file_path):
        """Deteksi tipe file menggunakan signature/header"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(20)  # Baca 20 byte pertama
            
            # Cek magic numbers untuk berbagai format
            if header.startswith(b'\xff\xd8\xff'):
                return 'image/jpeg'
            elif header.startswith(b'\x89PNG\r\n\x1a\n'):
                return 'image/png'
            elif header.startswith(b'GIF8'):
                return 'image/gif'
            elif header.startswith(b'%PDF'):
                return 'application/pdf'
            elif header.startswith(b'<?php'):
                return 'application/x-php'
            elif header.startswith(b'PK'):  # ZIP files
                return 'application/zip'
            elif header.startswith(b'MZ'):  # Windows EXE
                return 'application/x-dosexec'
            else:
                # Cek jika mengandung teks PHP/script
                if b'<?php' in header or b'<?=' in header:
                    return 'application/x-php'
                elif b'<script' in header.lower():
                    return 'application/x-javascript'
                
                return 'unknown'
        except:
            return 'unknown'

    def check_file_extension_mismatch(self, file_path, actual_type):
        """Cek apakah ekstensi file sesuai dengan tipe sebenarnya"""
        ext = Path(file_path).suffix.lower()
        
        # Jika file sebenarnya PHP tapi ekstensi bukan PHP
        if 'php' in actual_type and ext not in self.suspicious_extensions['executable']:
            return True
            
        # Jika file sebenarnya executable tapi ekstensi gambar
        if ('dosexec' in actual_type or 'executable' in actual_type) and ext in self.suspicious_extensions['image']:
            return True
            
        # Jika file sebenarnya text/script tapi ekstensi gambar
        if ('text' in actual_type or 'script' in actual_type) and ext in self.suspicious_extensions['image']:
            return True
            
        return False

    def scan_file_content(self, file_path):
        """Scan konten file untuk pattern mencurigakan"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(8192)  # Baca 8KB pertama
                
            suspicious_found = []
            for pattern in self.suspicious_patterns:
                if pattern in content:
                    suspicious_found.append(pattern.decode('utf-8', errors='ignore'))
            
            return suspicious_found
        except:
            return []

    def calculate_file_hash(self, file_path):
        """Hitung hash MD5 file"""
        try:
            hasher = hashlib.md5()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return None

    def scan_directory(self, directory_path):
        """Scan seluruh directory"""
        print(f"[+] Starting scan in: {directory_path}")
        
        # Scan semua subdirectory, tidak hanya files/images/repository
        target_dirs = ['files', 'images', 'repository', '']  # '' untuk root directory
        
        for target_dir in target_dirs:
            full_path = os.path.join(directory_path, target_dir)
            if os.path.exists(full_path):
                print(f"[+] Scanning: {full_path}")
                self._scan_single_directory(full_path)
            else:
                print(f"[-] Directory not found: {full_path}")

    def _scan_single_directory(self, directory):
        """Scan single directory"""
        try:
            for root, dirs, files in os.walk(directory):
                print(f"  [*] Scanning folder: {root} ({len(files)} files)")
                for file in files:
                    file_path = os.path.join(root, file)
                    self._analyze_file(file_path)
        except Exception as e:
            print(f"Error scanning {directory}: {str(e)}")

    def _analyze_file(self, file_path):
        """Analisis individual file"""
        self.scan_results['total_files_scanned'] += 1
        
        if self.scan_results['total_files_scanned'] % 100 == 0:
            print(f"  [*] Scanned {self.scan_results['total_files_scanned']} files...")
        
        try:
            file_size = os.path.getsize(file_path)
            actual_type = self.get_file_type(file_path)
            file_ext = Path(file_path).suffix.lower()
            file_hash = self.calculate_file_hash(file_path)
            
            # Skip file yang terlalu kecil
            if file_size < 10:
                return
            
            # Cek mismatch extension
            is_mismatched = self.check_file_extension_mismatch(file_path, actual_type)
            
            # Scan konten untuk pattern mencurigakan
            suspicious_patterns = self.scan_file_content(file_path)
            
            # Cek jika file image mengandung kode executable
            is_executable_image = False
            if file_ext in self.suspicious_extensions['image'] and ('php' in actual_type or 'executable' in actual_type):
                is_executable_image = True
            
            # Tentukan level threat
            threat_detected = suspicious_patterns or is_mismatched or is_executable_image
            
            if threat_detected:
                result = {
                    'file_path': file_path,
                    'file_size': file_size,
                    'file_extension': file_ext,
                    'actual_type': actual_type,
                    'threat_level': "SUSPICIOUS",
                    'hash': file_hash,
                    'issues': []
                }
                
                if is_mismatched:
                    result['issues'].append("EXTENSION_MISMATCH")
                    self.scan_results['mismatched_files'].append(result)
                
                if suspicious_patterns:
                    result['issues'].append("SUSPICIOUS_CONTENT")
                    result['suspicious_patterns'] = suspicious_patterns
                    self.scan_results['suspicious_files'].append(result)
                
                if is_executable_image:
                    result['issues'].append("EXECUTABLE_IMAGE")
                    self.scan_results['executable_images'].append(result)
                    
        except Exception as e:
            print(f"Error analyzing {file_path}: {str(e)}")

    def generate_report(self):
        """Generate laporan hasil scan"""
        self.scan_results['scan_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print("\n" + "="*80)
        print("BACKDOOR SCANNER REPORT")
        print("="*80)
        
        print(f"\nTotal files scanned: {self.scan_results['total_files_scanned']}")
        print(f"Scan time: {self.scan_results['scan_time']}")
        
        # Tampilkan file suspicious
        all_suspicious = (self.scan_results['suspicious_files'] + 
                         self.scan_results['mismatched_files'] + 
                         self.scan_results['executable_images'])
        
        if all_suspicious:
            print(f"\n⚠️  SUSPICIOUS FILES FOUND: {len(all_suspicious)} files")
            print("-" * 80)
            
            for i, file in enumerate(all_suspicious, 1):
                print(f"\n{i}. 📁 {file['file_path']}")
                print(f"   Size: {file['file_size']} bytes")
                print(f"   Extension: {file['file_extension']}")
                print(f"   Actual Type: {file['actual_type']}")
                print(f"   Threat Level: {file['threat_level']}")
                print(f"   Issues: {', '.join(file['issues'])}")
                if 'suspicious_patterns' in file:
                    print(f"   Suspicious Patterns: {', '.join(file['suspicious_patterns'])}")
                print(f"   MD5: {file['hash']}")
        else:
            print("\n✅ No suspicious files found!")

    def save_report(self, output_file="scan_report.json"):
        """Simpan hasil scan ke file JSON"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.scan_results, f, indent=2, ensure_ascii=False)
            print(f"\n📄 Full report saved to: {output_file}")
        except Exception as e:
            print(f"Error saving report: {str(e)}")

def main():
    print("🚀 Starting Backdoor Scanner...")
    print("Scanning for suspicious files...")
    
    # Jika tidak ada argumen, scan directory current
    import sys
    if len(sys.argv) > 1:
        directory = sys.argv[1]
    else:
        directory = os.getcwd()
    
    if not os.path.exists(directory):
        print(f"Error: Directory {directory} tidak ditemukan!")
        return
    
    scanner = BackdoorScanner()
    scanner.scan_directory(directory)
    scanner.generate_report()
    scanner.save_report()

if __name__ == "__main__":
    main()
