# Backdoor File Scanner

Tools Python untuk mendeteksi file mencurigakan yang mungkin berupa backdoor terselubung. Scanner ini dapat mengidentifikasi file dengan ekstensi normal (seperti .jpg, .pdf, .png) yang sebenarnya mengandung kode berbahaya.

## Fitur

- **Deteksi Extension Mismatch**: File dengan ekstensi gambar/dokumen tapi sebenarnya executable
- **Scan Konten File**: Mendeteksi pattern kode berbahaya seperti `eval()`, `base64_decode`, `system()`, dll
- **Magic Number Detection**: Mengidentifikasi tipe file sebenarnya menggunakan file signature
- **Hash Calculation**: Menghitung MD5 hash untuk identifikasi file
- **Multiple Directory Scan**: Otomatis scan folder `files`, `images`, `repository`
- **Detailed Reporting**: Laporan lengkap dalam format console dan JSON

## Instalasi

1. **Clone repository ini**:
```bash
git clone https://github.com/username/backdoor-scanner.git
cd backdoor-scanner
```

2. **Install dependencies**:
```bash
# Untuk Windows
pip install python-magic-bin

# Untuk Linux
pip install python-magic

# Untuk macOS
brew install libmagic
pip install python-magic
```

## Cara Penggunaan

### Basic Usage
```bash
# Scan directory current
python backdoor_scanner.py

# Scan directory tertentu
python backdoor_scanner.py C:/laragon/www/myproject

# Dengan output file custom
python backdoor_scanner.py C:/laragon/www/myproject -o report.json
```

### Command Line Options
```bash
python backdoor_scanner.py [DIRECTORY] [-o OUTPUT_FILE]

Arguments:
  DIRECTORY    Directory yang akan di-scan (default: current directory)
  -o, --output File output untuk laporan JSON (default: scan_report.json)
```

## Apa yang Dideteksi?

### 1. Extension Mismatch
- File `.jpg` yang sebenarnya file PHP
- File `.pdf` yang mengandung kode executable  
- File `.png` yang berisi script berbahaya

### 2. Suspicious Content Patterns
- `<?php`, `eval(`, `base64_decode(`
- `system(`, `exec(`, `shell_exec(`, `passthru(`
- `assert(`, `preg_replace(/.*/e)`
- `$_GET`, `$_POST`, `$_REQUEST`
- `file_put_contents(`, `fwrite(`, `move_uploaded_file(`

### 3. Executable Images
- File gambar yang mengandung kode PHP/executable
- File dengan magic number tidak sesuai ekstensi

## Output Contoh

```
Starting Backdoor Scanner...
[+] Scanning: C:/laragon/www/myproject/files
[*] Scanning folder: C:/laragon/www/myproject/files (150 files)

BACKDOOR SCANNER REPORT
================================================================================

Total files scanned: 423
Scan time: 2024-01-15 14:30:25

SUSPICIOUS FILES FOUND: 3 files
--------------------------------------------------------------------------------

1. C:/laragon/www/myproject/images/photo.jpg
   Size: 24576 bytes
   Extension: .jpg
   Actual Type: application/x-php
   Threat Level: SUSPICIOUS
   Issues: EXTENSION_MISMATCH, SUSPICIOUS_CONTENT
   Suspicious Patterns: <?php, eval(, base64_decode
   MD5: a1b2c3d4e5f678901234567890123456

2. C:/laragon/www/myproject/files/document.pdf
   Size: 10240 bytes  
   Extension: .pdf
   Actual Type: application/x-php
   Threat Level: SUSPICIOUS
   Issues: EXTENSION_MISMATCH
   MD5: b2c3d4e5f678901234567890123456a1
```

## Struktur Laporan JSON

```json
{
  "suspicious_files": [],
  "mismatched_files": [],
  "executable_images": [],
  "scan_time": "2024-01-15 14:30:25",
  "total_files_scanned": 423
}
```

## Troubleshooting

### Jika scanner tidak berjalan:
1. Pastikan Python 3.6+ terinstall
2. Install dependencies dengan benar
3. Gunakan versi sederhana terlebih dahulu:

```bash
python simple_scanner.py C:/laragon/www/myproject
```

### Error `python-magic` tidak ditemukan:
```bash
# Windows
pip install python-magic-bin

# Linux (Debian/Ubuntu)
sudo apt-get install libmagic1
pip install python-magic

# Linux (CentOS/RHEL)
sudo yum install file-devel
pip install python-magic
```

## Disclaimer

Tools ini dibuat untuk tujuan keamanan dan auditing. Pengguna bertanggung jawab penuh atas penggunaan tools ini. Selalu dapatkan izin sebelum melakukan scanning pada sistem yang bukan milik Anda.

## Kontribusi

Kontribusi dipersilakan! Silakan buat pull request atau buka issue untuk melaporkan bug dan saran fitur.

## License

MIT License - lihat file [LICENSE](LICENSE) untuk detail lengkap.

---

**Dibuat dengan ❤️ untuk komunitas keamanan Indonesia**
