# red-config Scanner

```
██████╗  ███████╗██████╗      ██████╗ ██████╗ ███╗   ██╗███████╗██╗██████╗ 
██╔══██╗██╔════╝██╔══██╗    ██╔════╝██╔═══██╗████╗  ██║██╔════╝██║██╔════╝ 
██████╔╝█████╗  ██║  ██║    ██║     ██║   ██║██╔██╗ ██║█████╗  ██║██║  ███╗
██╔══██╗██╔══╝  ██║  ██║    ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║██║   ██║
██║  ██║███████╗██████╔╝    ╚██████╗╚██████╔╝██║ ╚████║██║     ██║╚██████╔╝
╚═╝  ╚═╝╚══════╝╚═════╝      ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝ ╚═════╝

        Laravel Configuration Exposure & Security Scanner (beta)
```


---

`red-config` adalah alat pemindai keamanan berbasis Python yang dirancang untuk melakukan reconnaissance dan audit konfigurasi pada aplikasi web, dengan fokus pada celah keamanan umum dan spesifik Laravel.

## Fitur Utama

-   **Reconnaissance Komprehensif:** Mendeteksi IP, Hosting Provider, Web Server (Nginx, Apache, dll.), dan keberadaan WAF (Cloudflare, Sucuri, dll.).
-   **Penemuan Subdomain:** Secara pasif menemukan subdomain terkait target menggunakan data *Certificate Transparency Logs*.
-   **Analisis Jejak Jaringan:** Melakukan `traceroute` untuk memetakan jalur jaringan ke server target.
-   **Pemindaian Port Lanjutan:** Mendukung pemindaian port spesifik, rentang port, atau daftar 100 port terpopuler.
-   **Audit Konfigurasi Laravel:** Memeriksa file sensitif seperti `.env`, `.git/config`, `storage/logs/laravel.log`, dan mode debug yang aktif.
-   **Deteksi Kerentanan Umum:** Mencari *Directory Listing*, panel admin/login yang terekspos, dan file `phpinfo()`.
-   **Pemeriksaan CSRF Token:** Mendeteksi keberadaan perlindungan CSRF token pada halaman.
-   **Pemindaian Berbasis Wordlist:** Memungkinkan pengguna untuk menyediakan daftar path kustom untuk penemuan direktori yang lebih mendalam.
-   **Output Terminal Terstruktur:** Laporan yang jelas dan berwarna untuk kemudahan analisis.

## Instalasi

Untuk menjalankan skrip ini, Anda memerlukan Python 3.

1.  **Clone repositori ini:**
    ```bash
    git clone https://github.com/shitodcy/red-config.git
    ```

2.  **Masuk ke direktori proyek:**
    ```bash
    cd red-config
    ```

3.  **Instal semua dependensi yang dibutuhkan:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Pastikan Anda memiliki perintah `traceroute` (Linux/macOS) atau `tracert` (Windows) di sistem Anda agar fitur traceroute berfungsi).*

## Cara Penggunaan

Gunakan perintah `-h` atau `--help` untuk melihat semua opsi yang tersedia.

```bash
python3 redconfig.py -h
```
```
usage: redconfig.py [-h] [--ports <PORTS>] [-w <FILE>] [-t <NUM>] [--timeout <SECONDS>] TARGET

red config - Laravel Configuration Exposure & Security Scanner

Target Specification:
  TARGET                The root URL of the web application to be scanned (e.g., [https://example.com](https://example.com)).

Discovery & Enumeration Options:
  --ports <PORTS>       Specify ports to scan. Can be comma-separated, a range, or a keyword.
                        Examples:
                          '80,443,8080'    - Scan specific ports.
                          '1-1024'         - Scan a range of ports.
                          'top-100'        - Scan the 100 most common ports.
                        (Default: Scans a small list of common web-related ports).
  -w <FILE>, --wordlist <FILE>
                        Path to a custom wordlist file (one path per line) for discovering
                        additional files and directories.

Performance & Control:
  -t <NUM>, --threads <NUM>
                        Set the number of concurrent scanning threads (default: 10).
  --timeout <SECONDS>   Set the request timeout in seconds (default: 7).

Example: python3 redconfig.py [https://example.com](https://example.com) --ports top-100 -w /path/to/wordlist.txt
```

### Contoh Perintah

-   **Pemindaian dasar:**
    ```bash
    python3 redconfig.py https://target-website.com
    ```

-   **Pemindaian dengan 100 port terpopuler:**
    ```bash
    python3 redconfig.py https://target-website.com --ports top-100
    ```

-   **Pemindaian menggunakan wordlist kustom:**
    ```bash
    python3 redconfig.py https://target-website.com -w common-paths.txt
    ```

-   **Pemindaian komprehensif dengan 20 threads:**
    ```bash
    python3 redconfig.py https://target-website.com --ports 1-1024 -w /usr/share/wordlists/dirb/common.txt -t 20
    ```

## Disclaimer

⚠️ **Peringatan Keras:** Alat ini dibuat untuk tujuan **pendidikan dan pengujian keamanan yang sah**. Pengguna bertanggung jawab penuh atas semua tindakan yang dilakukan menggunakan alat ini. Jangan pernah menggunakan skrip ini pada sistem yang Anda tidak miliki izin eksplisit untuk mengujinya. Penulis tidak bertanggung jawab atas penyalahgunaan atau kerusakan apa pun yang disebabkan oleh program ini.
