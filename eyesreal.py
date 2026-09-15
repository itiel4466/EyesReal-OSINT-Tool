#!/usr/bin/env python3
"""
=============================================================================
EYESREAL OSINT TOOL [PRO CYBER RESEARCH EDITION v15.0 - FULL SUITE]
- Features: 14 Modules, XSS Protection, Proper Exception Handling, Fernet Crypto
=============================================================================
"""

import os
import sys
import json
import socket
import sqlite3
import hashlib
import platform
import uuid
import time
import random
import html
import subprocess
import ipaddress
from datetime import datetime

# --- Safe Dependency Check ---
try:
    import requests
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    import ollama
    from cryptography.fernet import Fernet
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    from rich.progress import Progress, SpinnerColumn, TextColumn
except ImportError as e:
    print(f"[!] Missing Dependency: {e}")
    print("[!] Please install required packages running: pip install -r requirements.txt")
    sys.exit(1)


# --- Plivo international validation and account-owned sender service ---
"""Shared validation; numbering-plan validity does not prove consent or service."""
import re
import phonenumbers as pn

REGIONS = {'US': ('United States', '+1'), 'CN': ('China', '+86'),
           'DE': ('Germany', '+49'), 'JP': ('Japan', '+81'),
           'IN': ('India', '+91'), 'IL': ('Israel', '+972')}

def normalize(raw, region=None):
    if region is not None and region not in REGIONS:
        raise ValueError('Choose US, CN, DE, JP, IN, or IL.')
    label = f'{REGIONS[region][0]} ({REGIONS[region][1]})' if region else 'International number'
    raw = raw.strip()
    if not raw or len(raw) > 64 or not re.fullmatch(r'\+?[0-9 ().-]+', raw):
        raise ValueError(f'{label}: use digits, spaces, parentheses or hyphens; no extensions or letters.')
    compact = re.sub(r'[ ().-]', '', raw)
    if compact.startswith('00'):
        compact = '+' + compact[2:]
    if not compact.startswith('+') and region is None:
        raise ValueError('Use +country-code format, or select a country for a local number.')
    try:
        number = pn.parse(compact, region)
    except pn.NumberParseException:
        raise ValueError(f'{label}: cannot parse this number; check its country code and digits.') from None
    actual = pn.region_code_for_number(number)
    if region and number.country_code != pn.country_code_for_region(region):
        raise ValueError(f'{label}: country code does not match the selected country.')
    if not pn.is_possible_number(number):
        raise ValueError(f'{label}: incorrect number length for this numbering plan.')
    if region and not pn.is_valid_number_for_region(number, region):
        raise ValueError(f'{label}: invalid area/mobile prefix or number pattern for this country.')
    if actual not in REGIONS or not pn.is_valid_number(number):
        raise ValueError(f'{label}: invalid number or unsupported region. +1 includes countries other than the US.')
    result = pn.format_number(number, pn.PhoneNumberFormat.E164)
    if not re.fullmatch(r'\+[1-9][0-9]{1,14}', result):
        raise ValueError(f'{label}: number exceeds E.164 limits.')
    return result

"""One destination per request; fixed account-owned sources, no automatic retries."""
from contextlib import closing
import os
import re
import sqlite3
from pathlib import Path
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / '.env')

class Service:
    def __init__(self, config=None):
        self.config = dict(os.environ if config is None else config)
        self.db = self.config.get('LOG_DB', str(ROOT / 'activity.sqlite3'))
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS activity (time TEXT DEFAULT CURRENT_TIMESTAMP, kind TEXT, destination TEXT, status TEXT, detail TEXT)')

    def required(self, key):
        value = self.config.get(key, '').strip()
        if not value:
            raise ValueError(f'Set {key} in .env first.')
        return value

    def signer(self):
        return URLSafeTimedSerializer(self.required('APP_SECRET'), salt='voice-answer')

    def log(self, kind, dst, status, detail):
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('INSERT INTO activity(kind,destination,status,detail) VALUES (?,?,?,?)', (kind, dst, status, detail))

    def recent(self):
        with closing(sqlite3.connect(self.db)) as db, db:
            return db.execute('SELECT * FROM activity ORDER BY rowid DESC LIMIT 30').fetchall()

    def api(self, method, path, payload=None):
        auth_id = self.required('PLIVO_AUTH_ID')
        if not re.fullmatch(r'[A-Za-z0-9]+', auth_id):
            raise ValueError('PLIVO_AUTH_ID must be alphanumeric.')
        try:
            response = requests.request(method, f'https://api.plivo.com/v1/Account/{auth_id}/{path}',
                auth=(auth_id, self.required('PLIVO_AUTH_TOKEN')), json=payload, timeout=(10, 30), allow_redirects=False)
        except requests.RequestException:
            raise ValueError('Network error; submission outcome may be unknown. Check Plivo before retrying.') from None
        if not 200 <= response.status_code < 300:
            raise ValueError(f'Plivo HTTP {response.status_code}: check credentials, balance, destination geo permissions, trial verification and sender/route eligibility in the console.')
        try:
            return response.json()
        except ValueError:
            raise ValueError('Unrecognized Plivo response; check the console before retrying.') from None

    def send(self, kind, raw, region, message='', voice=''):
        dst = normalize(raw, region)
        try:
            if kind not in ('sms', 'call'):
                raise ValueError('Choose sms or call.')
            allowed = {normalize(x) for x in self.required('AUTHORIZED_NUMBERS').split(',') if x.strip()}
            if dst not in allowed:
                raise ValueError('Destination is not in AUTHORIZED_NUMBERS. Obtain consent before configuring it.')
            text = message.strip() if kind == 'sms' else (voice.strip() or 'This is an authorized test call.')
            if not text or len(text) > 1600 or any(ord(c) < 32 and c not in '\n\r\t' for c in text):
                raise ValueError('Enter 1–1600 characters without control characters.')
            src = normalize(self.required('PLIVO_SMS_SOURCE' if kind == 'sms' else 'PLIVO_VOICE_SOURCE'))
            # Retrieve from this account: arbitrary caller IDs and alphanumeric senders are never accepted.
            owned = self.api('GET', f'Number/{src[1:]}/')
            if str(owned.get('number', '')).lstrip('+') != src[1:]:
                raise ValueError('Source must be a Plivo number owned by this account.')
            if owned.get('sms_enabled' if kind == 'sms' else 'voice_enabled') is not True:
                raise ValueError(f'Source is not enabled for {kind}.')
            if kind == 'sms':
                payload = {'src': src, 'dst': dst, 'text': text}
                path = 'Message/'
            else:
                base = self.required('PUBLIC_BASE_URL').rstrip('/')
                url = urlparse(base)
                if url.scheme != 'https' or not url.hostname or url.query or url.fragment or url.username:
                    raise ValueError('PUBLIC_BASE_URL must be a public HTTPS URL without query or credentials.')
                token = self.signer().dumps(text)
                payload = {'from': src, 'to': dst, 'answer_url': f'{base}/answer/{token}', 'answer_method': 'GET'}
                path = 'Call/'
            result = self.api('POST', path, payload)
            reference = str(result.get('message_uuid') or result.get('request_uuid') or result.get('api_id') or 'See console')
            self.log(kind, dst, 'accepted', reference)
            return f'Accepted by Plivo for {dst}. Reference: {reference}. Delivery/connection is not yet confirmed.'
        except ValueError as exc:
            self.log(kind, dst, 'error / check console', str(exc))
            raise




console = Console()

BANNER = """[bold cyan]
      ███████╗██╗   ██╗███████╗███████╗██████╗ ███████╗ █████╗ ██╗     
      ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗██║     
      █████╗   ╚████╔╝ █████╗  ███████╗██████╔╝█████╗  ███████║██║     
      ██╔══╝    ╚██╔╝  ██╔══╝  ╚╚════██║██╔══██╗██╔══╝  ██╔══██║██║     
      ███████╗   ██║   ███████╗███████║██║  ██║███████╗██║  ██║███████╗
[/bold cyan][bold magenta]
      [!] EYESREAL OSINT PLATFORM [PRO ACADEMIC EDITION v15.0] [!]
[/bold magenta]"""

DB_FILE = "eyesreal_academic_pro.db"
SESSION_KEY = Fernet.generate_key()
cipher_suite = Fernet(SESSION_KEY)

class SessionManager:
    """Encrypted OOP Unified Report Generator"""
    def __init__(self):
        self.telemetry = {
            "metadata": {"start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
            "modules_data": []
        }
        self.init_db()

    def init_db(self):
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS secure_audit_logs 
                              (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, module_name TEXT, target_value TEXT, encrypted_data TEXT)''')
            conn.commit()
        except sqlite3.Error as e:
            console.print(f"[red][!] Database Initialization Error: {e}[/red]")
        finally:
            if 'conn' in locals(): conn.close()

    def log_event(self, module_name, target, data):
        self.telemetry["modules_data"].append({"module": module_name, "target": target, "data": data})
        try:
            encrypted_target = cipher_suite.encrypt(str(target).encode('utf-8')).decode('utf-8')
            json_data = json.dumps(data, ensure_ascii=False).encode('utf-8')
            encrypted_payload = cipher_suite.encrypt(json_data).decode('utf-8')
            
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO secure_audit_logs (timestamp, module_name, target_value, encrypted_data) VALUES (?, ?, ?, ?)",
                           (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), module_name, encrypted_target, encrypted_payload))
            conn.commit()
        except Exception as e:
            console.print(f"[red][!] Audit Log Error for {module_name}: {e}[/red]")
        finally:
            if 'conn' in locals(): conn.close()

    def generate_unified_html_report(self):
        filename = f"EyesReal_Unified_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.html"
        html_content = f"""<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>EyesReal OSINT Intelligence Report</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f5f5f7; color: #1d1d1f; margin: 0; padding: 40px; }}
                .container {{ max-width: 900px; margin: auto; background: #ffffff; padding: 40px; border-radius: 18px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); }}
                h1 {{ font-size: 28px; font-weight: 600; border-bottom: 2px solid #e5e5ea; padding-bottom: 10px; color: #000; }}
                .module-card {{ background: #fbfbfd; border: 1px solid #e5e5ea; border-radius: 12px; padding: 20px; margin-top: 20px; }}
                .module-title {{ font-size: 18px; font-weight: 600; color: #007aff; margin-top: 0; }}
                pre {{ background: #2c2c2e; color: #fff; padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 13px; }}
                .secure-badge {{ float: right; background: #34c759; color: white; padding: 4px 8px; border-radius: 6px; font-size: 12px; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <span class="secure-badge">Fernet-Encrypted Session</span>
                <h1>EyesReal OSINT Intelligence Report</h1>
                <p><strong>Session Date:</strong> {html.escape(self.telemetry['metadata']['start_time'])}</p>
        """
        for item in self.telemetry["modules_data"]:
            safe_mod = html.escape(str(item['module']))
            safe_target = html.escape(str(item['target']))
            safe_data = html.escape(json.dumps(item['data'], indent=4))
            
            html_content += f"""
                <div class="module-card">
                    <h3 class="module-title">{safe_mod}</h3>
                    <p><strong>Target:</strong> {safe_target}</p>
                    <pre>{safe_data}</pre>
                </div>
            """
        html_content += "</div></body></html>"
        
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(html_content)
            return os.path.abspath(filename)
        except Exception as e:
            console.print(f"[red][!] Report Generation Error: {e}[/red]")
            return None

session = SessionManager()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0"
]

def http_session():
    s = requests.Session()
    s.headers.update({"User-Agent": random.choice(USER_AGENTS)})
    return s

def request_with_retry(url, timeout=5, retries=2, params=None, redact_params=None):
    s = http_session()
    redact_params = set(redact_params or [])

    for attempt in range(retries):
        try:
            response = s.get(url, params=params, timeout=timeout)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            if attempt < retries - 1:
                time.sleep(random.uniform(1.0, 2.5))
            else:
                error_text = str(e)
                if params:
                    for key in redact_params:
                        value = params.get(key)
                        if value:
                            error_text = error_text.replace(str(value), "***REDACTED***")
                console.print(f"[yellow][!] Request failed for {url}: {error_text}[/yellow]")
    return None

def check_system_readiness():
    os.system("cls" if os.name == "nt" else "clear")
    console.print(BANNER)
    console.print("\n[bold cyan]Performing System Pre-Flight Checks...[/bold cyan]")
    
    if request_with_retry("https://1.1.1.1", timeout=3):
        console.print("[green][V] Global Network Access: ONLINE[/green]")
    else:
        console.print("[bold red][X] Global Network Access: OFFLINE.[/bold red]")

    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        
    if not is_admin:
        console.print("[yellow][!] Execution Level: Standard User[/yellow]")
    else:
        console.print("[green][V] Execution Level: Administrator / Root[/green]")

    try:
        requests.get("http://127.0.0.1:11434", timeout=1.5)
        console.print("[green][V] Local AI Engine (Ollama): ONLINE[/green]")
    except requests.exceptions.RequestException:
        console.print("[yellow][!] Local AI Engine (Ollama): OFFLINE[/yellow]")
        
    time.sleep(2)

def decode_gps(coord, ref):
    try:
        deg, min_val, sec = float(coord[0]), float(coord[1]), float(coord[2])
        dec = deg + (min_val / 60.0) + (sec / 3600.0)
        if ref in ['S', 'W']: dec = -dec
        return dec
    except Exception: return None

def wait_for_kill_key(target_key='e'):
    console.print(f"\n[bold red blink]>>> PRESS '{target_key.upper()}' TO IMMEDIATELY TERMINATE CALL <<<[/bold red blink]")
    if os.name == 'nt':
        import msvcrt
        while True:
            key = msvcrt.getch()
            if key.lower() == target_key.encode('ascii'): break
            elif key == b'\x03': raise KeyboardInterrupt
    else:
        import tty, termios
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            while True:
                ch = sys.stdin.read(1)
                if ch.lower() == target_key: break
                elif ch == '\x03': raise KeyboardInterrupt
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

# --- Modules ---

def module_image_exif():
    console.print("\n[bold cyan][+] MODULE 1: Advanced Image Forensics[/bold cyan]")
    path = Prompt.ask("Enter full path to image").strip()
    if not os.path.exists(path):
        console.print("[yellow][!] File not found.[/yellow]")
        return Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")
    
    try:
        with open(path, "rb") as f:
            img_data = f.read()
        md5_hash = hashlib.md5(img_data).hexdigest()
        sha256_hash = hashlib.sha256(img_data).hexdigest()
        
        console.print(f"[bold magenta]File MD5:[/bold magenta] {md5_hash}")
        console.print(f"[bold magenta]File SHA256:[/bold magenta] {sha256_hash}")

        img = Image.open(path)
        exif_data = {}
        lat, lon = None, None

        if hasattr(img, '_getexif') and img._getexif():
            for tag, val in img._getexif().items():
                tag_label = str(TAGS.get(tag, tag))
                exif_data[tag_label] = str(val)
                if tag_label == 'GPSInfo':
                    gps_map = {GPSTAGS.get(t, t): val[t] for t in val}
                    if 'GPSLatitude' in gps_map and 'GPSLongitude' in gps_map:
                        lat = decode_gps(gps_map['GPSLatitude'], gps_map['GPSLatitudeRef'])
                        lon = decode_gps(gps_map['GPSLongitude'], gps_map['GPSLongitudeRef'])

        console.print(f"[green][V] Extracted {len(exif_data)} EXIF tags.[/green]")
        if lat and lon:
            gmaps_link = f"https://www.google.com/maps?q={lat},{lon}"
            console.print(f"[bold red][!] GPS Coordinates Found![/bold red]\nLatitude: {lat} | Longitude: {lon}\nGoogle Maps Link: [blue underline]{gmaps_link}[/blue underline]")
            exif_data["EyesReal_Maps_Link"] = gmaps_link

        session.log_event("Image Forensics", path, {"MD5": md5_hash, "SHA256": sha256_hash, "EXIF": exif_data})
    except Exception as e: 
        console.print(f"[red][!] Error parsing image: {e}[/red]")
    Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")

def module_social_recon():
    console.print("\n[bold cyan][+] MODULE 2: Asynchronous Social Footprint OSINT[/bold cyan]")
    username = Prompt.ask("Enter target username").strip()
    if not username: return
    
    platforms = {
        "GitHub": f"https://api.github.com/users/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
    }
    results = {}
    with Progress(SpinnerColumn(), TextColumn("[cyan]Querying endpoints..."), console=console) as prog:
        prog.add_task("", total=None)
        for name, url in platforms.items():
            r = request_with_retry(url)
            if r and r.status_code == 200:
                results[name] = {"Status": "Active", "HTTP": r.status_code}
            else:
                results[name] = {"Status": "Not Found / Error"}
            time.sleep(random.uniform(0.3, 1.0))

    table = Table(title=f"Footprint: {username}")
    table.add_column("Platform"); table.add_column("Status")
    for k, v in results.items(): 
        color = "green" if v["Status"] == "Active" else "yellow"
        table.add_row(k, f"[{color}]{v['Status']}[/{color}]")
    console.print(table)
    
    session.log_event("Social OSINT", username, results)
    Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")

def module_email_intel():
    console.print("\n[bold cyan][+] MODULE 3: Email & Digital Identity Intelligence[/bold cyan]")
    email = Prompt.ask("Enter target email address").strip()
    if "@" not in email: return
    email_hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
    
    results = {"email": email, "gravatar": False}
    with Progress(SpinnerColumn(), TextColumn("[cyan]Scanning ID Gateways..."), console=console) as prog:
        prog.add_task("", total=None)
        r = request_with_retry(f"https://www.gravatar.com/{email_hash}.json", timeout=4)
        if r and r.status_code == 200:
            results["gravatar"] = True

    console.print(f"[bold green]Gravatar Identity Associated:[/bold green] {results['gravatar']}")
    session.log_event("Email Intel", email, results)
    Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")

def module_population_mock():
    console.print("\n[bold cyan][+] MODULE 4: Census Database Record [SIMULATION][/bold cyan]")
    query_term = Prompt.ask("Enter search query (Name or ID)").strip()
    console.print(f"[green][V] Simulated DB query executed for '{query_term}'.[/green]")
    session.log_event("Census Simulation", query_term, {"status": "Archived Entry (Mock)"})
    Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")

def run_plivo_notification(kind):
    """Shared Rich prompts for one consenting recipient; credentials stay in .env."""
    target_phone = "(not entered)"
    try:
        countries = Table(title="Destination Country", header_style="bold magenta")
        countries.add_column("Code")
        countries.add_column("Country")
        countries.add_column("Calling Code")
        for code, (name, prefix) in REGIONS.items():
            countries.add_row(code, name, prefix)
        console.print(countries)
        region = Prompt.ask("Select country", choices=list(REGIONS), default="IL")
        raw = Prompt.ask("Authorized number (+country code, 00 prefix, or local format)")
        target_phone = normalize(raw, region)
        console.print(f"Normalized destination: {target_phone}", style="cyan", markup=False)
        if kind == "sms":
            message = Prompt.ask("SMS notification text").strip()
            voice = ""
        else:
            message = ""
            voice = Prompt.ask("Voice text", default="This is an authorized test call.").strip()
        confirmation = Prompt.ask(
            f"Send {kind} to this authorized destination?", choices=["yes", "no"], default="no"
        )
        if confirmation != "yes":
            console.print("[yellow][!] Cancelled. Nothing sent.[/yellow]")
            return
        result = Service().send(kind, target_phone, region, message, voice)
        console.print(result, style="bold green", markup=False)
        session.log_event(
            f"Plivo {kind.upper()}", target_phone,
            {"status": "Accepted by provider; final outcome not confirmed", "result": result}
        )
    except (ValueError, sqlite3.Error) as exc:
        console.print(f"[!] {exc}", style="red", markup=False)
        session.log_event(f"Plivo {kind.upper()}", target_phone, {"status": "Error", "error": str(exc)})
    finally:
        Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")


def module_plivo_sms():
    console.print("\n[bold red][!] MODULE 5: Plivo Authorized SMS Gateway [!][/bold red]")
    run_plivo_notification("sms")


def module_plivo_voice():
    console.print("\n[bold red][!] MODULE 6: Plivo Authorized Test Calls [!][/bold red]")
    console.print("[cyan]Keep app.py running at PUBLIC_BASE_URL for voice instructions.[/cyan]")
    run_plivo_notification("call")


def module_network_kali():
    console.print("\n[bold cyan][+] MODULE 7: Network Scanner & VM Wrapper[/bold cyan]")
    host = Prompt.ask("Enter target IP", default="127.0.0.1").strip()
    is_kali = os.path.exists("/usr/bin/nmap") and "kali" in platform.version().lower()
    
    if is_kali:
        console.print("[magenta][!] Routing through Nmap...[/magenta]")
        try:
            # Validate user input before passing it to Nmap.
            ipaddress.ip_address(host)

            # shell=False by default; each argument is passed separately.
            result = subprocess.run(
                ["nmap", "-Pn", "-F", host],
                capture_output=True,
                text=True,
                check=False,
                timeout=60
            )

            output = result.stdout.strip()
            error_output = result.stderr.strip()

            if output:
                console.print(output)
            if result.returncode != 0:
                console.print(f"[yellow][!] Nmap exited with code {result.returncode}: {error_output or 'Unknown error'}[/yellow]")

            session.log_event(
                "Kali Nmap Scan",
                host,
                {"returncode": result.returncode, "output": output, "stderr": error_output}
            )
        except ValueError:
            console.print("[red][!] Invalid IP address format.[/red]")
        except subprocess.TimeoutExpired:
            console.print("[red][!] Nmap scan timed out.[/red]")
        except Exception as e:
            console.print(f"[red][!] Nmap execution failed: {e}[/red]")
    else:
        console.print("[cyan]Standard Python Socket Scan (Fallback)...[/cyan]")
        open_ports = []
        for p in [21, 22, 53, 80, 443, 3306, 3389, 8080]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((host, p)) == 0: open_ports.append(p)
                s.close()
            except Exception as e: 
                pass # Socket exceptions are normal for closed ports
        console.print(f"[green]Open ports found: {open_ports}[/green]")
        session.log_event("Python Port Scan", host, {"open_ports": open_ports})
    Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")

def module_network_inspector():
    console.print("\n[bold cyan][+] MODULE 8: IP, Geo-Location & Shodan Infrastructure Recon[/bold cyan]")
    ip = Prompt.ask("Enter Target IP (or Enter for your own IP)").strip()
    
    with Progress(SpinnerColumn(), TextColumn("[cyan]Resolving IP Geo-Location..."), console=console) as prog:
        prog.add_task("", total=None)
        url = f"http://ip-api.com/json/{ip}" if ip else "http://ip-api.com/json/"
        response = request_with_retry(url)
        
        if response and response.status_code == 200:
            geo_data = response.json()
            console.print(Panel(f"IP: {geo_data.get('query')}\nISP: {geo_data.get('isp')}\nOrg: {geo_data.get('org')}\nLocation: {geo_data.get('city')}, {geo_data.get('country')}", title="Geo-Location Profile", border_style="green"))
            session.log_event("IP Geo", geo_data.get("query"), geo_data)
        else:
            console.print("[red][!] Geo-Location API Error. Falling back to local IP.[/red]")
            geo_data = {"query": "127.0.0.1"}

    shodan_api = Prompt.ask("Enter Shodan API Key (or Enter to skip)", password=True).strip()
    if shodan_api and geo_data.get('query'):
        try:
            console.print("[cyan]Querying Shodan for exposed infrastructure...[/cyan]")
            shodan_res = request_with_retry(
                f"https://api.shodan.io/shodan/host/{geo_data['query']}",
                params={"key": shodan_api},
                redact_params={"key"}
            )
            if shodan_res and shodan_res.status_code == 200:
                ports = shodan_res.json().get('ports', [])
                console.print(f"[bold red]Shodan Detected Exposed Ports:[/bold red] {ports}")
                session.log_event("Shodan Recon", geo_data['query'], {"exposed_ports": ports})
            else:
                console.print("[yellow]Shodan query returned no data.[/yellow]")
        except Exception as e: 
            console.print(f"[yellow][!] Shodan API Error: {e}[/yellow]")
    Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")

def module_visual_graph():
    console.print("\n[bold cyan][+] MODULE 9: Generate Network Topology Stub[/bold cyan]")
    console.print("[green][V] Topology details cached for reporting (Mock implementation).[/green]")
    session.log_event("Topology Stub", "Network", {"status": "Logged"})
    Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")

def module_ai_analysis():
    console.print("\n[bold cyan][+] MODULE 10: AI Threat Correlation & Intelligence (Ollama)[/bold cyan]")
    try:
        with Progress(SpinnerColumn(), TextColumn("[cyan]AI is analyzing encrypted session telemetry..."), console=console) as prog:
            prog.add_task("", total=None)
            response = ollama.chat(
                model='deepseek-r1:8b', 
                messages=[{'role': 'user', 'content': f"Act as a cybersecurity analyst. Review this OSINT session data and write a short threat intelligence report: {json.dumps(session.telemetry)}"}]
            )
        console.print(Panel(response['message']['content'], title="AI Analyst Output", border_style="red"))
        session.log_event("AI Analysis", "Full Session", {"ai_report": response['message']['content']})
    except Exception as e:
        console.print(f"[yellow][!] AI Error: {e}. Is Ollama running?[/yellow]")
    Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")

def module_hwid_profiler():
    console.print("\n[bold magenta][!] MODULE 11: Local Hardware & OS Forensics [!][/bold magenta]")
    hw_data = {"OS": platform.system(), "Architecture": platform.machine(), "MAC_Node": uuid.getnode()}
    if platform.system() == "Windows":
        try:
            hw_data["GPU"] = subprocess.getoutput('wmic path win32_VideoController get name').replace('Name', '').strip()
            hw_data["Bios_Serial"] = subprocess.getoutput('wmic bios get serialnumber').replace('SerialNumber', '').strip()
        except Exception as e:
            console.print(f"[yellow][!] WMIC execution failed: {e}[/yellow]")
    
    table = Table(title="Hardware Forensic Fingerprint", header_style="bold magenta")
    table.add_column("Component"); table.add_column("Telemetry")
    for k, v in hw_data.items(): table.add_row(k, str(v))
    console.print(table)
    
    session.log_event("Hardware Forensics", "Local System", hw_data)
    Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")

def module_domain_recon():
    console.print("\n[bold magenta][!] MODULE 12: Advanced Domain & DNS Enumeration [!][/bold magenta]")
    domain = Prompt.ask("Enter Target Domain (e.g., example.com)").strip()
    if not domain: return
    
    results = {}
    with Progress(SpinnerColumn(), TextColumn(f"[cyan]Resolving DNS records for {domain} (DoH)..."), console=console) as prog:
        prog.add_task("", total=None)
        record_types = {"A": 1, "MX": 15, "TXT": 16}
        for r_name, r_type in record_types.items():
            res = request_with_retry(f"https://dns.google/resolve?name={domain}&type={r_type}")
            if res and res.status_code == 200:
                answers = [ans['data'] for ans in res.json().get('Answer', [])]
                results[r_name] = answers if answers else "None found"
            else:
                results[r_name] = "Query Failed / Timeout"

    table = Table(title=f"DNS Recon: {domain}", header_style="bold magenta")
    table.add_column("Record Type"); table.add_column("Value")
    for r_type, value in results.items():
        val_str = "\n".join(value) if isinstance(value, list) else value
        table.add_row(r_type, val_str)
    console.print(table)
    
    session.log_event("Domain DNS Recon", domain, results)
    Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")

def module_generate_report():
    path = session.generate_unified_html_report()
    if path:
        console.print(f"\n[bold green][V] Unified Report Generated Successfully![/bold green]\nSaved at: {path}")
    Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]")

def module_secure_wipe():
    console.print("\n[bold red blink]>>> INITIATING SECURE WIPE (ANTI-FORENSICS) <<<[/bold red blink]")
    try:
        if os.path.exists(DB_FILE):
            file_size = os.path.getsize(DB_FILE)
            with open(DB_FILE, "wb") as f:
                f.write(os.urandom(file_size))
            os.remove(DB_FILE)
            console.print("[bold green][V] Local DB overwritten and purged.[/bold green]")
        else:
            console.print("[yellow][!] No database file found to wipe.[/yellow]")
    except Exception as e:
        console.print(f"[red][!] Wipe failed: {e}[/red]")
    
    console.print("[bold magenta]Encryption key destroyed. Exiting...[/bold magenta]")
    sys.exit(0)

def main_menu():
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        console.print(BANNER)
        console.print("[bold green][V] PRO Cyber Mode Active - Full 14-Module OSINT Suite Ready[/bold green]")
        console.print("[yellow][!] Notice: Local audit data is encrypted via Fernet in memory.[/yellow]")

        console.print("\n[bold white]MAIN MENU - OSINT PLATFORM:[/bold white]")
        console.print("1.  🖼️  Advanced Image Forensics (EXIF & Hash)")
        console.print("2.  🔍  Social Footprint OSINT")
        console.print("3.  ⚡  Email & Digital Identity Intelligence")
        console.print("4.  📂  Census Database [SIMULATION]")
        console.print("5.  📩  Plivo Authorized SMS Gateway")
        console.print("6.  📞  Plivo Authorized Test Calls")
        console.print("7.  🔌  Network Scanner & VM Wrapper")
        console.print("8.  🌐  IP, Geo-Location & Shodan Infrastructure Recon")
        console.print("9.  📊  Generate Network Topology Stub")
        console.print("10. 🧠  AI Threat Correlation & Intelligence (Ollama)")
        console.print("11. ⚙️  Local Hardware & OS Forensics (HWID Profiler)")
        console.print("12. 🌍  Advanced Domain & DNS Enumeration")
        console.print("13. 📑  [bold magenta]Generate Unified HTML Report[/bold magenta]")
        console.print("14. ❌  [bold red]Secure Wipe, Purge Logs & Exit[/bold red]")

        choice = Prompt.ask("\nSelect module", choices=[str(i) for i in range(1, 15)])

        if choice == "1": module_image_exif()
        elif choice == "2": module_social_recon()
        elif choice == "3": module_email_intel()
        elif choice == "4": module_population_mock()
        elif choice == "5": module_plivo_sms()
        elif choice == "6": module_plivo_voice()
        elif choice == "7": module_network_kali()
        elif choice == "8": module_network_inspector()
        elif choice == "9": module_visual_graph()
        elif choice == "10": module_ai_analysis()
        elif choice == "11": module_hwid_profiler()
        elif choice == "12": module_domain_recon()
        elif choice == "13": module_generate_report()
        elif choice == "14": module_secure_wipe()

if __name__ == "__main__":
    try:
        check_system_readiness()
        main_menu()
    except KeyboardInterrupt:
        console.print("\n[!] Program interrupted by user. Exiting safely.")
        sys.exit(0)
