from flask import Flask, render_template, request, jsonify, Response, send_from_directory
import asyncio
import dns.resolver
import re
import aiohttp
from aiofiles import open as aio_open
import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, quote
import validators
from concurrent.futures import ThreadPoolExecutor
import threading
import time
import queue
from werkzeug.utils import secure_filename
import tempfile

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# ======================= Global State Management =======================
scan_states = {
    'sql': {
        'running': False,
        'progress': 0,
        'current_test': '',
        'vulnerability_found': False,
        'stop_requested': False,
        'queue': queue.Queue()
    },
    'xss': {
        'running': False,
        'progress': 0,
        'results': [],
        'vulnerability_found': False,
        'current_test': "",
        'should_stop': False
    },
    'traversal': {
        'running': False,
        'progress': 0,
        'current_test': '',
        'vulnerability_found': False,
        'stop_flag': False,
        'queue': queue.Queue()
    },
    'subdomains': {
        'running': False,
        'progress': 0,
        'current_test': '',
        'queue': queue.Queue()
    }
}

# ======================= Common Utilities =======================
def safe_remove(filepath):
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
    except:
        pass

# ======================= Subdomain Enumeration Functions =======================
async def fetch_json(session, url):
    """Fetch JSON data from a given URL."""
    try:
        async with session.get(url, timeout=10) as response:
            if response.status == 200:
                return await response.json()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
    return None

async def passive_enumeration(domain, session):
    """Gather subdomains from passive sources without API keys."""
    passive_subdomains = set()
    sources = {
        "crt.sh": f"https://crt.sh/?q=%25.{domain}&output=json",
        "AlienVault": f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        "RapidDNS": f"https://rapiddns.io/s/{domain}?full=1",
    }
    
    tasks = [fetch_json(session, url) for name, url in sources.items() if "rapiddns" not in name]
    responses = await asyncio.gather(*tasks)
    
    for (source, response) in zip(sources.keys(), responses):
        if response:
            if source == "crt.sh":
                for entry in response:
                    if isinstance(entry, dict) and 'name_value' in entry:
                        passive_subdomains.add(entry['name_value'].lower())
            elif source == "AlienVault":
                for entry in response.get("passive_dns", []):
                    if isinstance(entry, dict) and "hostname" in entry:
                        passive_subdomains.add(entry["hostname"])
    
    async with session.get(sources["RapidDNS"], timeout=10) as response:
        if response.status == 200:
            text = await response.text()
            found = re.findall(r'([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')', text)
            passive_subdomains.update(found)
    
    return passive_subdomains

async def check_wildcard(domain):
    """Detect if the domain has wildcard DNS."""
    wildcard_ips = set()
    try:
        test_subdomain = f"randomtest.{domain}"
        answers = dns.resolver.resolve(test_subdomain)
        wildcard_ips.update([str(ip) for ip in answers])
    except dns.resolver.NXDOMAIN:
        pass  # No wildcard detected
    except Exception:
        pass
    return wildcard_ips

async def brute_force_subdomains(domain, active_subdomains, wildcard_ips):
    """Brute-force subdomains using asyncio and aiohttp."""
    wordlist = "wordlists/common.txt"  # Default wordlist path
    if not os.path.exists(wordlist):
        return
    
    async with aio_open(wordlist, 'r') as file:
        words = [line.strip() for line in await file.readlines() if line.strip()]
    
    async def worker(subdomain):
        try:
            answers = dns.resolver.resolve(subdomain)
            resolved_ips = [str(ip) for ip in answers]
            if not wildcard_ips or not set(resolved_ips).issubset(wildcard_ips):
                active_subdomains.add(subdomain)
        except dns.resolver.NXDOMAIN:
            pass
        except Exception:
            pass
    
    tasks = []
    for word in words[:1000]:  # Limit to first 1000 for web interface
        subdomain = f"{word}.{domain}"
        tasks.append(worker(subdomain))
    
    await asyncio.gather(*tasks)

# ======================= URL Extraction Functions =======================
def extract_urls_from_text(text):
    """Extract URLs from plain text."""
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    urls = url_pattern.findall(text)
    
    # If no URLs found, treat lines as domains and prepend https://
    if not urls:
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        urls = [f"https://{line}" if not line.startswith(('http://', 'https://')) else line 
               for line in lines]
    return sorted(set(urls))  # Remove duplicates and sort

def extract_urls_from_script(script_content):
    """Extract URLs embedded in JavaScript."""
    return re.findall(r'(https?://[^\s"<>]+)', script_content)

def extract_urls_from_styles(styles_content):
    """Extract URLs from CSS styles."""
    return re.findall(r'url\(["\']?(https?://[^\s"<>]+)["\']?\)', styles_content)

def extract_links_from_html(soup, base_url):
    """Extract all links from HTML content."""
    links = set()
    
    # Standard links
    for link in soup.find_all('a', href=True):
        full_url = urljoin(base_url, link['href'])
        links.add(full_url)

    # Other potential URL attributes
    url_attrs = ['src', 'data-src', 'action', 'formaction', 'cite', 'data-url']
    for tag in soup.find_all(True):
        for attr in url_attrs:
            url = tag.get(attr)
            if url:
                full_url = urljoin(base_url, url)
                links.add(full_url)

    return links

def scrape_page(url):
    """Scrape all links from a webpage."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        if response.status_code != 200:
            return set()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        links = extract_links_from_html(soup, url)
        
        # Extract from JavaScript and CSS
        for script in soup.find_all('script'):
            if script.string:
                links.update(extract_urls_from_script(script.string))

        for style in soup.find_all('style'):
            if style.string:
                links.update(extract_urls_from_styles(style.string))

        return links
    
    except Exception as e:
        print(f"Error scraping {url}: {e}")
        return set()

def wayback_machine(domain):
    """Find archived URLs from Wayback Machine."""
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            results = response.json()[1:]  # Skip headers
            return {entry[2] for entry in results}
    except:
        pass
    return set()

# ======================= SQL Injection Routes =======================
SQL_ERRORS = [
    "you have an error in your sql syntax;",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "syntax error",
    "fatal error",
    "oracle error",
    "sql error",
    "native client",
    "unexpected end of SQL command",
    "database is locked"
]

UNION_BASED_TESTS = [
    "' UNION SELECT null, null --",
    "' UNION SELECT 1, 'test' --",
    "' UNION SELECT username, password FROM users --",
]

ERROR_BASED_TESTS = [
    "' OR 1=1 --",
    "' OR 'a'='a' --",
    """' OR CAST((SELECT count(*) FROM information_schema.tables) AS INT) > 0 --""",
]

BOOLEAN_BASED_TESTS = [
    "' AND 1=1 --",
    "' AND 1=0 --",
    "' AND EXISTS(SELECT * FROM users) --"
]

def sql_extract_params(url):
    parsed_url = urlparse(url)
    return parse_qs(parsed_url.query)

def sql_check_sqli(url, param, payload, method="GET"):
    encoded_payload = quote(payload)
    full_url = f"{url}&{param}={encoded_payload}" if '?' in url else f"{url}?{param}={encoded_payload}"

    try:
        if method.upper() == "POST":
            data = {param: payload}
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.get(full_url, timeout=5)

        result = f"[TEST] Testing {param} with payload: {payload}"
        scan_states['sql']['queue'].put(result)
        
        if response.status_code == 500 or any(err in response.text.lower() for err in SQL_ERRORS):
            vuln_result = f"[VULNERABLE] SQL Injection detected! Parameter: {param}, Payload: {payload}, URL: {full_url}"
            scan_states['sql']['vulnerability_found'] = True
            scan_states['sql']['queue'].put(vuln_result)
        
    except requests.exceptions.RequestException as e:
        error_msg = f"[ERROR] Request failed for {param} with payload {payload}: {str(e)}"
        scan_states['sql']['queue'].put(error_msg)

def sql_scan_worker(url, payload_file, method):
    try:
        params = sql_extract_params(url)
        if not params:
            scan_states['sql']['queue'].put("[ERROR] No parameters found in URL.")
            return
        
        with open(payload_file, 'r') as f:
            payloads = [line.strip() for line in f.readlines() if line.strip()]
        
        payloads += UNION_BASED_TESTS + ERROR_BASED_TESTS + BOOLEAN_BASED_TESTS
        
        total_tests = len(params) * len(payloads)
        tests_completed = 0
        
        for param in params:
            if scan_states['sql']['stop_requested']:
                break
                
            for payload in payloads:
                if scan_states['sql']['stop_requested']:
                    break
                    
                scan_states['sql']['current_test'] = f"Testing {param} with payload: {payload[:50]}..."
                sql_check_sqli(url, param, payload, method)
                
                tests_completed += 1
                scan_states['sql']['progress'] = int((tests_completed / total_tests) * 100)
                time.sleep(0.1)
        
        if scan_states['sql']['stop_requested']:
            scan_states['sql']['queue'].put("[INFO] Scan stopped by user")
        else:
            scan_states['sql']['queue'].put("[INFO] Scan completed")
            if not scan_states['sql']['vulnerability_found']:
                scan_states['sql']['queue'].put("[INFO] No vulnerabilities found")
                
    except Exception as e:
        scan_states['sql']['queue'].put(f"[ERROR] Scan failed: {str(e)}")
    finally:
        scan_states['sql']['running'] = False
        scan_states['sql']['stop_requested'] = False
        safe_remove(payload_file)

# ======================= XSS Routes =======================
def xss_load_payloads(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        return []

def xss_extract_parameters(url):
    try:
        parsed_url = urlparse(url)
        return list(parse_qs(parsed_url.query).keys())
    except Exception as e:
        scan_states['xss']['results'].append(f"[-] Error parsing URL parameters: {str(e)}")
        return []

def xss_validate_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if not validators.url(url):
        raise ValueError("Invalid URL format")
    return url

def xss_test_xss(url, param, payload, blind_mode):
    if scan_states['xss']['should_stop']:
        return
        
    try:
        validated_url = xss_validate_url(url)
        params = {param: payload}
        headers = {
            "User-Agent": "XSS-Scanner/1.0",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.5"
        }
        
        current_test = f"Testing {param}={payload[:30]}{'...' if len(payload) > 30 else ''}"
        scan_states['xss']['current_test'] = current_test
        
        get_test_msg = f"[TEST] GET {param}={payload[:30]}{'...' if len(payload) > 30 else ''}"
        scan_states['xss']['results'].append(get_test_msg)
        
        try:
            response = requests.get(
                validated_url,
                params=params,
                headers=headers,
                timeout=15,
                allow_redirects=False,
                verify=False
            )
            
            if not blind_mode and payload in response.text:
                result = f"[VULNERABLE] GET {param} - Payload: {payload[:50]}{'...' if len(payload) > 50 else ''}"
                scan_states['xss']['results'].append(result)
                return
        except requests.RequestException as e:
            scan_states['xss']['results'].append(f"[ERROR] GET test failed: {str(e)}")
            return
        
        post_test_msg = f"[TEST] POST {param}={payload[:30]}{'...' if len(payload) > 30 else ''}"
        scan_states['xss']['results'].append(post_test_msg)
        
        try:
            response = requests.post(
                validated_url,
                data=params,
                headers=headers,
                timeout=15,
                allow_redirects=False,
                verify=False
            )
            
            if not blind_mode and payload in response.text:
                result = f"[VULNERABLE] POST {param} - Payload: {payload[:50]}{'...' if len(payload) > 50 else ''}"
                scan_states['xss']['results'].append(result)
                return
        except requests.RequestException as e:
            scan_states['xss']['results'].append(f"[ERROR] POST test failed: {str(e)}")
            return
        
        if blind_mode:
            result = f"[BLIND] Payload sent to {param}: {payload[:30]}{'...' if len(payload) > 30 else ''}"
            scan_states['xss']['results'].append(result)
            
    except ValueError as e:
        scan_states['xss']['results'].append(f"[INVALID] {str(e)}")
    except Exception as e:
        scan_states['xss']['results'].append(f"[ERROR] Test setup failed: {str(e)}")

def xss_run_scan(url, payload_file_path, blind_mode):
    scan_states['xss']['running'] = True
    scan_states['xss']['progress'] = 0
    scan_states['xss']['results'] = []
    scan_states['xss']['vulnerability_found'] = False
    scan_states['xss']['current_test'] = "Initializing scan..."
    scan_states['xss']['should_stop'] = False
    
    try:
        scan_states['xss']['results'].append(f"[START] Scanning URL: {url}")
        scan_states['xss']['results'].append(f"[MODE] Blind XSS: {'ON' if blind_mode else 'OFF'}")
        
        parameters = xss_extract_parameters(url)
        if not parameters:
            parameters = ["q", "search", "input"]
            scan_states['xss']['results'].append("[INFO] Using default parameters")
        
        payloads = xss_load_payloads(payload_file_path)
        if not payloads:
            scan_states['xss']['results'].append("[ERROR] No payloads loaded")
            return
        
        total_tests = len(parameters) * len(payloads) * 2
        tests_completed = 0
        scan_states['xss']['results'].append(f"[INFO] Testing {len(parameters)} params with {len(payloads)} payloads")
        
        for param in parameters:
            if scan_states['xss']['should_stop']:
                break
                
            scan_states['xss']['results'].append(f"[PARAM] Testing: {param}")
            
            for payload in payloads:
                if scan_states['xss']['should_stop']:
                    break
                    
                xss_test_xss(url, param, payload, blind_mode)
                tests_completed += 2
                scan_states['xss']['progress'] = min(100, int((tests_completed / total_tests) * 100))
                time.sleep(0.2)
        
        if scan_states['xss']['should_stop']:
            scan_states['xss']['results'].append("[STOPPED] Scan stopped by user")
        else:
            scan_states['xss']['results'].append("[COMPLETE] Scan completed")
    except Exception as e:
        scan_states['xss']['results'].append(f"[CRITICAL] Scan failed: {str(e)}")
    finally:
        scan_states['xss']['running'] = False
        scan_states['xss']['progress'] = 100
        scan_states['xss']['current_test'] = "Scan completed"
        scan_states['xss']['should_stop'] = False
        safe_remove(payload_file_path)

# ======================= Directory Traversal Routes =======================
def traversal_run_scan(base_url, payload_file):
    try:
        with open(payload_file, 'r', encoding='utf-8', errors='ignore') as f:
            payloads = [line.strip() for line in f if line.strip()]
        
        scan_states['traversal']['total_payloads'] = len(payloads)
        
        for i, payload in enumerate(payloads):
            if scan_states['traversal']['stop_flag']:
                scan_states['traversal']['queue'].put("[INFO] Scan stopped")
                break
                
            scan_states['traversal']['current_payload'] = i + 1
            scan_states['traversal']['progress'] = int(((i + 1) / len(payloads)) * 100)
            scan_states['traversal']['current_test'] = f"Testing payload: {payload}"
            
            try:
                if '?' in base_url or '=' in base_url:
                    test_url = base_url + payload
                else:
                    test_url = urljoin(base_url + ('/' if not base_url.endswith('/') else ''), payload)
                
                test_url = test_url.replace(' ', '%20').replace('\\', '/')
                
                scan_states['traversal']['queue'].put(f"[TEST] Attempting: {test_url}")
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                    'Accept': 'text/html,application/xhtml+xml',
                    'Accept-Language': 'en-US,en;q=0.5'
                }
                
                response = requests.get(
                    test_url,
                    headers=headers,
                    timeout=10,
                    allow_redirects=False,
                    verify=False
                )
                
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    windows_indicators = ['[fonts]', '[extensions]', '[mail]', 'boot loader', 'operating systems]', 'shell=', 'device=']
                    linux_indicators = ['root:', 'bin/bash', '/bin/sh', 'daemon:', 'sys:', 'nobody:', '/etc/passwd']
                    common_indicators = ['<?php', '<html', '<!doctype', 'sqlite', 'database', 'configuration', 'apache', 'nginx', 'iis']
                    
                    vulnerable = any(
                        indicator in content 
                        for indicators in [windows_indicators, linux_indicators, common_indicators] 
                        for indicator in indicators
                    )
                    
                    if len(response.text) > 1000:
                        vulnerable = True
                    
                    if vulnerable:
                        scan_states['traversal']['vulnerability_found'] = True
                        scan_states['traversal']['vulnerable_url'] = test_url
                        scan_states['traversal']['queue'].put(f"[VULNERABLE] Directory Traversal found at: {test_url}")
                        scan_states['traversal']['queue'].put(f"Response preview:\n{response.text[:500]}...")
                
                scan_states['traversal']['queue'].put(f"[TEST] Status {response.status_code} for payload: {payload}")
                
            except requests.RequestException as e:
                scan_states['traversal']['queue'].put(f"[ERROR] Failed to test {test_url}: {str(e)}")
                continue
            
            time.sleep(0.5)
        
        if not scan_states['traversal']['vulnerability_found'] and not scan_states['traversal']['stop_flag']:
            scan_states['traversal']['queue'].put("[INFO] Scan completed - No vulnerabilities found")
        
    except Exception as e:
        scan_states['traversal']['queue'].put(f"[ERROR] Scan failed: {str(e)}")
    finally:
        scan_states['traversal']['running'] = False
        safe_remove(payload_file)

def cleanup_scan_state(scan_type):
    """Reset all state variables for a given scan type"""
    if scan_type == 'sql':
        scan_states[scan_type].update({
            'running': False,
            'progress': 0,
            'current_test': '',
            'vulnerability_found': False,
            'stop_requested': False,
            'queue': queue.Queue()  # Clear the queue
        })
    elif scan_type == 'xss':
        scan_states[scan_type].update({
            'running': False,
            'progress': 0,
            'results': [],
            'vulnerability_found': False,
            'current_test': "",
            'should_stop': False
        })
    elif scan_type == 'traversal':
        scan_states[scan_type].update({
            'running': False,
            'progress': 0,
            'current_test': '',
            'vulnerability_found': False,
            'stop_flag': False,
            'queue': queue.Queue()  # Clear the queue
        })
# ======================= Flask Routes =======================
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/subdomain')
def subdomain():
    return render_template('subdomain.html')
@app.route('/testing')
def testing():
    return render_template('testing.html')

@app.route('/url_grabber')
def url_grabber():
    return render_template('url_grabber.html')

@app.route('/sql_attack')
def sql_attack():
    return render_template('sql_attack.html')

@app.route('/xss_attack')
def xss_attack():
    return render_template('xss_attack.html')

@app.route('/directory_traversal')
def directory_traversal():
    return render_template('directory_traversal.html')

@app.route('/all_type_attack')
def all_type_attack():
    return render_template('all_type_attack.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

# Subdomain Enumeration Routes
@app.route('/grab_subdomains')
async def grab_subdomains():
    domain = request.args.get('domain', '').strip()
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    
    try:
        passive_subdomains = set()
        active_subdomains = set()
        
        async with aiohttp.ClientSession() as session:
            passive_subdomains = await passive_enumeration(domain, session)
            wildcard_ips = await check_wildcard(domain)
            await brute_force_subdomains(domain, active_subdomains, wildcard_ips)
        
        all_subdomains = sorted(passive_subdomains.union(active_subdomains))
        return jsonify({"subdomains": all_subdomains})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/save_subdomains', methods=['POST'])
async def save_subdomains():
    data = request.json
    domain = data.get('domain', '').strip()
    subdomains = data.get('subdomains', [])
    
    if not domain or not subdomains:
        return jsonify({"error": "Domain and subdomains are required"}), 400
    
    try:
        filename = f"subdomains_{domain}.txt"
        async with aio_open(filename, 'w') as f:
            await f.writelines(f"{sub}\n" for sub in subdomains)
        
        return jsonify({
            "message": f"Saved {len(subdomains)} subdomains to {filename}"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/extract_urls', methods=['POST'])
def handle_extraction():
    data = request.json
    input_type = data.get('type')
    content = data.get('content')
    
    if not content:
        return jsonify({"error": "No content provided"}), 400
    
    try:
        if input_type == 'text':
            urls = extract_urls_from_text(content)
        elif input_type == 'file':
            urls = extract_urls_from_text(content)
        else:
            return jsonify({"error": "Invalid input type"}), 400
        
        return jsonify({"urls": urls})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/scrape_urls', methods=['POST'])
def handle_scraping():
    data = request.json
    urls = data.get('urls', [])
    
    if not urls:
        return jsonify({"error": "No URLs provided"}), 400
    
    try:
        all_links = set()
        with ThreadPoolExecutor(max_workers=5) as executor:
            results = executor.map(scrape_page, urls)
            for links in results:
                all_links.update(links)
        
        return jsonify({"urls": sorted(all_links)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/save_urls', methods=['POST'])
def save_urls():
    data = request.json
    urls = data.get('urls', [])
    domain = data.get('domain', '')  # Added domain parameter
    
    if not urls:
        return jsonify({"error": "No URLs provided"}), 400
    
    try:
        # If domain is provided, append to domain-specific file
        if domain:
            filename = f"subdomains_{domain}.txt"
            mode = 'a'  # Append mode
        else:
            filename = "extracted_urls.txt"
            mode = 'w'  # Write mode
        
        with open(filename, mode) as f:
            f.write('\n'.join(urls) + '\n')
        
        return jsonify({
            "message": f"Saved {len(urls)} URLs to {filename}",
            "filename": filename
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# SQL Injection Routes
@app.route('/start_sql_scan', methods=['POST'])
def start_sql_scan():
    cleanup_scan_state('sql') 
    if scan_states['sql']['running']:
        return jsonify({'error': 'Scan already in progress'}), 400
    
    scan_states['sql'].update({
        'running': True,
        'progress': 0,
        'current_test': 'Initializing scan...',
        'vulnerability_found': False,
        'stop_requested': False
    })
    
    url = request.form.get('url')
    method = request.form.get('method', 'GET')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    if 'payloadFile' not in request.files:
        return jsonify({'error': 'No payload file provided'}), 400
    
    file = request.files['payloadFile']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    try:
        filename = secure_filename(file.filename)
        payload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(payload_path)
        
        thread = threading.Thread(target=sql_scan_worker, args=(url, payload_path, method))
        thread.start()
        
        return jsonify({'status': True})
    except Exception as e:
        return jsonify({'error': f'Error starting scan: {str(e)}'}), 500

@app.route('/stop_sql_scan', methods=['POST'])
def stop_sql_scan():
    if scan_states['sql']['running']:
        scan_states['sql']['stop_requested'] = True
        return jsonify({'status': True})
    return jsonify({'error': 'No scan in progress'}), 400

@app.route('/check_sql_status', methods=['GET'])
def check_sql_status():
    return jsonify({
        'running': scan_states['sql']['running'],
        'progress': scan_states['sql']['progress'],
        'current_test': scan_states['sql']['current_test'],
        'vulnerability_found': scan_states['sql']['vulnerability_found']
    })

@app.route('/stream_sql_results')
def stream_sql_results():
    def event_stream():
        while True:
            try:
                message = scan_states['sql']['queue'].get_nowait()
                yield f"data: {message}\n\n"
            except queue.Empty:
                if not scan_states['sql']['running']:
                    break
                time.sleep(0.5)
        yield "data: [END]\n\n"
    
    return Response(event_stream(), mimetype="text/event-stream")

# XSS Routes
@app.route('/start_xss_scan', methods=['POST'])
def start_xss_scan():
    cleanup_scan_state('xss') 
    if scan_states['xss']['running']:
        return jsonify({'status': False, 'error': 'Scan already in progress'})
    
    if 'payloadFile' not in request.files:
        return jsonify({'status': False, 'error': 'No payload file provided'})
    
    file = request.files['payloadFile']
    if file.filename == '':
        return jsonify({'status': False, 'error': 'No selected file'})
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)
    
    url = request.form.get('url', '').strip()
    blind_mode = request.form.get('blindMode') == 'true'
    
    if not url:
        return jsonify({'status': False, 'error': 'No URL provided'})
    
    try:
        xss_validate_url(url)
    except ValueError as e:
        return jsonify({'status': False, 'error': str(e)})
    
    threading.Thread(
        target=xss_run_scan,
        args=(url, file_path, blind_mode),
        daemon=True
    ).start()
    
    return jsonify({'status': True})

@app.route('/stop_xss_scan', methods=['POST'])
def stop_xss_scan():
    if not scan_states['xss']['running']:
        return jsonify({'success': False, 'message': 'No scan in progress'})
    
    scan_states['xss']['should_stop'] = True
    return jsonify({'success': True, 'message': 'Stop signal sent'})

@app.route('/stream_xss_results')
def stream_xss_results():
    def generate():
        last_index = 0
        while scan_states['xss']['running'] or last_index < len(scan_states['xss']['results']):
            if last_index < len(scan_states['xss']['results']):
                yield f"data: {scan_states['xss']['results'][last_index]}\n\n"
                last_index += 1
            time.sleep(0.1)
    return Response(generate(), mimetype='text/event-stream')

@app.route('/check_xss_status')
def check_xss_status():
    return jsonify({
        'running': scan_states['xss']['running'],
        'progress': scan_states['xss']['progress'],
        'vulnerability_found': scan_states['xss']['vulnerability_found'],
        'current_test': scan_states['xss']['current_test']
    })

# Directory Traversal Routes
@app.route('/start_traversal_scan', methods=['POST'])
def start_traversal_scan():
    cleanup_scan_state('traversal') 
    if scan_states['traversal']['running']:
        return jsonify({'error': 'Scan already in progress'}), 400

    scan_states['traversal'].update({
        'running': True,
        'progress': 0,
        'current_test': '',
        'vulnerability_found': False,
        'stop_flag': False
    })

    url = request.form['url']
    payload_file = request.files['payloadFile']
    
    filename = secure_filename(payload_file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    payload_file.save(filepath)
    
    threading.Thread(target=traversal_run_scan, args=(url, filepath), daemon=True).start()
    
    return jsonify({'status': True})

@app.route('/stream_traversal_results')
def stream_traversal_results():
    def generate():
        while True:
            try:
                message = scan_states['traversal']['queue'].get(timeout=1)
                yield f"data: {message}\n\n"
            except queue.Empty:
                if not scan_states['traversal']['running']:
                    yield "data: [INFO] Scan finished\n\n"
                    break
                yield ":keepalive\n\n"
    
    return Response(generate(), mimetype="text/event-stream")

@app.route('/check_traversal_status')
def check_traversal_status():
    return jsonify({
        'running': scan_states['traversal']['running'],
        'progress': scan_states['traversal']['progress'],
        'current_test': scan_states['traversal']['current_test'],
        'vulnerability_found': scan_states['traversal']['vulnerability_found']
    })

@app.route('/stop_traversal_scan', methods=['POST'])
def stop_traversal_scan():
    scan_states['traversal']['stop_flag'] = True
    return jsonify({'status': 'stopped'})

# Add this with your other routes in app.py

@app.route('/get_saved_url_files')
def get_saved_url_files():
    """List all saved URL files in the current directory"""
    try:
        # Get all files that start with 'subdomains_' or 'extracted_urls'
        files = [f for f in os.listdir() 
                if f.startswith('subdomains_') or f.startswith('extracted_urls')]
        return jsonify({'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_urls_from_file')
def get_urls_from_file():
    """Get URLs from a specific saved file"""
    filename = request.args.get('filename', '')
    if not filename:
        return jsonify({'error': 'Filename is required'}), 400
    
    try:
        with open(filename, 'r') as f:
            urls = [line.strip() for line in f.readlines() if line.strip()]
        return jsonify({'urls': urls})
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    app.run(debug=True, threaded=True)