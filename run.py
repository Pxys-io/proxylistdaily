import threading
import queue
import requests
import time
import sqlite3
import sys
import logging
import csv
import json
import re  # Added for advanced parsing
from datetime import datetime
from bs4 import BeautifulSoup

# --- DEPENDENCY NOTE ---
# To test SOCKS proxies with the 'requests' library, you MUST install PySocks.
# Run: pip install pysocks
# The script will still run without it, but SOCKS checks will fail.

# --- CONFIGURATION ---
DB_FILE = 'proxies.db'
LOG_FILE = 'proxy_manager.log'
TEST_URL = 'http://httpbin.org/ip'
TIMEOUT = 10
NUM_CHECKER_THREADS = 150
SAVE_INTERVAL = 60  # Save working proxies every 60 seconds

# --- PRIORITY CONSTANTS ---
PRIORITY_HTTP = 1
PRIORITY_SOCKS = 2

# --- GLOBAL COMPONENTS ---
proxies_to_check_q = queue.PriorityQueue()
db_writer_q = queue.Queue()
stop_event = threading.Event()
entry_counter = 0
entry_counter_lock = threading.Lock()
checked_counter = 0
working_counter = 0
counter_lock = threading.Lock()
last_save_time = time.time()


# --- 1. SETUP LOGGING ---
def setup_logging():
    """Configures two log handlers: one for a detailed file, one for a clean console."""
    # Prevent duplicate handlers if this function is called again
    if logging.getLogger().hasHandlers():
        logging.getLogger().handlers.clear()

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(LOG_FILE, mode='w')
    file_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)


# --- 2. DATABASE MANAGER ---
def get_working_proxies_from_db(limit=10):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT protocol, proxy_address FROM working_proxies ORDER BY latency_ms ASC LIMIT ?",
            (limit, ))
        proxies = [{
            "protocol": row[0],
            "proxy": row[1]
        } for row in cursor.fetchall()]
        conn.close()
        if proxies:
            logging.info(
                f"Loaded {len(proxies)} meta-proxies from the database for retries."
            )
        return proxies
    except sqlite3.OperationalError:
        return []


def db_writer_worker():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()
    logging.info("DB Writer ready.")
    while not stop_event.is_set() or not db_writer_q.empty():
        try:
            query, params = db_writer_q.get(timeout=1)
            cursor.execute(query, params)
            conn.commit()
            db_writer_q.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            logging.error(f"DB Writer error: {e}")
    conn.close()
    logging.info("DB Writer shutdown complete.")


def setup_database():
    logging.info("Initializing database...")
    db_writer_q.put(('''
        CREATE TABLE IF NOT EXISTS all_proxies (
            proxy_address TEXT PRIMARY KEY, protocol TEXT, source TEXT,
            first_seen TEXT, last_seen TEXT
        )''', ()))
    db_writer_q.put(('''
        CREATE TABLE IF NOT EXISTS working_proxies (
            proxy_address TEXT PRIMARY KEY, protocol TEXT, source TEXT, latency_ms INTEGER,
            country TEXT, anonymity TEXT, last_tested TEXT
        )''', ()))
    db_writer_q.join()
    logging.info("Database initialization confirmed.")


# --- 3. SCRAPER FUNCTIONS ---
def put_proxy_in_queue(priority, proxy_info):
    global entry_counter
    with entry_counter_lock:
        entry_counter += 1
        proxies_to_check_q.put((priority, entry_counter, proxy_info))


def resilient_get(url, headers=None):
    if headers is None:
        headers = {
            'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    try:
        source_name = url.split('/')[2]
    except IndexError:
        source_name = url
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        logging.warning(
            f"Direct request to {source_name} failed. Attempting with meta-proxies..."
        )
    meta_proxies = get_working_proxies_from_db()
    if not meta_proxies:
        logging.error(
            f"Cannot scrape {source_name}: No working meta-proxies in DB to retry with."
        )
        return None
    for meta_proxy in meta_proxies:
        try:
            protocol, proxy_address = meta_proxy['protocol'], meta_proxy[
                'proxy']
            proxy_dict = {
                'http': f"{protocol}://{proxy_address}",
                'https': f"{protocol}://{proxy_address}"
            }
            response = requests.get(url,
                                    headers=headers,
                                    proxies=proxy_dict,
                                    timeout=20)
            response.raise_for_status()
            logging.info(
                f"Successfully fetched {source_name} using meta-proxy {proxy_address}"
            )
            return response
        except requests.RequestException:
            logging.warning(
                f"Meta-proxy {meta_proxy['proxy']} failed for {source_name}. Trying next one."
            )
    logging.error(
        f"All meta-proxies failed for {source_name}. Cannot scrape this source."
    )
    return None


# --- Existing Scrapers ---
def scrape_proxyscrape(protocol):
    priority = PRIORITY_SOCKS if 'socks' in protocol else PRIORITY_HTTP
    url = f"https://api.proxyscrape.com/v2/?request=getproxies&protocol={protocol}&timeout=10000&country=all"
    try:
        # This API is generally reliable, so we can try a direct request first
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        count = 0
        for proxy in response.text.strip().splitlines():
            proxy = proxy.strip()
            if proxy:
                put_proxy_in_queue(priority, {
                    'protocol': protocol,
                    'proxy': proxy,
                    'source': 'ProxyScrape'
                })
                count += 1
        logging.info(
            f"ProxyScrape ({protocol.upper()}): Found {count} proxies.")
    except Exception as e:
        logging.error(f"ProxyScrape ({protocol.upper()}): {e}")


def scrape_html_table(url, priority):
    source_name = url.split('/')[2]
    response = resilient_get(url)
    if not response: return
    try:
        soup = BeautifulSoup(response.text, 'lxml')
        table = soup.find("table", {"class": "table"}) or soup.find("table")
        count = 0
        for row in table.find_all("tr")[1:]:
            cells = row.find_all("td")
            if len(cells) > 1:
                ip, port = cells[0].text.strip(), cells[1].text.strip()
                if not ip or not port: continue
                protocol = 'https' if len(cells) > 6 and cells[6].text.strip(
                ).lower() == 'yes' else 'http'
                put_proxy_in_queue(
                    priority, {
                        'protocol': protocol,
                        'proxy': f"{ip}:{port}",
                        'source': source_name
                    })
                count += 1
        logging.info(f"{source_name}: Found {count} proxies.")
    except Exception as e:
        logging.error(f"Failed to parse table from {source_name}: {e}")


# --- NEW SCRAPER FUNCTIONS ---
def scrape_github_raw_text(url, protocol, source_name):
    """Scrapes proxies from a raw text file on GitHub or similar sites."""
    priority = PRIORITY_SOCKS if 'socks' in protocol else PRIORITY_HTTP
    response = resilient_get(url)
    if not response: return
    count = 0
    for proxy in response.text.strip().splitlines():
        proxy = proxy.strip()
        if proxy:
            put_proxy_in_queue(priority, {
                'protocol': protocol,
                'proxy': proxy,
                'source': source_name
            })
            count += 1
    logging.info(f"{source_name} ({protocol.upper()}): Found {count} proxies.")


def scrape_geonode_api():
    """Scrapes proxies from the Geonode.com free proxy list API."""
    # API provides up to 500 proxies on the free plan
    url = "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc"
    response = resilient_get(url)
    if not response: return
    try:
        data = response.json()
        count = 0
        for p in data.get('data', []):
            proxy_address = f"{p['ip']}:{p['port']}"
            for protocol in p.get('protocols', []):
                protocol = protocol.strip()
                if not protocol: continue
                priority = PRIORITY_SOCKS if 'socks' in protocol else PRIORITY_HTTP
                put_proxy_in_queue(
                    priority, {
                        'protocol': protocol,
                        'proxy': proxy_address,
                        'source': 'GeonodeAPI'
                    })
                count += 1
        logging.info(f"GeonodeAPI: Found {count} proxy entries.")
    except Exception as e:
        logging.error(f"Failed to parse JSON from GeonodeAPI: {e}")


def scrape_json_list(url, source_name):
    """Scrapes proxies from a JSON list file."""
    response = resilient_get(url)
    if not response: return
    try:
        data = response.json()
        count = 0
        for p in data:
            proxy_address = f"{p['ip']}:{p['port']}"
            protocol = p.get('protocol', 'http') # Default to http if not specified
            priority = PRIORITY_SOCKS if 'socks' in protocol else PRIORITY_HTTP
            put_proxy_in_queue(priority, {
                'protocol': protocol,
                'proxy': proxy_address,
                'source': source_name
            })
            count += 1
        logging.info(f"{source_name}: Found {count} proxy entries.")
    except Exception as e:
        logging.error(f"Failed to parse JSON from {source_name}: {e}")


def scrape_spys_one():
    """Scrapes spys.one, dealing with JavaScript-obfuscated ports."""
    url = "http://spys.one/en/free-proxy-list/"
    try:
        response = resilient_get(url)
        if not response: return

        # 1. Extract the secret variables used for port calculation
        port_vars = {}
        # This regex finds all variable assignments like 'b5p=3;o9q=0;...'
        var_defs = re.findall(r'([a-z0-9]{3,})=([0-9]{1,});', response.text)
        for var, val in var_defs:
            port_vars[var] = int(val)

        # 2. Find all proxy entries and parse them
        count = 0
        # This regex finds the IP, the port calculation script, and the protocol type
        proxy_entries = re.findall(
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})<script.*?write\(":"\+((?:[a-z0-9]{3,}\^)+[a-z0-9]{3,})\).*?>(SOCKS5|HTTP|HTTPS)<',
            response.text)
        for ip, port_expr, protocol in proxy_entries:
            try:
                # 3. Calculate the actual port
                port_parts = port_expr.split('^')
                port = 0
                for part in port_parts:
                    port ^= port_vars[part]

                proxy_address = f"{ip}:{port}"
                protocol = 'socks5' if 'SOCKS' in protocol else 'http'
                priority = PRIORITY_SOCKS if protocol == 'socks5' else PRIORITY_HTTP
                put_proxy_in_queue(
                    priority, {
                        'protocol': protocol,
                        'proxy': proxy_address,
                        'source': 'Spys.one'
                    })
                count += 1
            except KeyError as e:
                logging.warning(
                    f"Spys.one: Could not find port variable {e} for a proxy. Skipping."
                )
            except Exception as e:
                logging.warning(
                    f"Spys.one: Error processing a proxy entry: {e}")
        logging.info(f"Spys.one: Found and decoded {count} proxies.")
    except Exception as e:
        logging.error(f"Failed to scrape Spys.one: {e}")


# --- 4. CHECKER WORKER ---
def proxy_checker_worker():
    global checked_counter, working_counter
    headers = {
        'User-Agent':
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    while not stop_event.is_set():
        try:
            _priority, _count, proxy_info = proxies_to_check_q.get(timeout=1)
        except queue.Empty:
            if stop_event.is_set() and proxies_to_check_q.empty(): break
            continue
        protocol, proxy_address = proxy_info['protocol'], proxy_info['proxy']
        now = datetime.utcnow().isoformat(timespec='seconds')
        db_writer_q.put((
            "INSERT INTO all_proxies (proxy_address, protocol, source, first_seen, last_seen) VALUES (?, ?, ?, ?, ?) ON CONFLICT(proxy_address) DO UPDATE SET last_seen=excluded.last_seen, protocol=excluded.protocol, source=excluded.source",
            (proxy_address, protocol, proxy_info['source'], now, now)))
        proxy_dict = {
            'http': f"{protocol}://{proxy_address}",
            'https': f"{protocol}://{proxy_address}"
        }
        try:
            start_time = time.time()
            response = requests.get(TEST_URL,
                                    headers=headers,
                                    proxies=proxy_dict,
                                    timeout=TIMEOUT)
            response.raise_for_status()
            # We can also add a check to ensure the IP is different from our own.
            # my_ip = requests.get('http://httpbin.org/ip').json()['origin']
            # if my_ip in response.text: continue

            latency = round((time.time() - start_time) * 1000)
            db_writer_q.put((
                "INSERT INTO working_proxies (proxy_address, protocol, source, latency_ms, country, anonymity, last_tested) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(proxy_address) DO UPDATE SET latency_ms=excluded.latency_ms, last_tested=excluded.last_tested, source=excluded.source",
                (proxy_address, protocol, proxy_info['source'], latency,
                 proxy_info.get('country',
                                'N/A'), proxy_info.get('anonymity',
                                                       'N/A'), now)))
            with counter_lock:
                working_counter += 1
        except Exception:
            pass
        finally:
            with counter_lock:
                checked_counter += 1
            proxies_to_check_q.task_done()


# --- 5. FINAL REPORT GENERATOR ---
def generate_output_files():
    logging.info("Generating final output files...")
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT protocol, proxy_address, latency_ms, country, anonymity, source, last_tested FROM working_proxies ORDER BY latency_ms ASC"
        )
        results = cursor.fetchall()
        conn.close()
        if not results:
            logging.warning(
                "No working proxies found in the database. Output files will be empty."
            )
            open('working_proxies.csv', 'w').close()
            open('working_proxies.txt', 'w').close()
            return
        with open('working_proxies.csv', 'w', newline='',
                  encoding='utf-8') as f_csv:
            writer = csv.writer(f_csv)
            writer.writerow([
                'protocol', 'proxy_address', 'latency_ms', 'ssl_support',
                'country', 'anonymity', 'source', 'last_tested'
            ])
            for row in results:
                protocol, proxy, latency, country, anon, source, last_tested = row
                writer.writerow([
                    protocol, proxy, latency, (protocol == 'https'), country,
                    anon, source, last_tested
                ])
        with open('working_proxies.txt', 'w', encoding='utf-8') as f_txt:
            for row in results:
                f_txt.write(f"{row[0]}://{row[1]}\n")
        logging.info(
            f"Successfully generated working_proxies.csv and working_proxies.txt with {len(results)} proxies."
        )
    except Exception as e:
        logging.error(f"Failed to generate output files: {e}")


# --- 6. MAIN EXECUTION BLOCK ---
if __name__ == '__main__':
    setup_logging()
    logging.info("--- Smart Proxy Manager Starting ---")

    # Check for PySocks dependency for full functionality
    try:
        import socks
        logging.info("PySocks is installed. SOCKS proxy checking is enabled.")
    except ImportError:
        logging.warning(
            "PySocks is not installed (pip install pysocks). SOCKS proxies will not be checked correctly."
        )

    db_thread = threading.Thread(target=db_writer_worker, name="DBWriter")
    db_thread.start()
    setup_database()

    # Expanded list of scraper tasks
    scraper_tasks = [
        # --- Original Sources ---
        {
            'target': scrape_html_table,
            'args': ('https://www.sslproxies.org/', PRIORITY_HTTP),
            'name': 'Scraper-SSLProxies'
        },
        {
            'target': scrape_html_table,
            'args': ('https://free-proxy-list.net/', PRIORITY_HTTP),
            'name': 'Scraper-FreeProxyList'
        },
        {
            'target': scrape_proxyscrape,
            'args': ('http', ),
            'name': 'Scraper-ProxyScrape-HTTP'
        },
        {
            'target': scrape_proxyscrape,
            'args': ('socks4', ),
            'name': 'Scraper-ProxyScrape-SOCKS4'
        },
        {
            'target': scrape_proxyscrape,
            'args': ('socks5', ),
            'name': 'Scraper-ProxyScrape-SOCKS5'
        },

        # --- New Sources ---

        # Proxifly GitHub Aggregator (High Volume Raw Text Files)
        {
            'target':
            scrape_github_raw_text,
            'args':
            ('https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt',
             'http', 'Proxifly-GitHub'),
            'name':
            'Scraper-Proxifly-HTTP'
        },
        {
            'target':
            scrape_github_raw_text,
            'args':
            ('https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt',
             'socks4', 'Proxifly-GitHub'),
            'name':
            'Scraper-Proxifly-SOCKS4'
        },
        {
            'target':
            scrape_github_raw_text,
            'args':
            ('https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt',
             'socks5', 'Proxifly-GitHub'),
            'name':
            'Scraper-Proxifly-SOCKS5'
        },

        # HTML Table Scrapers
        {
            'target': scrape_html_table,
            'args': ('http://free-proxy.cz/en/', PRIORITY_HTTP),
            'name': 'Scraper-FreeProxyCZ'
        },
        {
            'target': scrape_html_table,
            'args': ('https://proxydb.net/', PRIORITY_HTTP),
            'name': 'Scraper-ProxyDB'
        },

        # JSON Aggregator
        {
            'target': scrape_json_list,
            'args': ('https://raw.githubusercontent.com/monosans/proxy-list/main/proxies.json',
                     'monosans-GitHub'),
            'name': 'Scraper-monosans-JSON'
        },

        # GitHub Aggregators (High Volume)
        {
            'target':
            scrape_github_raw_text,
            'args':
            ('https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt',
             'http', 'TheSpeedX-GitHub'),
            'name':
            'Scraper-TheSpeedX-HTTP'
        },
        {
            'target':
            scrape_github_raw_text,
            'args':
            ('https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt',
             'socks4', 'TheSpeedX-GitHub'),
            'name':
            'Scraper-TheSpeedX-SOCKS4'
        },
        {
            'target':
            scrape_github_raw_text,
            'args':
            ('https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt',
             'socks5', 'TheSpeedX-GitHub'),
            'name':
            'Scraper-TheSpeedX-SOCKS5'
        },
        {
            'target':
            scrape_github_raw_text,
            'args':
            ('https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt',
             'http', 'Jetkai-GitHub'),
            'name':
            'Scraper-Jetkai-HTTP'
        },
        {
            'target':
            scrape_github_raw_text,
            'args':
            ('https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt',
             'https', 'Jetkai-GitHub'),
            'name':
            'Scraper-Jetkai-HTTPS'
        },
        {
            'target':
            scrape_github_raw_text,
            'args':
            ('https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt',
             'socks4', 'Jetkai-GitHub'),
            'name':
            'Scraper-Jetkai-SOCKS4'
        },
        {
            'target':
            scrape_github_raw_text,
            'args':
            ('https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt',
             'socks5', 'Jetkai-GitHub'),
            'name':
            'Scraper-Jetkai-SOCKS5'
        },

        # API-based Source
        {
            'target': scrape_geonode_api,
            'args': (),
            'name': 'Scraper-GeonodeAPI'
        },

        # Advanced Scraper (JS Obfuscation)
        {
            'target': scrape_spys_one,
            'args': (),
            'name': 'Scraper-SpysOne'
        },
    ]

    scraper_threads = [
        threading.Thread(target=task['target'],
                         args=task['args'],
                         name=task['name']) for task in scraper_tasks
    ]

    logging.info(f"Starting scraping from {len(scraper_tasks)} sources...")
    for t in scraper_threads:
        t.start()
    for t in scraper_threads:
        t.join()

    total_to_check = proxies_to_check_q.qsize()
    if total_to_check == 0:
        logging.critical(
            "No proxies were scraped. Check network connection or scraper functions. Exiting."
        )
        stop_event.set()
    else:
        logging.info(
            f"Scraped a total of {total_to_check} unique proxy entries. Starting checks..."
        )
        checker_threads = [
            threading.Thread(target=proxy_checker_worker,
                             name=f"Checker-{i+1}")
            for i in range(NUM_CHECKER_THREADS)
        ]
        for t in checker_threads:
            t.start()

        while checked_counter < total_to_check:
            with counter_lock:
                print(
                    f"\rProgress: Checked {checked_counter}/{total_to_check} | Working: {working_counter}",
                    end="")
            current_time = time.time()
            if current_time - last_save_time >= SAVE_INTERVAL:
                db_writer_q.join()
                generate_output_files()
                last_save_time = current_time
                logging.info("Periodic save completed.")
            time.sleep(1)
        print()  # Final newline to clear the progress bar

        logging.info(
            "All checker tasks are complete. Signaling threads to stop.")
        stop_event.set()
        for t in checker_threads:
            t.join()

    logging.info("Shutting down database writer...")
    db_writer_q.join()
    db_thread.join()

    generate_output_files()
    logging.info("--- Process Complete ---")
