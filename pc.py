import argparse
import threading
import requests
import random
import time
import sys
from tqdm import tqdm
from datetime import datetime
import json

request_count_lock = threading.Lock()
print_lock = threading.Lock()
stats_lock = threading.Lock()

def format_proxy(proxy):
    """Ensure proxy has the correct format"""
    if proxy:
        proxy = proxy.replace('http://', '').replace('https://', '')
    return proxy

def format_domain(domain):
    """Ensure domain has the correct format"""
    if not domain.startswith("http"):
        return f"http://{domain}"
    return domain

def get_isp_info(ip, max_retries=1):
    """Fetch ISP information for the given IP address using ip-api.com"""
    try:
        
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json'
        })
        
        
        response = session.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=2
        )
        
        if response.status_code == 200:
            data = response.json()
            org = data.get('org', '')
            asn = data.get('asn', '')
            return f"{org} ({asn})" if org and asn else org or asn or "Unknown ISP"
        
        
        response = session.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,isp,org",
            timeout=2
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return data.get('isp', '') or data.get('org', '') or "Unknown ISP"
        
        return "Unknown ISP"
            
    except requests.RequestException:
        try:
            
            response = session.get(
                f"https://ipwho.is/{ip}",
                timeout=2
            )
            if response.status_code == 200:
                data = response.json()
                return data.get('connection', {}).get('isp', 'Unknown ISP')
        except:
            pass
        
        return "Unknown ISP"
    finally:
        session.close()

def visit_target(domain, proxy, thread_id, isp_flag, max_retries=1):
    """Visit target with no retry logic for maximum speed"""
    proxies = {"http": format_proxy(proxy), "https": format_proxy(proxy)} if proxy else None
    
    isp_info = None
    if isp_flag and proxy:
        proxy_ip = format_proxy(proxy).split(":")[0]
        isp_info = get_isp_info(proxy_ip)
    
    try:
        start_time = time.time()
        response = requests.get(
            domain, 
            proxies=proxies, 
            timeout=2,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        elapsed_time = time.time() - start_time
        
        with print_lock:
            status_icon = "✅" if response.status_code == 200 else "⚠️" if response.status_code < 500 else "❌"
            proxy_info = f"{proxy if proxy else 'Direct'}"
            if isp_info:
                isp_display = (
                    f"[ISP: \033[38;5;51m⟨\033[38;5;45m◈\033[38;5;39m "  
                    f"\033[1;38;5;51m{isp_info}\033[0m"  
                    f"\033[38;5;39m ◈\033[38;5;45m⟩\033[0m"  
                )
                proxy_info += f" {isp_display}"
            
            status_color = "\033[1;32m"  
            if response.status_code >= 500:
                status_color = "\033[1;31m"  
            elif response.status_code >= 400:
                status_color = "\033[1;33m"  
            elif response.status_code >= 300:
                status_color = "\033[1;34m" 
            
            print(f"\r{status_icon} [{thread_id:02d}] {proxy_info} → {domain} "
                  f"(Status: {status_color}{response.status_code}\033[0m, Time: {elapsed_time:.2f}s)")
        return True, response.status_code, elapsed_time
        
    except (requests.exceptions.Timeout,
            requests.exceptions.ProxyError,
            requests.exceptions.ConnectionError,
            requests.RequestException) as e:
        with print_lock:
            error_msg = str(e)[:50] + "..." if len(str(e)) > 50 else str(e)
            print(f"\r❌ [{thread_id:02d}] {proxy if proxy else 'Direct'} → {domain} "
                  f"(Error: {error_msg})")
    
    return False, None, None

def validate_proxy(proxy):
    """Validate proxy format"""
    if not proxy:
        return False
    
    try:
        parts = proxy.split(':')
        if len(parts) != 2:
            return False
        
        port = int(parts[1])
        if not (0 <= port <= 65535):
            return False
            
        return True
    except:
        return False

def run_scan(domain, proxy=None, proxy_list=None, threads=1, isp_flag=False):
    domain = format_domain(domain)
    proxies = []
    successful_proxies = set()

    try:
        requests.get(domain, timeout=5)
    except requests.RequestException:
        print(f"❌ Error: Unable to reach target domain {domain}. Please verify the domain is accessible.")
        return

    print("\n🚀 PROXY SCANNER")
    print("――――――――――――――――――――――――")
    print(f"🎯 Target: {domain}")
    print(f"🧵 Threads: {threads}")
    print(f"🔧 Mode: {'Multiple Proxies' if proxy_list else 'Single Proxy' if proxy else 'Direct'}")
    if isp_flag:
        print(f"🌍 ISP Info: Enabled")
    print("――――――――――――――――――――――――\n")
    
    stats = {
        'successful_requests': 0,
        'failed_requests': 0,
        'status_codes': {},
        'total_time': 0,
        'fastest_proxy': (None, float('inf')),
        'slowest_proxy': (None, 0)
    }
    
    if proxy_list:
        try:
            with open(proxy_list, 'r') as file:
                proxies = []
                for line in file:
                    proxy = format_proxy(line.strip())
                    if validate_proxy(proxy):
                        proxies.append(proxy)
                    else:
                        print(f"⚠️ Skipping invalid proxy format: {line.strip()}")
                        
            print(f"📋 Loaded {len(proxies)} valid proxies from {proxy_list}\n")
            if not proxies:
                print("❌ Error: No valid proxies found in proxy list.")
                return
        except FileNotFoundError:
            print("❌ Error: Proxy list file not found.")
            return
    elif proxy:
        if not validate_proxy(format_proxy(proxy)):
            print("❌ Error: Invalid proxy format.")
            return
        proxies.append(format_proxy(proxy))
    

    total_requests = len(proxies)
    progress_bar = tqdm(total=total_requests, 
                       desc="🔍 Progress", 
                       unit="req",
                       bar_format="{desc}: {percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")
    request_count = 0
    start_time = time.time()
    
    def worker(thread_id):
        nonlocal request_count
        while True:
            with request_count_lock:
                if request_count >= total_requests:
                    break
                current_proxy = proxies[request_count] if proxies else None
                request_count += 1
            
            success, status_code, elapsed_time = visit_target(domain, current_proxy, thread_id, isp_flag)
            
            with stats_lock:
                if success:
                    stats['successful_requests'] += 1
                    stats['status_codes'][status_code] = stats['status_codes'].get(status_code, 0) + 1
                    stats['total_time'] += elapsed_time
                    if elapsed_time < stats['fastest_proxy'][1]:
                        stats['fastest_proxy'] = (current_proxy, elapsed_time)
                    if elapsed_time > stats['slowest_proxy'][1]:
                        stats['slowest_proxy'] = (current_proxy, elapsed_time)
                   
                    if status_code == 200 and current_proxy:
                        clean_proxy = current_proxy.replace('http://', '').replace('https://', '')
                        successful_proxies.add(clean_proxy)
                else:
                    stats['failed_requests'] += 1
            
            progress_bar.update(1)
            
            with print_lock:
                elapsed_total_time = time.time() - start_time
                rate = request_count / elapsed_total_time if elapsed_total_time > 0 else 0
                remaining_time = (total_requests - request_count) / rate if rate > 0 else 0
                print(f"\rRate: {rate:.2f} req/sec | Remaining Time: {remaining_time:.2f}s", end='')

    thread_list = []
    for i in range(threads):
        t = threading.Thread(target=worker, args=(i,))
        t.daemon = True
        thread_list.append(t)
        t.start()
    
    try:
        for t in thread_list:
            t.join()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    
    progress_bar.close()
    
    print("\n📊 SCAN RESULTS")
    print("――――――――――――――――――――――――")
    print(f"📈 Total Requests: {total_requests}")
    print(f"✅ Successful: {stats['successful_requests']}")
    print(f"❌ Failed: {stats['failed_requests']}")
    
    print("\n📊 Status Codes:")
    for status, count in stats['status_codes'].items():
        percentage = (count / total_requests) * 100
        bar = "■" * int(percentage/5)  
    
        status_color = "\033[1;32m"  
        if status >= 500:
            status_color = "\033[1;31m"  
        elif status >= 400:
            status_color = "\033[1;33m"  
        elif status >= 300:
            status_color = "\033[1;34m"  
            
        print(f"    {status_color}{status}\033[0m: {count} ({percentage:.1f}%) {bar}")
    
    if stats['successful_requests'] > 0:
        avg_time = stats['total_time'] / stats['successful_requests']
        print("\n⚡ Performance:")
        print(f"    ⏱️  Average Response: {avg_time:.2f}s")
        print(f"    🏃 Fastest Proxy: {stats['fastest_proxy'][0]} ({stats['fastest_proxy'][1]:.2f}s)")
        print(f"    🐌 Slowest Proxy: {stats['slowest_proxy'][0]} ({stats['slowest_proxy'][1]:.2f}s)")
    
   
    if successful_proxies:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"working_proxies_{timestamp}.txt"
        working_proxy_count = len(successful_proxies)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Target Domain: {domain}\n")
            f.write(f"Total Working Proxies Found: {working_proxy_count}\n")
            f.write("-----------------------\n") 
            for proxy in successful_proxies:
                f.write(f"{proxy}\n")
        print(f"\n💾 Working proxies saved to: {filename}")
        print(f"📌 Found {working_proxy_count} working {'proxy' if working_proxy_count == 1 else 'proxies'}")
    
    print("――――――――――――――――――――――――\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Scan with Proxies & UI Feedback.")
    parser.add_argument("-d", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-p", help="Single proxy (e.g., 123.45.67.89:8080)")
    parser.add_argument("-l", help="File containing list of proxies (each line: 123.45.67.89:8080)")
    parser.add_argument("-t", type=int, default=1, help="Number of threads")
    parser.add_argument("-isp", action='store_true', help="Display ISP information for proxies")
    
    args = parser.parse_args()
    
    if not args.p and not args.l:
        print("Error: You must provide either a single proxy (-p) or a proxy list (-l)")
    else:
        run_scan(args.d, proxy=args.p, proxy_list=args.l, threads=args.t, isp_flag=args.isp) 
