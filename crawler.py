import re
import aiohttp
import asyncio
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
import collections

class WebCrawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = aiohttp.ClientSession()
        self.visited = set()
        
        # Wordlist potensi login page (dari daftar Anda)
        self.login_keywords = [
            'login', 'log-in', 'signin', 'sign-in', 'auth', 'authentication', 'account', 'user', 'users',
            'admin', 'administrator', 'secure', 'oauth', 'oauth2', 'sso', 'openid', 'saml', 'authz',
            'authorize', 'authorization', 'callback', 'token', 'tokens', 'refresh-token', 'access-token',
            'session', 'sessions', 'cookie', 'cookies', 'logout', 'signout', 'log-out', 'sign-out',
            'verify', 'verification', 'confirm', 'confirmation', 'activation', 'activate', 'my-profile',
            'myaccount', 'my-account', 'profile', 'profiles'
        ]

    async def fetch(self, url, extra_headers=None, cookies=None):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            if extra_headers:
                headers.update(extra_headers)
            print(f"[*] Request Headers for {url}: {headers}")
            async with self.session.get(url, headers=headers, cookies=cookies or {}, timeout=10) as response:
                if response.status == 200:
                    response_headers = dict(response.headers)
                    response_cookies = dict(response.cookies)
                    print(f"[*] Response Headers for {url}: {response_headers}")
                    print(f"[*] Cookies for {url}: {response_cookies}")
                    
                    html = await response.text()
                    return {
                        'html': html,
                        'headers': response_headers,
                        'cookies': response_cookies,
                        'url': str(response.url)  # Final URL setelah redirect
                    }
        except Exception as e:
            print(f"Error fetching {url}: {e}")
        return None

    async def extract_links(self, url, extra_headers=None, cookies=None):
        result = await self.fetch(url, extra_headers, cookies)
        if not result:
            return []
          
        html = result['html']
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
          
        for element in soup.find_all('a', href=True):
            href = element['href']
          
            if href.startswith(('#', 'javascript:', 'mailto:')):
                continue
              
            full_url = urljoin(url, href)
          
            if urlparse(full_url).netloc != urlparse(self.base_url).netloc:
                continue
              
            excluded_extensions = [
                '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.pdf',
                '.ico', '.svg', '.woff', '.ttf', '.xml', '.json', '.txt',
                '.zip', '.rar', '.tar', '.gz', '.7z', '.exe', '.dmg', '.iso'
            ]
            if any(full_url.lower().endswith(ext) for ext in excluded_extensions):
                continue
              
            parsed_url = urlparse(full_url)
            clean_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                '', '', ''
            ))
            clean_url = clean_url.rstrip('/')
          
            if '?' in full_url:
                continue
              
            if len(clean_url.split('/')) > 8:
                continue
              
            skip_patterns = [
                r'\/api\/', r'\/ajax\/', r'\/rest\/', r'\/graphql', r'\/ws\/', r'\/wss\/',
                r'\/feed\/', r'\/rss\/', r'\/atom\/', r'\/sitemap', r'\/\.well-known\/',
            ]
            if any(re.search(pattern, clean_url, re.IGNORECASE) for pattern in skip_patterns):
                continue
              
            if clean_url.strip() and clean_url not in links:
                links.add(clean_url)
                  
        return list(links)

    async def find_login_page(self, dir_file, extra_headers=None, cookies=None):
        # Baca existing directories dari dir_file
        known_urls = set()
        if os.path.exists(dir_file):
            with open(dir_file, 'r') as f:
                known_urls = {line.strip() for line in f if line.strip()}
        
        # Prioritas 1: Check URL dari wordlist potensi login (gabung dengan base_url)
        potential_login_urls = set()
        for keyword in self.login_keywords:
            potential_url = urljoin(self.base_url, keyword)
            potential_login_urls.add(potential_url)
        
        # Tambahkan known_urls ke potential (hindari double)
        potential_login_urls.update(known_urls)
        
        # Set visited untuk hindari double check
        self.visited = set()
        
        # Queue untuk crawling (prioritas potential login URLs dulu untuk optimasi)
        queue = collections.deque(list(potential_login_urls) + [self.base_url])
        
        batch_size = 100  # Batch 100 per iterasi
        while queue:
            batch = []
            for _ in range(min(batch_size, len(queue))):
                current_url = queue.popleft()
                if current_url in self.visited:
                    continue  # Hindari double check
                self.visited.add(current_url)
                batch.append(current_url)
            
            # Crawl batch dan analisis
            tasks = [self.fetch(url, extra_headers, cookies) for url in batch]
            results = await asyncio.gather(*tasks)
            
            for current_url, result in zip(batch, results):
                if not result:
                    continue
                
                fetched_url = result['url']  # Final URL setelah redirect
                
                # Analisis redirect: Jika redirect terjadi dan final URL punya indicator login
                if fetched_url != current_url:
                    print(f"[*] Redirect detected: {current_url} -> {fetched_url}")
                    # Check jika fetched_url punya indicator login
                    path = urlparse(fetched_url).path.lower()
                    if any(kw in path for kw in self.login_keywords):
                        # Analisis form di redirected URL
                        login_form = await self.crawl_login_page(fetched_url, extra_headers, cookies)
                        if login_form:
                            # Tambahkan ke dir_output jika belum ada
                            if fetched_url not in known_urls:
                                with open(dir_file, 'a') as f:
                                    f.write(fetched_url + '\n')
                                known_urls.add(fetched_url)
                                print(f"[+] Added redirected URL to dir_output: {fetched_url}")
                            return fetched_url, login_form  # Ditemukan, return
        
                # Analisis form di original fetched URL
                if any(kw in urlparse(fetched_url).path.lower() for kw in self.login_keywords):
                    print(f"[*] Checking potential login URL: {fetched_url}")
                    login_form = await self.crawl_login_page(fetched_url, extra_headers, cookies)
                    if login_form:
                        # Tambahkan ke dir_output jika belum ada
                        if fetched_url not in known_urls:
                            with open(dir_file, 'a') as f:
                                f.write(fetched_url + '\n')
                            known_urls.add(fetched_url)
                        return fetched_url, login_form
            
            # Jika tidak ditemukan di batch, extract links baru untuk batch berikutnya
            tasks = [self.extract_links(url, extra_headers, cookies) for url in batch]
            results = await asyncio.gather(*tasks)
            
            for urls in results:
                for link in urls:
                    # Optimasi: Hanya tambah link jika mengandung keyword login (minimalkan scan)
                    if link not in self.visited and link not in queue and any(kw in link.lower() for kw in self.login_keywords):
                        queue.append(link)
            
            print(f"[*] Processed batch of {len(batch)}, total visited: {len(self.visited)}, queue remaining: {len(queue)}")
            
            # Batasi total crawl (misal max 500 untuk hindari terlalu banyak)
            if len(self.visited) > 500:
                print("[!] Max crawl limit reached. No login form found.")
                break
        
        # Jika masih tidak ditemukan, tanya manual
        print("[!] Login page not found after analysis")
        manual_url = input("Enter login page URL manually: ").strip()
        login_form = await self.crawl_login_page(manual_url, extra_headers, cookies)
        if login_form:
            # Tambahkan ke dir_output jika belum ada
            if manual_url not in known_urls:
                with open(dir_file, 'a') as f:
                    f.write(manual_url + '\n')
            return manual_url, login_form
        return None, None

    
    async def crawl_login_page(self, url, extra_headers=None, cookies=None):
        result = await self.fetch(url, extra_headers, cookies)
        if not result:
            return None
        html = result['html']
        headers = result['headers']
        cookies = result['cookies']
      
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')
      
        for form in forms:
            if form.find('input', {'type': 'password'}):
                inputs = []
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                enctype = form.get('enctype', 'application/x-www-form-urlencoded').lower()
              
                if action:
                    action = urljoin(url, action)
                else:
                    action = url
              
                # Identify username and password fields
                username_field_candidates = []
                password_field = None
              
                for inp in form.find_all('input'):
                    input_name = inp.get('name', '')
                    input_type = inp.get('type', 'text')
                    input_value = inp.get('value', '')
                  
                    inputs.append({
                        'name': input_name,
                        'type': input_type,
                        'value': input_value
                    })
                  
                    if input_type == 'password':
                        password_field = input_name
                  
                    if input_type in ['text', 'email', 'number']:
                        username_field_candidates.append(input_name)
              
                username_field = None
                common_username_names = ['login', 'user', 'username', 'email', 'account']
                for candidate in username_field_candidates:
                    if any(name in candidate.lower() for name in common_username_names):
                        username_field = candidate
                        break
                if not username_field and len(username_field_candidates) == 1:
                    username_field = username_field_candidates[0]
                if not username_field and username_field_candidates:
                    username_field = username_field_candidates[0]
              
                has_hidden_with_value = any(
                    inp.get('type') == 'hidden' and inp.get('value', '') != ''
                    for inp in inputs
                )
                has_session_cookie = any('session' in key.lower() for key in cookies)
                is_complicated = has_hidden_with_value or has_session_cookie
              
                # Baseline OTP detected (narrowed)
                otp_keywords = ['otp', 'verification', 'two-factor', '2fa', 'twofactor', 'authenticator', 'verification code', 'mfa', 'one-time', 'security code', 'pin']
                baseline_otp_detected = any(keyword in html.lower() for keyword in otp_keywords) and (
                    '/sessions/two-factor' in action.lower() or 'two-factor' in url.lower() or 'otp' in url.lower()
                )
              
                # Baseline size
                baseline_size = len(html)
              
                return {
                    'action': action,
                    'method': method,
                    'inputs': inputs,
                    'username_field': username_field,
                    'password_field': password_field,
                    'is_complicated': is_complicated,
                    'headers': headers,
                    'cookies': cookies,
                    'baseline_otp_detected': baseline_otp_detected,
                    'baseline_size': baseline_size,
                    'enctype': enctype
                }
        return None
  
    async def crawl_form(self, url, keyword, extra_headers=None, cookies=None):
        """Search for forms containing specific keywords (e.g., 'search', 'register', etc.)"""
        result = await self.fetch(url, extra_headers, cookies)
        if not result:
            return None
          
        html = result['html']
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')
      
        for form in forms:
            form_text = form.text.lower()
            form_html = str(form).lower()
          
            if keyword.lower() in form_text or keyword.lower() in form_html:
                inputs = []
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                enctype = form.get('enctype', 'application/x-www-form-urlencoded').lower()
              
                if action:
                    action = urljoin(url, action)
                else:
                    action = url
              
                for inp in form.find_all('input'):
                    inputs.append({
                        'name': inp.get('name', ''),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', ''),
                        'placeholder': inp.get('placeholder', '')
                    })
              
                return {
                    'action': action,
                    'method': method,
                    'inputs': inputs,
                    'enctype': enctype
                }
        return None    
    async def crawl_otp_form(self, url, extra_headers=None, cookies=None):
        result = await self.fetch(url, extra_headers, cookies)
        if not result:
            return None

        html = result['html']
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')

        otp_keywords = ['otp', 'verification', 'two-factor', '2fa', 'twofactor', 'authenticator', 'verification code', 'mfa', 'one-time', 'security code', 'pin', 'app_otp', 'totp']

        for form in forms:
            inputs = form.find_all('input')
            has_otp_input = False

            # Improved detection: Require at least one non-hidden input likely for OTP
            for inp in inputs:
                inp_type = inp.get('type', 'text').lower()
                if inp_type == 'hidden':
                    continue
                name = inp.get('name', '').lower()
                placeholder = inp.get('placeholder', '').lower()
                id_ = inp.get('id', '').lower()
                maxlength = inp.get('maxlength', '')

                # Find associated label
                label = None
                if id_:
                    label = soup.find('label', {'for': id_})
                label_text = label.text.lower() if label else ''

                # Check if this input is OTP-like (spesifik keyword)
                if (
                    any(kw in name for kw in otp_keywords) or
                    any(kw in placeholder for kw in otp_keywords) or
                    any(kw in label_text for kw in otp_keywords) or
                    (maxlength and maxlength in ['4', '6', '8'] and (inp_type in ['text', 'number', 'tel']))
                ):
                    has_otp_input = True
                    break

            # Also check action or form text for confirmation
            action = form.get('action', '').lower()
            form_text = form.text.lower()
            form_html = str(form).lower()

            if has_otp_input and (
                'two-factor' in action or
                any(kw in form_text for kw in otp_keywords) or
                any(kw in form_html for kw in otp_keywords)
            ):
                inputs_list = []
                action_full = form.get('action', '')
                method = form.get('method', 'get').lower()
                enctype = form.get('enctype', 'application/x-www-form-urlencoded').lower()

                if action_full:
                    action_full = urljoin(url, action_full)
                else:
                    action_full = url

                # Ambil semua inputs dengan value asli (termasuk hidden)
                for inp in inputs:
                    inputs_list.append({
                        'name': inp.get('name', ''),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', '')  # Pertahankan value asli
                    })

                # Return dengan headers dan cookies lengkap dari response
                return {
                    'action': action_full,
                    'method': method,
                    'inputs': inputs_list,
                    'enctype': enctype,
                    'headers': result['headers'],  # Headers lengkap dari crawl
                    'cookies': result['cookies']   # Cookies lengkap dari crawl
                }
        return None
        
    async def close(self):
        await self.session.close()