import aiohttp
import asyncio
import os
import json
from crawler import WebCrawler
from auth_tester import AuthTester
from bruteforce import DirectoryBruteforcer
from urllib.parse import urljoin
def generate_report(safe_host, directories, successful_logins, brute_success, otp_brute_success, manual_used):
    html = """
<html>
<head><title>Report for {safe_host}</title></head>
<body>
<h1>Security Test Report for {safe_host}</h1>
<h2>Directories Crawled</h2>
<ul>
""".format(safe_host=safe_host)
    for dir in directories:
        html += f"<li>{dir}</li>\n"
    html += "</ul>\n"
    html += """
<h2>Login Section</h2>
<ul>
"""
    for login in successful_logins:
        status = "FULL_ACCESS" if not login['otp_required'] else "OTP_REQUIRED"
        html += f"<li>{login['username']}:{login['password']} - {status}</li>\n"
    html += "</ul>\n"
    if brute_success is not None:
        html += f"<p>Brute force login: {'Successful' if brute_success else 'Failed or Detected'}</p>\n"
   
    if otp_brute_success is not None:
        html += f"<p>Brute force OTP: {'Successful' if otp_brute_success else 'Failed or Detected'}</p>\n"
   
    if manual_used:
        html += "<p>Percobaan menggunakan data yang disediakan user.</p>\n"
   
    html += "</body></html>"
   
    with open(f"data/report_{safe_host}.html", 'w') as f:
        f.write(html)
    print(f"[+] Report saved to data/report_{safe_host}.html")
async def handle_otp(tester, crawler, account, auto_mode=False):
    print(f"[*] Processing OTP for {account['username']}")
   
    otp_form = None
    if tester.last_response:
        otp_form = await crawler.crawl_otp_form(tester.last_response.url)
   
    if not otp_form:
        otp_paths = ['/sessions/two-factor', '/otp', '/2fa', '/twofactor', '/verify']
        for path in otp_paths:
            test_url = urljoin(tester.base_url, path)
            print(f"[*] Checking OTP form at: {test_url}")
            otp_form = await crawler.crawl_otp_form(test_url)
            if otp_form:
                break
   
    if not otp_form:
        print(f"[-] OTP form not found for {account['username']}")
        return False
   
    print("[+] OTP form found")
    print(f" URL: {otp_form['action']}")
    print(f" Method: {otp_form['method']}")
    print(" Inputs:")
    for inp in otp_form.get('inputs', []):
        print(f" {inp.get('name', 'N/A')} ({inp.get('type', 'N/A')}) = {inp.get('value', '')}")
   
    # Detect length and type
    length, otp_type = tester.detect_otp_details(tester.last_response)
    if length:
        print(f"[+] Detected OTP length: {length}, type: {otp_type}")
    else:
        print("[-] OTP details undetected")
   
    if auto_mode:
        if not length:
            otp_type_choice = input("Enter OTP type (1: number only, 2: alphanum): ")
            otp_type = 'number' if otp_type_choice == '1' else 'alphanum'
            length = int(input("Enter OTP length: "))
       
        otp_result = tester.otp_bruteforce(otp_form, length, otp_type)
        if otp_result == "BLOCKED":
            print(f"[!] OTP brute detected for {account['username']}")
            return False, False # success, brute_success
        elif otp_result:
            print(f"[+] OTP brute successful: {otp_result}")
            tester.save_cookies(account['username'])
            return True, True
        else:
            print(f"[-] OTP brute failed")
            return False, False
    else:
        otp_code = input("Enter OTP code: ").strip()
        success = tester.try_otp(otp_form, otp_code)
        if success:
            print(f"[+] OTP successful for {account['username']}")
            tester.save_cookies(account['username'])
            return True, None # No brute
        else:
            print(f"[-] OTP failed")
            return False, None
        
async def main():
    host = input("Enter target host (e.g., http://example.com): ").strip()
    output_dir = "data"
    os.makedirs(output_dir, exist_ok=True)
   
    if not host.startswith(('http://', 'https://')):
        host = 'http://' + host
   
    safe_host = host.replace('http://', '').replace('https://', '').replace(':', '_').replace('/', '_').rstrip('/')
    dir_output = f"data/dir_{safe_host}.txt"
    successful_logins_path = f"data/successful_logins_{safe_host}.txt"
    wordlist_path = "data/wordlist.txt"
        
    # Create bruteforcer instance AFTER wordlist_path is defined
    bruteforcer = DirectoryBruteforcer(host, wordlist_path, dir_output)
    
    # Check if result file already exists
    if os.path.exists(dir_output):
        with open(dir_output, 'r') as f:
            valid_urls = [line.strip() for line in f if line.strip()]
        print(f"[+] File {dir_output} already exists, found {len(valid_urls)} URLs. Skipping brute force.")
    else:
        # Ask user for scan mode
        print("[?] Select scan mode:")
        print("1. Full (entire wordlist)")
        print("2. Login page only (authentication section only)")
        choice = input("Choice (1/2): ").strip()
        
        if choice == "2":
            # Filter wordlist for authentication section only
            filtered_words = await bruteforcer.filter_wordlist_login_only()
            
            if not filtered_words:
                print("[-] No words found in authentication section, using full mode")
                valid_urls = await bruteforcer.run(filter_auth=False)
            else:
                # Create temporary wordlist file for authentication only
                temp_wordlist_path = f"data/wordlist_auth_{safe_host}.tmp"
                with open(temp_wordlist_path, 'w') as f:
                    for word in filtered_words:
                        f.write(word + '\n')
                
                # Create a new bruteforcer instance for the filtered wordlist
                auth_bruteforcer = DirectoryBruteforcer(host, temp_wordlist_path, dir_output)
                print(f"[*] Using authentication-only wordlist: {len(filtered_words)} words")
                valid_urls = await auth_bruteforcer.run(filter_auth=False)
                
                # Remove temporary file
                os.remove(temp_wordlist_path)
        else:
            # Full mode
            valid_urls = await bruteforcer.run(filter_auth=False)
                                                              
    # Step 2: Search for login page from dir list
    crawler = WebCrawler(host)
    login_page, login_form = await crawler.find_login_page(dir_output)
   
    if not login_form:
        print("[-] No login form found")
        await crawler.close()
        return
   
    print("[+] Login form found:")
    print(f" URL: {login_page}")
    print(f" Action: {login_form.get('action', 'N/A')}")
    print(f" Method: {login_form.get('method', 'N/A')}")
    print(f" Username field: {login_form.get('username_field', 'N/A')} ({login_form['inputs'][0]['type'] if login_form['inputs'] else 'N/A'})") # Show type for choice
    print(f" Password field: {login_form.get('password_field', 'N/A')}")
    print(f" Form type: {'Complicated' if login_form.get('is_complicated') else 'Simple'}")
    print(" Inputs:")
    for inp in login_form.get('inputs', []):
        print(f" {inp.get('name', 'N/A')} ({inp.get('type', 'N/A')}) = {inp.get('value', '')}")
   
    # Determine username type
    username_type = 'username'
    if 'email' in login_form.get('username_field', '').lower() or login_form['inputs'][0]['type'] == 'email':
        username_type = 'email'
    elif login_form['inputs'][0]['type'] == 'number':
        username_type = 'phone'
    print(f"[+] Detected username type: {username_type}")
   
    tester = AuthTester(host)
    tester.login_page_url = login_page
   
    successful_logins = []
    brute_success = None
    otp_brute_success = None
    manual_used = False
   
    # Check if successful_logins exists
    if os.path.exists(successful_logins_path):
        print(f"[+] Existing successful logins found, testing brute...")
        with open(successful_logins_path, 'r') as f:
            lines = [line.strip().split(':') for line in f if line.strip()]
            for username, password, _ in lines:
                print(f"[*] Brute testing existing: {username}:{password}")
                success, otp_detected = tester.try_login(login_form, username, password)
                if tester.brute_force_detected:
                    brute_success = False
                    break
                if success:
                    if otp_detected:
                        otp_success, otp_brute = await handle_otp(tester, crawler, {'username': username, 'password': password}, auto_mode=True)
                        if otp_success:
                            successful_logins.append({'username': username, 'password': password, 'otp_required': False})
                        else:
                            successful_logins.append({'username': username, 'password': password, 'otp_required': True})
                        if otp_brute is not None:
                            otp_brute_success = otp_brute
                    else:
                        successful_logins.append({'username': username, 'password': password, 'otp_required': False})
                        tester.save_cookies(username)
   
    # Login mode choice
    choice = input("[?] Login mode: 1. Manual 2. Auto (brute): ")
    auto_mode = choice == '2'
    if not auto_mode:
        manual_used = True
   
    if auto_mode:
        usernames_path = "data/usernames.txt"
        passwords_path = "data/passwords.txt"
        if not os.path.exists(usernames_path) or not os.path.exists(passwords_path):
            print("[-] Wordlists for brute not found")
            return
       
        usernames = [line.strip() for line in open(usernames_path, 'r')]
        passwords = [line.strip() for line in open(passwords_path, 'r')]
       
        for username in usernames:
            if username in tester.successful_usernames:
                continue
            for password in passwords:
                print(f"[*] Trying {username}:{password}")
                success, otp_detected = tester.try_login(login_form, username, password)
                if tester.brute_force_detected:
                    brute_success = False
                    break
                if success:
                    brute_success = True
                    if otp_detected:
                        print("[?] OTP mode: 1. Manual 2. Auto: ")
                        otp_choice = input()
                        otp_auto = otp_choice == '2'
                        otp_success, otp_brute = await handle_otp(tester, crawler, {'username': username, 'password': password}, auto_mode=otp_auto)
                        otp_brute_success = otp_brute if otp_auto else None
                        if otp_success:
                            successful_logins.append({'username': username, 'password': password, 'otp_required': False})
                        else:
                            successful_logins.append({'username': username, 'password': password, 'otp_required': True})
                    else:
                        successful_logins.append({'username': username, 'password': password, 'otp_required': False})
                        tester.save_cookies(username)
                    break
            if tester.brute_force_detected:
                break
    else:
        username = input("Username: ")
        password = input("Password: ")
        success, otp_detected = tester.try_login(login_form, username, password)
        if success:
            if otp_detected:
                print("[?] OTP mode: 1. Manual 2. Auto: ")
                otp_choice = input()
                otp_auto = otp_choice == '2'
                otp_success, otp_brute = await handle_otp(tester, crawler, {'username': username, 'password': password}, auto_mode=otp_auto)
                otp_brute_success = otp_brute if otp_auto else None
                if otp_success:
                    successful_logins.append({'username': username, 'password': password, 'otp_required': False})
                    tester.save_cookies(username)
                else:
                    successful_logins.append({'username': username, 'password': password, 'otp_required': True})
            else:
                successful_logins.append({'username': username, 'password': password, 'otp_required': False})
                tester.save_cookies(username)
   
    # Save successful logins if new
    if successful_logins and not os.path.exists(successful_logins_path):
        with open(successful_logins_path, 'w') as f:
            for acc in successful_logins:
                status = "OTP_REQUIRED" if acc['otp_required'] else "FULL_ACCESS"
                f.write(f"{acc['username']}:{acc['password']}\n")
   
    # Get directories for report
    directories = []
    if os.path.exists(dir_output):
        with open(dir_output, 'r') as f:
            directories = [line.strip() for line in f if line.strip()]
   
    generate_report(safe_host, directories, successful_logins, brute_success, otp_brute_success, manual_used)
   
    await crawler.close()
if __name__ == "__main__":
    asyncio.run(main())