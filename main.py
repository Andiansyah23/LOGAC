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

async def main():
    host = input("Enter target host (e.g., http://example.com): ").strip()
    output_dir = "data"
    os.makedirs(output_dir, exist_ok=True)
   
    if not host.startswith(('http://', 'https://')):
        host = 'http://' + host
   
    safe_host = host.replace('http://', '').replace('https://', '').rstrip('/')
    safe_host = safe_host.replace(':', '_').replace('/', '_')
    dir_output = f"data/dir_{safe_host}.txt"
    successful_logins_path = f"data/successful_logins_{safe_host}.txt"
    wordlist_path = "data/wordlist.txt"
    
    # Check if wordlist exists
    if not os.path.exists(wordlist_path):
        print(f"[-] Wordlist not found at {wordlist_path}")
        return
        
    # Create bruteforcer instance
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
    
    # Check if inputs exist before accessing them
    if login_form.get('inputs'):
        username_field_type = login_form['inputs'][0]['type'] if login_form['inputs'] else 'N/A'
    else:
        username_field_type = 'N/A'
        
    print(f" Username field: {login_form.get('username_field', 'N/A')} ({username_field_type})")
    print(f" Password field: {login_form.get('password_field', 'N/A')}")
    print(f" Form type: {'Complicated' if login_form.get('is_complicated') else 'Simple'}")
    print(" Inputs:")
    for inp in login_form.get('inputs', []):
        print(f" {inp.get('name', 'N/A')} ({inp.get('type', 'N/A')}) = {inp.get('value', '')}")
   
    # Determine username type
    username_type = 'username'
    if 'email' in login_form.get('username_field', '').lower() or (login_form.get('inputs') and login_form['inputs'][0]['type'] == 'email'):
        username_type = 'email'
    elif login_form.get('inputs') and login_form['inputs'][0]['type'] == 'number':
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
            for line in f:
                if line.strip():
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        username, password = parts[0], parts[1]
                        print(f"[*] Brute testing existing: {username}:{password}")
                        success, otp_detected = tester.try_login(login_form, username, password)
                        if tester.brute_force_detected:
                            brute_success = False
                            break
                        if success:
                            if otp_detected:
                                print("[?] OTP mode for existing login: 1. Manual 2. Auto (brute): ")
                                otp_choice = input()
                                otp_auto_mode = None if otp_choice == '' else (True if otp_choice == '2' else False)
                                otp_success, otp_brute = await tester.handle_otp(crawler, {'username': username, 'password': password}, auto_mode=otp_auto_mode)
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
                        # Tidak ask di sini, pass auto_mode=None agar ask di handle_otp setelah scan form
                        otp_success, otp_brute = await tester.handle_otp(crawler, {'username': username, 'password': password}, auto_mode=None)
                        otp_brute_success = otp_brute if otp_brute is not None else None  # otp_brute True jika auto sukses
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
                # Tidak ask di sini, pass auto_mode=None agar ask di handle_otp setelah scan form
                otp_success, otp_brute = await tester.handle_otp(crawler, {'username': username, 'password': password}, auto_mode=None)
                otp_brute_success = otp_brute if otp_brute is not None else None
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
        with open(successful_logins_path, 'a') as f:
            for acc in successful_logins:
                f.write(f"{acc['username']}:{acc['password']}\n")
   
    # Get directories for report
    directories = []
    if os.path.exists(dir_output):
        with open(dir_output, 'r') as f:
            directories = [line.strip() for line in f if line.strip()]
    await crawler.close()  
    generate_report(safe_host, directories, successful_logins, brute_success, otp_brute_success, manual_used)
   
    await crawler.close()

if __name__ == "__main__":
    asyncio.run(main())