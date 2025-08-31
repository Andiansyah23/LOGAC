import aiohttp
import asyncio
from urllib.parse import urljoin
import time
import os

class DirectoryBruteforcer:
    def __init__(self, host, wordlist_path, output_file):
        self.host = host
        self.wordlist_path = wordlist_path
        self.output_file = output_file
        self.valid_urls = []
        self.consecutive_failures = 0
        self.fast_mode = True
    
    async def filter_wordlist_login_only(self):
        """Filter wordlist to only include words in authentication sections"""
        login_keywords = ['login', 'auth', 'signin', 'signup', 'log-in', 'log_in', 'authentication']
        words = []
        in_login_section = False
        
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Detect section headers
                    if line.startswith('#') or line.startswith('='):
                        # Check if section header contains login keywords
                        if any(keyword in line.lower() for keyword in login_keywords):
                            in_login_section = True
                        else:
                            in_login_section = False
                    else:
                        if in_login_section:
                            words.append(line)
            
            print(f"[+] Found {len(words)} words in authentication section")
            return words
        except Exception as e:
            print(f"[-] Error filtering wordlist: {e}")
            return []
    
    async def load_wordlist(self, filter_auth=False):
        """Load wordlist with optional authentication filtering"""
        if filter_auth:
            return await self.filter_wordlist_login_only()
        else:
            try:
                with open(self.wordlist_path, 'r') as f:
                    wordlist = []
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith(('#', '=')):
                            wordlist.append(line)
                print(f"📖 Loaded {len(wordlist)} words from {self.wordlist_path}")
                return wordlist
            except Exception as e:
                print(f"❌ Failed to read wordlist: {e}")
                return []
    
    async def test_url(self, session, url, word):
        """Test a single URL and handle retries"""
        max_retries = 10
        for retry in range(max_retries):
            try:
                async with session.get(url, timeout=15) as response:
                    status = response.status
                    
                    if status == 429:
                        print(f"⛔ Rate limited: {url} (Status: 429) (attempt {retry + 1}/{max_retries})")
                        self.consecutive_failures += 1
                        
                        wait_time = 2 ** (retry + 1)  # Exponential backoff
                        print(f"⏳ Waiting {wait_time}s before retry")
                        await asyncio.sleep(wait_time)
                        continue
                        
                    elif status in {200, 201, 202, 204, 301, 302, 307, 308, 403}:
                        print(f"✅ Found: {url} (Status: {status})")
                        self.valid_urls.append(url)
                        self.consecutive_failures = 0
                        
                        # Save result in real-time
                        try:
                            with open(self.output_file, 'a') as f:
                                f.write(url + '\n')
                        except Exception as e:
                            print(f"⚠️ Failed to save result: {e}")
                        
                        return True
                        
                    else:
                        # print(f"❌ Not found: {url} (Status: {status})")
                        self.consecutive_failures = 0
                        return True
                        
            except Exception as e:
                print(f"⚠️ Error: {url} - {str(e)}")
                self.consecutive_failures += 1
                
                wait_time = 2 ** (retry + 1)
                print(f"⏳ Waiting {wait_time}s before retry")
                await asyncio.sleep(wait_time)
                continue
        
        print(f"❌ Giving up on {url} after {max_retries} attempts")
        return False
    
    async def run(self, filter_auth=False):
        """Run the directory bruteforce"""
        print(f"🚀 Starting directory bruteforce on {self.host}")
        
        # Load wordlist
        wordlist = await self.load_wordlist(filter_auth)
        if not wordlist:
            return []
        
        if not self.host.startswith('http'):
            self.host = 'http://' + self.host
        print(f"🌐 Target URL: {self.host}")

        # Ensure output directory exists
        os.makedirs(os.path.dirname(self.output_file) if os.path.dirname(self.output_file) else '.', exist_ok=True)
        
        # Use connector with conservative limits for online websites
        connector = aiohttp.TCPConnector(limit=10, ssl=False, force_close=True)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            for i, word in enumerate(wordlist):
                url = urljoin(self.host, word)
                
                # Determine delay based on mode
                delay = 0 if self.fast_mode else 5

                if delay > 0:
                    print(f"⏳ Waiting {delay}s before next request")
                    await asyncio.sleep(delay)
                
                # Test the URL
                await self.test_url(session, url, word)
                
                # Check if we need to switch modes
                if self.consecutive_failures >= 3 and self.fast_mode:
                    print("🔄 Switching to slow mode (5 seconds between requests)")
                    self.fast_mode = False
                elif self.consecutive_failures == 0 and not self.fast_mode:
                    print("🔄 Switching back to fast mode")
                    self.fast_mode = True

                # Progress report
                if (i + 1) % 20 == 0:
                    print(f"📊 Progress: {i + 1}/{len(wordlist)} URLs tested")
                    print(f"   Valid URLs found: {len(self.valid_urls)}")
                    print(f"   Consecutive failures: {self.consecutive_failures}")
                    print(f"   Current mode: {'Fast' if self.fast_mode else 'Slow'}")

        # Save final results
        try:
            with open(self.output_file, 'w') as f:
                for url in self.valid_urls:
                    f.write(url + '\n')
            print(f"💾 Final results saved to {self.output_file}")
        except Exception as e:
            print(f"❌ Failed to save final results: {e}")
        
        print(f"\n🎉 Bruteforce completed!")
        print(f"📋 Found {len(self.valid_urls)} valid URLs out of {len(wordlist)} tested")
        
        return self.valid_urls

# Untuk kompatibilitas dengan kode yang ada
async def directory_bruteforce(host, wordlist_path, output_file, filter_auth=False):
    """Wrapper function for backward compatibility"""
    bruteforcer = DirectoryBruteforcer(host, wordlist_path, output_file)
    return await bruteforcer.run(filter_auth)

# Jika file ini dijalankan langsung
async def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Directory bruteforce tool with retry on rate limit')
    parser.add_argument('host', help='Target host (e.g., example.com or http://example.com)')
    parser.add_argument('wordlist', help='Path to wordlist file')
    parser.add_argument('-o', '--output', default='results.txt', help='Output file (default: results.txt)')
    parser.add_argument('-f', '--filter-auth', action='store_true', help='Filter for authentication pages only')
    
    args = parser.parse_args()
    
    await directory_bruteforce(args.host, args.wordlist, args.output, args.filter_auth)

if __name__ == "__main__":
    asyncio.run(main())
