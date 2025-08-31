import aiohttp
import asyncio
from urllib.parse import urljoin
import time
import os

async def directory_bruteforce(host, wordlist_path, output_file):
    print(f"🚀 Starting directory bruteforce on {host}")
    
    # Baca wordlist dan skip komentar
    try:
        with open(wordlist_path, 'r') as f:
            wordlist = []
            for line in f:
                line = line.strip()
                if line and not line.startswith(('#', '=')):
                    wordlist.append(line)
        print(f"📖 Loaded {len(wordlist)} words from {wordlist_path}")
    except Exception as e:
        print(f"❌ Failed to read wordlist: {e}")
        return []

    if not host.startswith('http'):
        host = 'http://' + host
    print(f"🌐 Target URL: {host}")

    # Variabel untuk melacak status
    consecutive_failures = 0
    fast_mode = True
    valid_urls = []

    # Pastikan direktori output ada
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
    
    # Gunakan connector dengan limit yang lebih konservatif untuk website online
    connector = aiohttp.TCPConnector(limit=10, ssl=False, force_close=True)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        for i, word in enumerate(wordlist):
            url = urljoin(host, word)
            
            # Tentukan delay berdasarkan mode
            delay = 0 if fast_mode else 5

            if delay > 0:
                print(f"⏳ Waiting {delay}s before next request")
                await asyncio.sleep(delay)
            
            max_retries = 10  # Kurangi retry untuk website online
            request_success = False
            for retry in range(max_retries):
                try:
                    # print(f"🔍 Testing: {url} ")
                    async with session.get(url, timeout=15) as response:  # Increase timeout
                        status = response.status
                        
                        if status == 429:
                            print(f"⛔ Rate limited: {url} (Status: 429) (attempt {retry + 1}/{max_retries})")
                            consecutive_failures += 1
                            
                            wait_time = 2 ** (retry + 1)  # Exponential backoff
                            print(f"⏳ Waiting {wait_time}s before retry")
                            await asyncio.sleep(wait_time)
                            continue
                            
                        elif status in {200, 201, 202, 204, 301, 302, 307, 308, 403}:
                            # print(f"✅ Found: {url} (Status: {status})")
                            valid_urls.append(url)
                            consecutive_failures = 0
                            request_success = True
                            
                            # Simpan hasil secara real-time
                            try:
                                with open(output_file, 'a') as f:  # Mode append
                                    f.write(url + '\n')
                            except Exception as e:
                                print(f"⚠️ Failed to save result: {e}")
                            
                            break
                            
                        else:
                            # print(f"❌ Not found: {url} (Status: {status})")
                            consecutive_failures = 0
                            request_success = True
                            break
                            
                except Exception as e:
                    print(f"⚠️ Error: {url} - {str(e)}")
                    consecutive_failures += 1
                    
                    wait_time = 2 ** (retry + 1)
                    print(f"⏳ Waiting {wait_time}s before retry")
                    await asyncio.sleep(wait_time)
                    continue
            
            if not request_success:
                print(f"❌ Giving up on {url} after {max_retries} attempts")
            
            # Cek jika perlu beralih mode
            if consecutive_failures >= 3 and fast_mode:
                print("🔄 Switching to slow mode (5 seconds between requests)")
                fast_mode = False
            elif consecutive_failures == 0 and not fast_mode:
                print("🔄 Switching back to fast mode")
                fast_mode = True

            # Progress report
            if (i + 1) % 20 == 0:  # Kurangi frekuensi progress report
                print(f"📊 Progress: {i + 1}/{len(wordlist)} URLs tested")
                print(f"   Valid URLs found: {len(valid_urls)}")
                print(f"   Consecutive failures: {consecutive_failures}")
                print(f"   Current mode: {'Fast' if fast_mode else 'Slow'}")

    # Simpan hasil akhir (untuk memastikan semua data tersimpan)
    try:
        with open(output_file, 'w') as f:
            for url in valid_urls:
                f.write(url + '\n')
        print(f"💾 Final results saved to {output_file}")
    except Exception as e:
        print(f"❌ Failed to save final results: {e}")
    
    print(f"\n🎉 Bruteforce completed!")
    print(f"📋 Found {len(valid_urls)} valid URLs out of {len(wordlist)} tested")
    
    return valid_urls

async def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Directory bruteforce tool with retry on rate limit')
    parser.add_argument('host', help='Target host (e.g., example.com or http://example.com)')
    parser.add_argument('wordlist', help='Path to wordlist file')
    parser.add_argument('-o', '--output', default='results.txt', help='Output file (default: results.txt)')
    
    args = parser.parse_args()
    
    await directory_bruteforce(args.host, args.wordlist, args.output)

if __name__ == "__main__":
    asyncio.run(main())