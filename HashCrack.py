# -*- coding: utf-8 -*-

import hashlib
import re
import os
import time
import itertools
from tqdm import tqdm
import threading
from queue import Queue


COLORS = {
    'red': '\033[91m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'blue': '\033[94m',
    'magenta': '\033[95m',
    'cyan': '\033[96m',
    'reset': '\033[0m'
}
os.system('cls' if os.name == 'nt' else 'clear')

gradient_chars = '┴┼┘┤└┐─┬├┌└│]░▒░▒█▓▄▌▀()'

def MainColor2(text):
    start_color = (0, 255, 255)
    end_color = (200, 255, 255)

    num_steps = 9

    colors = []
    for i in range(num_steps):
        r = start_color[0] + (end_color[0] - start_color[0]) * i // (num_steps - 1)
        g = start_color[1] + (end_color[1] - start_color[1]) * i // (num_steps - 1)
        b = start_color[2] + (end_color[2] - start_color[2]) * i // (num_steps - 1)
        colors.append((r, g, b))
    
    colors += list(reversed(colors[:-1]))  
    
    def text_color(r, g, b):
        return f"\033[38;2;{r};{g};{b}m"
       
    lines = text.split('\n')
    num_colors = len(colors)
    
    result = []
    for i, line in enumerate(lines):
        for j, char in enumerate(line):
            color_index = (i + j) % num_colors
            color = colors[color_index]
            result.append(text_color(*color) + char + "\033[0m")
        
        if i < len(lines) - 1:
            result.append('\n')
    
    return ''.join(result)


banner = MainColor2(fr"""

██████╗██╗   ██╗██████╗ ███████╗██████╗     ███████╗ ██████╗ ███╗   ██╗███████╗     ██████╗ ██████╗  ██████╗ ██╗   ██╗██████╗     
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ╚══███╔╝██╔═══██╗████╗  ██║██╔════╝    ██╔════╝ ██╔══██╗██╔═══██╗██║   ██║██╔══██╗    
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝      ███╔╝ ██║   ██║██╔██╗ ██║█████╗      ██║  ███╗██████╔╝██║   ██║██║   ██║██████╔╝    
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗     ███╔╝  ██║   ██║██║╚██╗██║██╔══╝      ██║   ██║██╔══██╗██║   ██║██║   ██║██╔═══╝     
╚██████╗   ██║   ██████╔╝███████╗██║  ██║    ███████╗╚██████╔╝██║ ╚████║███████╗    ╚██████╔╝██║  ██║╚██████╔╝╚██████╔╝██║         
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝
                                                                                            

""")
print(banner)
print(MainColor2("┌───────────────────────────────────────────────────────────────────────────────────────┐"))
print(MainColor2("│\x42\x75\x20\x74\x6F\x6F\x6C\x20\x6C\x75\x6E\x61\x6E\x6F\x69\x72\x2C\x20\x74\x65\x6D\x61\x20\x52\x31\x50\x78\x30\x78\x38\x2C\x20\x74\x61\x72\x61\x66\x69\x6E\x64\x61\x6E\x20\x79\x61\x70\x69\x6C\x6D\x69\x73\x74\x69\x72\x2E\x20\x43\x79\x62\x65\x72\x5A\x6F\x6E\x65\x54\x65\x61\x6D\x20\x47\x75\x72\x75\x72\x6C\x61\x72\x69\x6E\x69\x7A\x6C\x61\x2E\x2E\x2E│"))
print(MainColor2("└───────────────────────────────────────────────────────────────────────────────────────┘"))


def detect_hash_type(hash_input):
    hash_input = hash_input.strip()
    patterns = {
        'md5': (r'^[a-fA-F0-9]{32}$', lambda p, h: hashlib.md5(p).hexdigest() == h.lower()),
        'sha1': (r'^[a-fA-F0-9]{40}$', lambda p, h: hashlib.sha1(p).hexdigest() == h.lower()),
        'sha256': (r'^[a-fA-F0-9]{64}$', lambda p, h: hashlib.sha256(p).hexdigest() == h.lower()),
        'sha512': (r'^[a-fA-F0-9]{128}$', lambda p, h: hashlib.sha512(p).hexdigest() == h.lower()),
        'bcrypt': (r'^\$2[aby]\$\d+\$[./A-Za-z0-9]{53}$', lambda p, h: bcrypt.checkpw(p, h.encode())),
        'ntlm': (r'^[a-fA-F0-9]{32}$', lambda p, h: hashlib.new('md4', p.encode('utf-16le')).hexdigest().upper() == h.upper())
    }

    for hash_type, (pattern, check_fn) in patterns.items():
        if re.match(pattern, hash_input):
            if hash_type == 'ntlm' and hash_input.isupper():
                return (hash_type, check_fn)
            return (hash_type, check_fn)
    return (None, None)

def create_multi_layer_check(layers):
    def check_fn(password, target_hash):
        current = password
        for layer in layers:
            if layer == 'md5':
                current = hashlib.md5(current).hexdigest().encode()
            elif layer == 'sha1':
                current = hashlib.sha1(current).hexdigest().encode()
            elif layer == 'sha256':
                current = hashlib.sha256(current).hexdigest().encode()
            elif layer == 'sha512':
                current = hashlib.sha512(current).hexdigest().encode()
            elif layer == 'ntlm':
                current = hashlib.new('md4', current.decode().encode('utf-16le')).hexdigest().upper().encode()
        return current.decode() == target_hash.lower()
    return check_fn

def worker(hash_check, target_hash, queue, result, progress):
    while not queue.empty() and not result['found']:
        try:
            password = queue.get_nowait().rstrip('\n')
            if hash_check(password.encode(), target_hash):
                result['password'] = password
                result['found'] = True
            progress.update(1)
        except Exception as e:
            continue

class HashCracker:
    def __init__(self):
        self.salt = None
        self.iterations = 1000

    def set_pbkdf2_params(self, salt, iterations=100000):
        self.salt = salt
        self.iterations = iterations

    def main(self):
        print(MainColor2(" ┌──────────────────────────────────┐"))
        print(MainColor2(" ├ [*]  Hash kırıcı by lunanoir  [*]"))
        print(MainColor2(" │"))
        target_hash = input(MainColor2(f" ├ [?]- Hedef hash: ")).strip()
        print(MainColor2(" │"))
        hash_type, hash_check = detect_hash_type(target_hash)
        print(MainColor2(f" ├ [!]-  {hash_type.upper()} Hash tespit edildi!!!")) if hash_type else None
        print(MainColor2(f" │"))
        attack_type = input(MainColor2(f" ├ [?]- Saldırı tipi seçin (1: Wordlist, 2: Mask, 3: Hybrid, 4: Multi-layer): ")).strip()
        print(MainColor2(" │"))
        if attack_type == '4':
            layer_count = int(input(MainColor2(f" ├ [?]- Katman sayısı: ")))
            layers = []
            for i in range(layer_count):
                print(MainColor2(" │"))
                ht = input(MainColor2(f" ├ [?]- Katman {i+1} hash türü (md5,sha1,sha256,sha512,ntlm): ")).strip().lower()
                layers.append(ht)
            hash_check = create_multi_layer_check(layers)
            hash_type = "->".join(layers).upper()

        wordlist_path = None
        if attack_type in ['1', '3', '4']:
            wordlist_path = self.find_wordlist()
            if not wordlist_path:
                return

        start_time = time.time()
        result = {'found': False, 'password': None}

        try:
            with tqdm(desc=f"{COLORS['cyan']} |- İlerleme{COLORS['reset']}", unit=' Cracking...',
                     bar_format="{l_bar}%s{bar}%s{r_bar}" % (COLORS['magenta'], COLORS['reset'])) as progress:

                if attack_type == '1':
                    self.wordlist_attack(hash_check, target_hash, wordlist_path, result, progress)
                elif attack_type == '2':
                    self.mask_attack(hash_check, target_hash, result, progress)
                elif attack_type == '3':
                    self.hybrid_attack(hash_check, target_hash, wordlist_path, result, progress)
                elif attack_type == '4':
                    self.wordlist_attack(hash_check, target_hash, wordlist_path, result, progress)
                else:
                    print(f"{COLORS['cyan']} ├ {COLORS['red']}[{COLORS['reset']}!{COLORS['red']}]{COLORS['reset']}- Geçersiz saldırı tipi!{COLORS['reset']}")
                    return

        except KeyboardInterrupt:
            print(MainColor2(f" ├ [!]- İşlem durduruldu!"))
            return

        finally:
            elapsed = time.time() - start_time
            self.report_results(result, target_hash, elapsed, progress.n if 'progress' in locals() else 0, hash_type)

    def find_wordlist(self):
        wordlist_path = input(MainColor2(f" ├ [?]- Wordlist yolunu girin (boş bırakırsanız default yollar denenir): ")).strip()
        if wordlist_path:
            if os.path.exists(wordlist_path):
                return wordlist_path
            else:
                print(MainColor2(f" ├ [*]-  Belirtilen wordlist dosyası bulunamadı!"))
                return None
        else:
            paths = [
                'rockyou.txt',
                '/usr/share/wordlists/rockyou.txt',
                '/usr/share/john/wordlist.lst'
            ]
            for path in paths:
                if os.path.exists(path):
                    print(MainColor2(f" ├ [*]- Default wordlist kullanılıyor: {path}"))
                    return path
            print(MainColor2(f" ├ [!]- Wordlist bulunamadı!"))
            return None

    def wordlist_attack(self, hash_check, target_hash, wordlist_path, result, progress):
        with open(wordlist_path, 'r', errors='ignore') as f:
            queue = Queue(maxsize=100000000000)
            [queue.put(line) for line in itertools.islice(f, 100000000000)]

            progress.total = queue.qsize()
            threads = [threading.Thread(target=worker, args=(hash_check, target_hash, queue, result, progress))
                      for _ in range(os.cpu_count())]

            [t.start() for t in threads]
            [t.join() for t in threads]

    def mask_attack(self, hash_check, target_hash, result, progress):
        mask = input(MainColor2(f" ├ [?]- Mask formatını girin (Örn: ?l?l?l?l?d?d): "))
        mask_parts = self.parse_mask(mask)

        total_combinations = 1
        for part in mask_parts:
            total_combinations *= len(part)
        progress.total = total_combinations

        for combo in itertools.product(*mask_parts):
            if result['found']:
                break
            password = ''.join(combo)
            if hash_check(password.encode(), target_hash):
                result['password'] = password
                result['found'] = True
            progress.update(1)

    def hybrid_attack(self, hash_check, target_hash, wordlist_path, result, progress):
        mask = input(MainColor2(f" ├ [*]- Hybrid mask ekini girin (Örn: ?d?d?d): "))
        mask_parts = self.parse_mask(mask)

        with open(wordlist_path, 'r', errors='ignore') as f:
            for base_pass in f:
                base_pass = base_pass.strip()
                for suffix in itertools.product(*mask_parts):
                    if result['found']:
                        return
                    full_pass = base_pass + ''.join(suffix)
                    if hash_check(full_pass.encode(), target_hash):
                        result['password'] = full_pass
                        result['found'] = True
                    progress.update(1)

    def parse_mask(self, mask):
        char_sets = {
            '?l': 'abcdefghijklmnopqrstuvwxyz',
            '?u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            '?d': '0123456789',
            '?s': ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~',
            '?a': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'
        }
        mask_parts = []
        while mask:
            if mask[:2] in char_sets:
                mask_parts.append(char_sets[mask[:2]])
                mask = mask[2:]
            else:
                mask_parts.append(mask[0])
                mask = mask[1:]
        return mask_parts

    def report_results(self, result, target_hash, elapsed, tried_count, hash_type):
        if result['found']:
            print(MainColor2(f" ┌──────────────────────────────────┐"))
            print(MainColor2(f" ├ [*]-  [+] Şifre kırıldı: {result['password']}"))
            print(MainColor2(f" ├ [*]-  [+] Hash Türü: {hash_type}"))
            print(MainColor2(f" ├ [*]-  [+] Hash: {target_hash}"))
            print(MainColor2(f" ├ [*]-  [+] Toplam süre: {elapsed:.2f}s"))
            print(MainColor2(f" ├ [*]-  [+] Hız: {tried_count/elapsed:.2f} şifre/saniye"))
            print(MainColor2(f" └──────────────────────────────────┘"))

            with open('cracked_results.txt', 'a') as f:
                f.write(f"Hash: {target_hash}\nŞifre: {result['password']}\n\n")
        else:
            print(f"{COLORS['red']}\n ├ [-]- Şifre bulunamadı!{COLORS['reset']}")

if __name__ == "__main__":
    try:
        import bcrypt
        cracker = HashCracker()
        cracker.main()
    except ImportError:
        print(MainColor2(f" ├ [!]- Gerekli kütüphaneler yüklü değil !!!"))
        print(MainColor2(f" ├ [*]- Kurulum için: pip install bcrypt tqdm"))
