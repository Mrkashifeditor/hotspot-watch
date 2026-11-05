# hotspot-watch

**Ye program kya karta hai?** Tumhare Ruijie RG-EW300N (192.168.111.1) pe nazar rakhta hai aur REPORT deta hai ke kaun sa mobile hotspot se internet aage share kar raha hai. **Ye khud kuch block NAHI karta** — block tum khud Reyee app se karte ho.

## Ye kya NAHI kar sakta (sach baat)

- **EW300N se akela hotspot PROVE nahi kar sakta.** Router ko sirf mobile nazar aata hai, uske peeche hotspot se kitne log hain ye router dekh nahi sakta. Is liye Mode A me zyada traffic sirf **SHAK (SUSPECT)** hai, proof nahi.
- **Gateway mode ke baghair proof nahi milta.** Proof sirf tab milta hai jab agent beech me gateway ho aur TTL 63 / 127 dekhe (Android/iOS 64 → 63, Windows 128 → 127).
- **Internet se router tak nahi pahuncha ja sakta.** 192.168.111.1 ek private LAN IP hai. Koi bahar wala server isko nahi dekh sakta. Is liye ye program **tumhare ghar ke andar** hi chalna chahiye — Raspberry Pi ya PC jo usi Wi-Fi / LAN pe ho.
- **100% nahi hai.** Koi technical banda apne laptop pe TTL 65 set karke TTL check ko bypass kar sakta hai.

## Kaise kaam karta hai — 3 tareeqay (Mode)

| Mode | Kya chahiye | Kya milega |
|---|---|---|
| **A — Router poll (default)** | Pi/PC jo router se connect ho, `.env` me router ka eWeb password | Har 5 min pe Online Clients ki list, traffic score, SUSPECT report |
| **B — Gateway (proof wala)** | Pi / purana PC jis me 2 LAN port hon, EW300N AP mode pe uske peeche | TTL 63/127 dekh ke **PROOF** — yehi ek tareeqa hai jo hotspot prove karta hai |
| **C — CSV (manual)** | Reyee app se client list ka CSV export | Bina router login ke bhi scoring + report |

**Scoring (imaandari se):**
- Traffic 7-day median se **3x zyada** ho 1 ghante me → SUSPECT
- Phone-only MAC 1 ghante me **500 MB se zyada** download kare → SUSPECT
- Gateway mode me **TTL 63 ya 127** dikhe → **PROOF**
- Ek hi IP se **iOS + Windows** dono ke nishan milen → SUSPECT
- SUSPECT ka matlab hai "check karo", PROOF ka matlab hai TTL se sabit hua.

## Setup — Raspberry Pi (recommended)

```bash
# 1. Pi pe copy karo (GitHub se ya zip se)
git clone <tumhara-repo-url> hotspot-watch
cd hotspot-watch

# 2. Config banao
cp config.yaml.example config.yaml
cp .env.example .env
nano .env
# ROUTER_PASSWORD=  <- yahan apna router eWeb password likho
# (ye password sirf tumhare Pi pe rahega, kabhi GitHub pe nahi jayega)

# 3. Install karo
pip install -r requirements.txt

# 4. Test karo
python3 tests/simulate.py
python3 agent.py --once

# 5. Har 5 min pe chalao (cron)
crontab -e
# ye line add karo:
*/5 * * * * cd /home/pi/hotspot-watch && python3 agent.py --once >> /home/pi/hotspot-watch/data/cron.log 2>&1
```

## Setup — Purana Windows PC

1. Python 3.11+ install karo (python.org se, "Add to PATH" tick karo).
2. Is folder ko `C:\hotspot-watch` me copy karo.
3. `config.yaml.example` ko `config.yaml` banao, `.env.example` ko `.env` banao aur `ROUTER_PASSWORD=` bharo.
4. Command Prompt me:
   ```
   cd C:\hotspot-watch
   pip install -r requirements.txt
   python tests\simulate.py
   python agent.py --once
   ```
5. Har 5 min pe chalane ke liye Task Scheduler: Create Task → Trigger "Repeat every 5 minutes" → Action `python.exe C:\hotspot-watch\agent.py --once` (Start in `C:\hotspot-watch`).

## Setup — Linux PC

Pi wale steps hi hain, bas path apne hisab se badal lo. Cron wali line wahi hai.

## Gateway mode (Mode B) — sirf agar proof chahiye

1. Pi / PC ko internet aur EW300N ke beech me lagao: Internet → Pi (2 LAN) → EW300N AP mode pe.
2. `config.yaml` me `gateway_mode: true` karo.
3. `sudo python3 agent.py --once --mode gateway` — TTL ke liye root chahiye hota hai.
4. Ya tcpdump wali file do: `python3 agent.py --once --mode gateway --pcap capture.txt`

## Report kahan milegi?

- `reports/report-YYYY-MM-DD-HHMM.md` — har run ki report
- `reports/latest.json` — latest report (machine-readable)
- `data/history.jsonl` — saari history (7-day baseline isi se banta hai)
- Report ko Muse ko bhejne ke liye: `reports/latest.json` ya latest `.md` file upload kar do, ya uska text copy kar ke bhej do.

## Report dobara banana

```bash
python3 report.py
# ya
python3 agent.py --report
```

## Khud block kaise karo (Reyee app)

Ye program kabhi block nahi karta. Report me jo MAC **SUSPECT / PROOF** ho:
1. Reyee app kholo → **Clients**
2. Us device pe tap karo (MAC se match karo)
3. **Block** dabao

## Mode C — CSV se

CSV ke columns: `mac,ip,hostname,up_mb,down_mb,device_type,ttl_seen,os_fingerprints`
Example `tests/sample-clients.csv` dekho. Chalao:
```bash
python3 agent.py --once --csv tests/sample-clients.csv
```

## Test

```bash
python3 tests/simulate.py
```
Ye 3 fake clients banata hai: ek normal phone, ek 4x traffic wala sharer, ek TTL-63 wala. Sahi result: pehle wale ko NORMAL, baaki do ko flag karna. Poora result `tests/TEST-RESULT.md` me hai.

---

## English (short version)

**hotspot-watch** watches your Ruijie RG-EW300N and writes a report about
which phone may be sharing internet onward via mobile hotspot. It never
blocks anything — you block suspects yourself in the Reyee app.

**Limits, honestly:** from the EW300N alone it cannot see behind a phone's
NAT, so traffic spikes are SUSPECT, not proof. Only gateway mode (TTL 63/127)
can prove hotspot sharing. 192.168.111.1 is a private LAN address — no
internet server can reach it, so the agent must run on your LAN. Detection
is not 100%.

**Setup:** copy `config.yaml.example` → `config.yaml`, `.env.example` →
`.env` (put your router eWeb password in `.env` only, never in git),
`pip install -r requirements.txt`, `python3 agent.py --once`, then run
every 5 min via cron (Pi/Linux) or Task Scheduler (Windows). Reports land
in `reports/`. Block in Reyee app: Clients → tap device → Block.
