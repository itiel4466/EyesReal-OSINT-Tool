# 🔍 EYESREAL v15 — Plivo Integration

Advanced Open Source Intelligence (OSINT) platform. The full v15 source is available in `EyesReal_v15_Plivo.py`, featuring updated modules 5 and 6 integrated with Plivo (replacing the old Twilio dependency). The original banner, colors, report generator, and unrelated modules are fully preserved.

## 🚀 Features & Updates
- **Modules 5 & 6:** Module 5 sends a single SMS, and module 6 initiates a direct text-to-speech test call using fixed account-owned senders and authorized destinations.
- **Workflow Updates:** The old bridge and E-key hangup workflow have been replaced by direct test calls. Menu labels reflect this, and empty configuration blocks sends.
- **Web Companion (`app.py`):** Runs alongside the main tool. Voice instructions and web interfaces require `PUBLIC_BASE_URL` pointing to a public HTTPS URL. Both share `.env` and `activity.sqlite3`.
- **Audit & Reports:** The Plivo activity database is separate from the original EYESREAL encrypted audit database. Module 14 retains its original behavior without removing the Plivo database, and EYESREAL reports receive Plivo acceptance/errors.

## ⚙️ Installation & Setup (Kali Linux)

Clone the repository and enter the directory:
```bash
git clone [https://github.com/itiel4466/EyesReal-OSINT-Tool.git]
cd EyesReal-OSINT-Tool


Create and activate a Python virtual environment, then install dependencies:
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt



Configure your environment variables:
cp .env.example .env


(Edit the .env file with your Plivo credentials, API keys, and settings).

💻 Usage & Running
Run the main CLI script:
python3 EyesReal_v15_Plivo.py

Or run the companion web application:
python3 app.py

(Note: cli.py is available as an alternative minimal terminal interface).

⚠️ Disclaimer & Important Notes
Created for educational and authorized security testing purposes only.

No real messages or calls were sent during validation. Provider acceptance does not confirm delivery; check the Plivo console for final results..

See configuration details for country coverage constraints.
