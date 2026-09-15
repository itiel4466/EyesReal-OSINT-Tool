# 👁️ EyesReal OSINT Framework v15.0

![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Kali Linux Support](https://img.shields.io/badge/Supported-Kali_Linux-black.svg?logo=kali-linux)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active_Development-brightgreen.svg)

**Advanced Cyber Intelligence & Reconnaissance Platform**

EyesReal is an enterprise-grade, highly modular Open-Source Intelligence (OSINT) framework designed for advanced data gathering, entity cross-correlation, and secure reconnaissance. 

> **Academic Note:** This platform was engineered as an advanced final project for a 5-Unit Computer Science curriculum, demonstrating principles of asynchronous networking, graph-based databases, cryptography, and object-oriented architecture.

---

## 🚀 Core Features

*   **🛡️ Stealth Engine & Resilience:** Integrated proxy rotation, dynamic User-Agent spoofing, and rate-limiting to bypass modern WAFs and bot-protection mechanisms.
*   **🧩 14 Specialized Modules:** A massive arsenal of tools including network analysis, social media footprinting, and deep-web scraping.
*   **📡 Plivo Integration (Modules 5 & 6):** Automated, verified SMS dispatching and direct TTS (Text-to-Speech) call generation for target verification.
*   **🧠 Local AI Integration:** Built-in support for `ollama` to analyze unstructured data locally without leaking intelligence to third-party clouds.
*   **🔒 Cryptographic Security:** Utilizes `Fernet` symmetric encryption to secure sensitive API keys, session tokens, and gathered intelligence.
*   **🕸️ Cross-Correlation Engine:** Employs SQLite to build entity graphs (nodes and edges), automatically linking emails, phone numbers, and IPs.
*   **📊 Rich CLI UI:** Powered by the `rich` library for a beautiful, responsive, and color-coded terminal interface, including progress bars and data tables.

## ⚙️ Prerequisites

Ensure your environment is set up with the following dependencies. Kali Linux is the recommended operating system.

*   Python 3.8 or higher
*   Git
*   Valid API keys for selected modules (e.g., Plivo) added to a `.env` file.

## 📥 Installation

Clone the repository and install the required dependencies:

```bash
# Clone the repository
git clone [https://github.com/itiel4466/EyesReal-OSINT-Tool.git](https://github.com/itiel4466/EyesReal-OSINT-Tool.git)

# Navigate to the directory
cd EyesReal-OSINT-Tool

# Install Python dependencies
pip install -r requirements.txt
💻 Usage
Launch the main framework utilizing the rich CLI interface:

Bash
python3 eyesreal.py
Upon launch, you will be greeted by the master banner and the 14-module selection menu. Navigate using the on-screen prompts.

⚠️ Disclaimer
Educational and Authorized Use Only.
EyesReal was developed strictly for academic purposes, authorized penetration testing, and ethical OSINT research. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Users must comply with all applicable local, state, and federal laws. Do not target systems or entities without explicit mutual consent.

Developed with uncompromising standards for modern cyber research.
