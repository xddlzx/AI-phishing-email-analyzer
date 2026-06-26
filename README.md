# AI-Powered Phishing Email Analyzer

A defensive, modular phishing email analysis tool for MITRE ATT&CK Initial Access research.
The system analyzes local email samples and classifies them as:

* `SAFE`
* `SUSPICIOUS`
* `PHISHING`

The project focuses on phishing techniques under:

* `T1566` — Phishing
* `T1566.001` — Spearphishing Attachment
* `T1566.002` — Spearphishing Link
* `T1566.003` — Spearphishing via Service

This tool does **not** send emails, open links, execute attachments, collect credentials, or perform offensive actions. It only analyzes local harmless or sanitized email samples.

---

## Features

* AI-based email text classification
* Header and authentication analysis
* SPF, DKIM, and DMARC result checking
* Sender spoofing and domain mismatch detection
* Suspicious URL analysis
* Attachment filename and extension analysis
* Social engineering indicator detection
* MITRE ATT&CK mapping
* Component-level and overall risk scoring
* Explainable findings for every decision

---

## Project Structure

```text
ai-phishing-email-analyzer/
│
├── app.py
├── requirements.txt
├── README.md
│
├── analyzers/
│   ├── text_classifier.py
│   ├── header_analyzer.py
│   ├── url_analyzer.py
│   ├── attachment_analyzer.py
│   └── social_engineering_analyzer.py
│
├── scoring/
│   └── risk_engine.py
│
├── utils/
│   └── email_parser.py
│
├── samples/
│   ├── safe_email.txt
│   ├── urgent_email.txt
│   ├── mixed.txt
│   ├── suspicious.txt
│   ├── suspicious_email.txt
│   ├── suspicious_header.txt
│   ├── suspicious_header_email.txt
│   ├── attachment_email.txt
│   ├── macro_attachment.txt
│   └── spearphishing_via_services.txt
│
└── reports/
    └── example_output.json
```

---

## How It Works

```text
Selected email sample
        ↓
Email Parser
        ↓
AI Text Classifier
Header Analyzer
URL Analyzer
Attachment Analyzer
Social Engineering Analyzer
        ↓
Final Risk Engine
        ↓
SAFE / SUSPICIOUS / PHISHING
```

The app lists all `.txt` files inside the `samples/` folder.
The user selects one sample, then the system analyzes it with all modules and prints the final result.

---

## Modules

### 1. AI Text Classifier

Uses the Hugging Face model:

```text
cybersectony/phishing-email-detection-distilbert_v2.4.1
```

It analyzes the email subject, body, visible URLs, and attachment names.

This model is used as a **soft signal**.
It can increase the risk score, but it does not force the final result to `PHISHING` by itself.

---

### 2. Header Analyzer

Checks email header and authentication indicators:

* SPF result
* DKIM result
* DMARC result
* From vs Reply-To mismatch
* From vs Return-Path mismatch
* Display-name spoofing
* Message-ID mismatch

Main MITRE mapping:

```text
T1566 - Phishing
```

---

### 3. URL Analyzer

Detects suspicious URL indicators:

* IP address URLs
* HTTP instead of HTTPS
* Too many subdomains
* Punycode / IDN tricks
* URL shorteners
* Suspicious TLDs
* Brand impersonation
* Lookalike domains
* Credential-related URL keywords

Main MITRE mapping:

```text
T1566.002 - Spearphishing Link
```

The tool does not open or visit URLs.

---

### 4. Attachment Analyzer

Checks attachment names and extensions:

* `.exe`, `.scr`, `.js`, `.vbs`, `.ps1`, `.lnk`
* `.docm`, `.xlsm`, `.pptm`
* `.zip`, `.rar`, `.7z`, `.iso`, `.img`
* Double extensions like `invoice.pdf.exe`
* Suspicious lure keywords such as `invoice`, `payment`, `salary`

Main MITRE mapping:

```text
T1566.001 - Spearphishing Attachment
```

The tool does not open, extract, scan, or execute attachments.

---

### 5. Social Engineering Analyzer

Detects phishing-style persuasion techniques:

* Urgency
* Fear or threat
* Credential request
* Financial lure
* Authority impersonation
* Attachment lure
* Link-click lure
* Service impersonation

Example risky combinations:

* Urgency + credential request
* Fear + credential request
* Financial lure + attachment lure
* Service impersonation + link-click request

---

## Risk Scoring

Each module has its own score and classification.

| Module                      | Max Score |
| --------------------------- | --------: |
| AI Text Classifier          |        40 |
| Header Analysis             |        25 |
| URL Analysis                |        20 |
| Attachment Analysis         |        10 |
| Social Engineering Analysis |         5 |
| **Total**                   |   **100** |

Final score thresholds:

|  Score | Final Classification |
| -----: | -------------------- |
|   0–29 | `SAFE`               |
|  30–59 | `SUSPICIOUS`         |
| 60–100 | `PHISHING`           |

Component-level thresholds:

|    Ratio | Component Classification |
| -------: | ------------------------ |
|   0%–39% | `LOW_RISK_COMPONENT`     |
|  40%–74% | `SUSPICIOUS_COMPONENT`   |
| 75%–100% | `HIGH_RISK_COMPONENT`    |

Hard technical evidence components:

```text
header_analysis
url_analysis
attachment_analysis
```

Soft signal components:

```text
text_classification
social_engineering_analysis
```

A high-risk URL, header, or attachment can force `PHISHING`.
A high-risk AI or social engineering result alone usually escalates only to `SUSPICIOUS`.

---

## Installation

```bash
git clone https://github.com/xddlzx/AI-phishing-email-analyzer.git
cd AI-phishing-email-analyzer
```

Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

Run:

```bash
python app.py
```

The app lists available email samples:

```text
=== AVAILABLE EMAIL SAMPLES ===
1. attachment_email.txt
2. macro_attachment.txt
3. mixed.txt
4. safe_email.txt
...
```

Enter the number of the email sample you want to analyze.

The output includes:

* Final classification
* Overall score
* Component scores
* MITRE ATT&CK mapping
* Detailed findings
* Explanation of the decision

---

## Example Output

```text
=== FINAL RISK RESULT ===
Final Classification: PHISHING
Overall Score: 100.0/100
Overall Score Classification: PHISHING

MITRE Mapping:
  - T1566 - Phishing
  - T1566.001 - Spearphishing Attachment
  - T1566.002 - Spearphishing Link

Findings:
  - [High] AI text classifier detected phishing-like language.
  - [High] DMARC authentication result is 'fail'.
  - [High] URL may be impersonating a trusted brand.
  - [High] Attachment uses a high-risk executable extension.
```

---

## Sample Emails

| Sample                           | Purpose                     | Expected Result |
| -------------------------------- | --------------------------- | --------------- |
| `safe_email.txt`                 | Clean email                 | `SAFE`          |
| `urgent_email.txt`               | Benign urgent reminder      | `SUSPICIOUS`    |
| `mixed.txt`                      | Mixed weak indicators       | `SUSPICIOUS`    |
| `suspicious.txt`                 | Text-only suspicious email  | `SUSPICIOUS`    |
| `suspicious_email.txt`           | Multi-signal phishing       | `PHISHING`      |
| `suspicious_header_email.txt`    | Header spoofing             | `PHISHING`      |
| `attachment_email.txt`           | Double-extension attachment | `PHISHING`      |
| `macro_attachment.txt`           | Macro-enabled Office file   | `SUSPICIOUS`    |
| `spearphishing_via_services.txt` | Service impersonation       | `PHISHING`      |

---

## Safety

This project is defensive only.

It does not:

* Send emails
* Generate phishing campaigns
* Collect credentials
* Open links
* Expand shortened URLs
* Visit websites
* Download files
* Execute attachments
* Perform malware analysis
* Interact with real targets

---

## Limitations

* SPF, DKIM, and DMARC are read from email headers; live DNS verification is not performed.
* URL analysis is static; reputation and redirect checks are not included.
* Attachment analysis is based on filename and extension only.
* The AI model can be overconfident on business emails containing words like `payment`, `account`, or `billing`.
* The social engineering analyzer is rule-based and may flag benign urgent emails.
* This is not a production email security gateway.

---

## Future Improvements

* Add JSON report export
* Add Streamlit web interface
* Add optional DNS checks
* Add optional URL reputation API integration
* Add unit tests
* Add evaluation metrics
* Add PDF or HTML report generation
* Fine-tune a multi-label social engineering classifier

---

# Türkçe Açıklama

Bu proje, MITRE ATT&CK Initial Access kapsamındaki phishing tekniklerini analiz etmek için geliştirilmiş savunma odaklı bir e-posta analiz aracıdır.

Sistem e-postaları şu üç sınıftan biriyle değerlendirir:

* `SAFE`
* `SUSPICIOUS`
* `PHISHING`

Proje yalnızca AI modeline dayanmaz. AI metin sınıflandırmasını; header analizi, URL analizi, attachment analizi ve sosyal mühendislik kontrolleriyle birleştirir.

---

## Türkçe Özet

Sistem şu modüllerden oluşur:

* **AI Text Classifier:** E-posta metninin phishing benzeri olup olmadığını analiz eder.
* **Header Analyzer:** SPF, DKIM, DMARC ve sender spoofing kontrolleri yapar.
* **URL Analyzer:** Şüpheli linkleri, domain benzerliğini ve URL hilelerini analiz eder.
* **Attachment Analyzer:** Riskli dosya uzantılarını ve çift uzantı hilelerini tespit eder.
* **Social Engineering Analyzer:** Aciliyet, korku, credential request ve finansal lure gibi ifadeleri bulur.
* **Risk Engine:** Tüm modül sonuçlarını birleştirerek final kararı üretir.

---

## Türkçe Kullanım

Projeyi çalıştırmak için:

```bash
python app.py
```

Uygulama `samples/` klasöründeki e-posta örneklerini listeler.
Kullanıcı analiz etmek istediği örneğin numarasını girer.

Çıktıda şunlar gösterilir:

* Final classification
* Genel skor
* Modül skorları
* MITRE ATT&CK eşleştirmesi
* Detaylı bulgular
* Kararın açıklaması

---

## Türkçe Güvenlik Notu

Bu proje yalnızca savunma ve eğitim amacıyla geliştirilmiştir.

Şunları yapmaz:

* Phishing e-postası göndermez
* Gerçek kampanya oluşturmaz
* Kimlik bilgisi toplamaz
* Link açmaz
* Dosya indirmez
* Attachment çalıştırmaz
* Gerçek hedeflerle etkileşime girmez

Sadece lokal ve zararsız örnek e-postaları analiz eder.
