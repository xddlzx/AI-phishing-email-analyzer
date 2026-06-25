# AI Phishing Email Analyzer

## English

A small Python project for analyzing email text and detecting possible phishing attempts using an AI text classifier.

The current version focuses on email text analysis. It classifies a given email as:

* `SAFE`
* `SUSPICIOUS`
* `PHISHING`

It also returns a phishing score, confidence value, raw model prediction, and probability scores.

### Features

* AI-based phishing email text classification
* Uses a DistilBERT phishing detection model
* Runs on CPU, CUDA, or Apple Silicon MPS when available
* Simple example usage in `app.py`

### Installation

```bash
git clone https://github.com/xddlzx/AI-phishing-email-analyzer.git
cd AI-phishing-email-analyzer
pip install -r requirements.txt
```

### Usage

```bash
python app.py
```

The script analyzes a sample email and prints the classification result.

### Note

This project is for defensive and educational cybersecurity purposes only. It does not send emails, open links, collect credentials, or perform offensive actions.

---

## Türkçe

AI Phishing Email Analyzer, e-posta metinlerini analiz ederek olası phishing / oltalama girişimlerini tespit etmeye yardımcı olan küçük bir Python projesidir.

Mevcut sürüm e-posta metni analizine odaklanır. Girilen e-postayı şu sınıflardan biriyle değerlendirir:

* `SAFE`
* `SUSPICIOUS`
* `PHISHING`

Ayrıca phishing skoru, güven değeri, ham model tahmini ve olasılık sonuçlarını döndürür.

### Özellikler

* Yapay zeka destekli phishing e-posta metni sınıflandırması
* DistilBERT tabanlı phishing tespit modeli kullanımı
* Uygunsa CPU, CUDA veya Apple Silicon MPS üzerinde çalışabilme
* `app.py` içinde basit örnek kullanım

### Kurulum

```bash
git clone https://github.com/xddlzx/AI-phishing-email-analyzer.git
cd AI-phishing-email-analyzer
pip install -r requirements.txt
```

### Kullanım

```bash
python app.py
```

Komut, örnek bir e-postayı analiz eder ve sınıflandırma sonucunu ekrana yazdırır.

### Not

Bu proje yalnızca savunma ve eğitim amaçlı siber güvenlik çalışmaları için hazırlanmıştır. E-posta göndermez, bağlantı açmaz, kimlik bilgisi toplamaz ve saldırı amaçlı işlem yapmaz.
