<div align="center">
  <img src="https://img.shields.io/github/languages/count/ibrahimyigitcetin/FolderSleuth?style=flat-square&color=blueviolet" alt="Language Count">
  <img src="https://img.shields.io/github/languages/top/ibrahimyigitcetin/FolderSleuth?style=flat-square&color=1e90ff" alt="Top Language">
  <img src="https://img.shields.io/github/last-commit/ibrahimyigitcetin/FolderSleuth?style=flat-square&color=ff69b4" alt="Last Commit">
  <img src="https://img.shields.io/github/license/ibrahimyigitcetin/FolderSleuth?style=flat-square&color=yellow" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-green?style=flat-square" alt="Status">
  <img src="https://img.shields.io/badge/Contributions-Welcome-brightgreen?style=flat-square" alt="Contributions">
</div>

# 🔍 FolderSleuth - Klasörlerde Dosya Değişikliği İzleme Aracı

Gelişmiş yapay zeka tabanlı dosya izleme ve güvenlik tehdidi tespit sistemi. Klasörlerinizi ransomware, malware ve şüpheli aktivitelerden korur.

## ✨ Özellikler

### 🔍 **Gelişmiş Dosya İzleme**
- 📁 **Derin Klasör Tarama**: Klasör ve alt klasörleri recursively tarar
- 🔐 **SHA-256 Hash Kontrolü**: Dosya değişikliklerini hassas şekilde tespit eder
- 📊 **Detaylı Değişiklik Raporu**: Eklenen, silinen ve değiştirilen dosyaları raporlar

### 🛡️ **AI-Powered Güvenlik Sistemi**
- 🚨 **Ransomware Tespiti**: Şüpheli dosya uzantılarını ve davranışları tespit eder
- 🔍 **Malware Göstergeleri**: Dosya isimlerinde ve içeriklerinde malware belirtilerini arar
- 🎯 **Hassas Veri Koruması**: API anahtarları, şifreler ve private key'leri tespit eder
- ⚡ **Performans Anomalisi**: Anormal sistem kaynak kullanımını izler

### 🧠 **Akıllı Analiz Özellikleri**
- 📈 **Davranış Analizi**: Normal olmayan dosya değişiklik desenlerini tespit eder
- 🕒 **Zaman Tabanlı Analiz**: Çalışma saatleri dışındaki şüpheli aktiviteleri fark eder
- 🎯 **Yanlış Pozitif Filtreleme**: Güvenli dosyaları ve sistem dosyalarını filtreler
- 📊 **Tehdit Puanlama**: 0-100 arası tehdit seviyesi hesaplar

### 📝 **Kapsamlı Raporlama**
- 🏥 **Anomali Günlüğü**: Detaylı güvenlik olayları kaydı
- 📈 **Değişiklik Geçmişi**: Zaman damgalı tüm değişikliklerin takibi
- 🎨 **Renkli Terminal Çıktısı**: Kullanıcı dostu görsel geri bildirim

## 🚀 Kurulum

### Gereksinimler
```bash
pip install psutil
```

### Repository Kurulumu
```bash
git clone https://github.com/ibrahimyigitcetin/FolderSleuth.git
cd FolderSleuth
```

## 📖 Kullanım

### Temel Kullanım
```bash
python foldersleuth.py /path/to/your/folder
```

### Gelişmiş Parametreler
```bash
# Özel tehdit eşiği ile çalıştırma
python foldersleuth.py /path/to/folder --threat-threshold 50

# Yüksek güvenlik modunda
python foldersleuth.py /path/to/folder --threat-threshold 30
```

### Platform Örnekleri

```bash
# Windows
python foldersleuth.py "C:\Users\Username\Documents"
python foldersleuth.py "D:\Important Files" --threat-threshold 40

# Linux/Mac
python foldersleuth.py /home/username/projects
python foldersleuth.py ./sensitive-data --threat-threshold 25
```

## 🔧 Konfigürasyon Dosyaları

### `baseline_metrics.json` - Sistem Temel Metrikleri
```json
{
  "avg_file_size": 50000,
  "avg_changes_per_hour": 10,
  "common_extensions": [".py", ".txt", ".md", ".json", ".log"],
  "normal_change_rate": 5
}
```

### `normal_patterns.json` - Normal Davranış Desenleri
```json
{
  "working_hours": [9, 18],
  "common_file_types": [".py", ".txt", ".md", ".json"],
  "max_hourly_changes": 50,
  "max_size_change_ratio": 3.0
}
```

## 📂 Çıktı Dosyaları

Araç çalıştıktan sonra aşağıdaki dosyalar oluşturulur:

- **`backup_state.pkl`** - Klasörün mevcut hash durumu
- **`change_log.json`** - Zaman damgalı değişiklik geçmişi
- **`last_report.txt`** - Son taramanın detaylı güvenlik raporu
- **`anomaly_detection.json`** - Tespit edilen güvenlik anomalileri
- **`threat_signatures.json`** - Tehdit imzaları ve desenler

## 🛡️ Güvenlik Özellikleri Detayı

### Tespit Edilen Tehdit Türleri

**🔒 Ransomware Göstergeleri**
- Şüpheli dosya uzantıları (`.encrypted`, `.locked`, `.crypto`, vb.)
- Kitlesel dosya değişiklikleri (5 dakikada 20+ dosya)
- Aynı dosyaya hızlı ardışık değişiklikler

**🦠 Malware İndikatörleri**
- Dosya isimlerinde şüpheli kelimeler
- Backdoor, keylogger, trojan belirtileri
- Shell ve exploit göstergeleri

**🔑 Hassas Veri Tespiti**
- API anahtarları ve tokenlar
- Şifreler ve veritabanı URL'leri
- Private key'ler ve sertifikalar

**⚡ Sistem Anomalileri**
- Anormal CPU/RAM kullanımı (%90+)
- Yüksek disk I/O aktivitesi (100MB/s+)
- Çalışma saatleri dışı aktiviteler

## 📋 Örnek Çıktı

```
[+] FolderSleuth Advanced - Scanning '/home/user/projects' with threat detection...

🚨 THREAT ANALYSIS 🚨
High-risk changes detected: 2

⚠️  HIGH RISK: documents/passwords.txt
   Threat Score: 85/100
   Change Type: added
   Indicators: Sensitive data pattern detected, Change detected outside working hours

⚠️  HIGH RISK: temp/file.encrypted
   Threat Score: 95/100
   Change Type: changed
   Indicators: Suspicious extension: .encrypted, Mass file changes detected

✅ SECURITY STATUS: 2 threats require immediate attention

📊 FILE CHANGES SUMMARY
➕ Eklenen Dosyalar: 5
  - src/new_feature.py
  - config/settings.json
  - documents/passwords.txt ⚠️ 
  - logs/system.log
  - temp/cache.tmp

✏️ Değiştirilen Dosyalar: 3
  - main.py
  - temp/file.encrypted ⚠️ 
  - README.md

🚨 CRITICAL SECURITY ALERTS: 2 threats detected!
Check the detailed report above and anomaly_detection.json for full analysis.
```

## ⚙️ Sistem Gereksinimleri

- **Python**: 3.6+
- **Gerekli Kütüphaneler**:
  - `psutil` - Sistem kaynak monitörü
  - `hashlib` - Dosya hash hesaplama
  - `pickle` - Durum kaydetme
  - `json` - Veri depolama
  - `re` - Pattern matching
  - `statistics` - İstatistiksel analiz

## 🔧 Gelişmiş Ayarlar

### Tehdit Eşiği Ayarlama
- **Düşük (20-40)**: Çok hassas, daha fazla yanlış pozitif
- **Orta (50-70)**: Dengeli güvenlik (varsayılan: 70)
- **Yüksek (80-90)**: Sadece kritik tehditler

### Özelleştirilebilir Parametreler
```python
# Anomaly Detector ayarları
threat_score_threshold = 70  # Tehdit eşiği
recent_changes_max = 1000    # Saklanacak son değişik sayısı
working_hours = (9, 18)      # Çalışma saatleri
```

## 🎯 Kullanım Senaryoları

### 🏢 **Kurumsal Güvenlik**
- Sunucu dizinlerinin ransomware koruması
- Hassas veri sızıntısı tespiti
- Insider threat monitörü

### 🏠 **Kişisel Kullanım**
- Önemli belgeler klasörü koruması
- Fotoğraf ve video koleksiyonu güvenliği
- Proje dosyalarının yedekleme kontrolü

### 🔬 **Geliştirici Araçları**
- Kaynak kod değişiklik takibi
- Build süreçlerinin monitörü
- Dependency dosyalarının güvenlik kontrolü

## 🤝 Katkıda Bulunma

1. Projeyi fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-security-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add advanced threat detection'`)
4. Branch'inizi push edin (`git push origin feature/amazing-security-feature`)
5. Pull Request açın

Detaylar için [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) dosyasını inceleyiniz.

### Katkı Alanları
- Yeni tehdit imzaları ekleme
- False positive azaltma algoritmaları
- Performans optimizasyonları
- Yeni raporlama formatları

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE.md](LICENSE.md) dosyasını inceleyiniz.

## 🐛 Sorun Bildirimi

Bir güvenlik açığı veya sorunla karşılaştıysanız:

- **Güvenlik sorunları için**: Özel mesaj gönderin
- **Genel sorunlar için**: [Issues](https://github.com/ibrahimyigitcetin/FolderSleuth/issues) sayfasını kullanın

---

**⚠️ Önemli Güvenlik Notu**: Bu araç güvenlik amaçlı geliştirilmiştir. Tespit edilen tehditler için uygun güvenlik protokollerini uygulayın ve gerektiğinde güvenlik uzmanlarından yardım alın.
