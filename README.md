# FolderSleuth 🔍

Klasörlerinizde olan değişiklikleri takip eden basit ve etkili bir Python aracı. Dosya ekleme, silme ve değişiklikleri izler.

## ✨ Özellikler

- 📁 **Klasör Tarama**: Belirtilen klasörü ve alt klasörlerini recursively tarar
- 🔐 **Hash Tabanlı Kontrol**: SHA-256 hash kullanarak dosya değişikliklerini hassas şekilde tespit eder
- 📊 **Değişiklik Raporu**: Eklenen, silinen ve değiştirilen dosyaları detaylı şekilde raporlar
- 💾 **Durum Kaydetme**: Önceki durumu kaydeder ve karşılaştırma yapar
- 📝 **Değişiklik Geçmişi**: Tüm değişiklikleri JSON formatında loglar
- 🇹🇷 **Türkçe Arayüz**: Kullanıcı dostu Türkçe çıktılar

## 🚀 Kurulum

1. Repository'yi klonlayın:
```bash
git clone https://github.com/ibrahimyigitcetin/FolderSleuth.git
cd FolderSleuth
```

2. Python 3.6+ sürümünün yüklü olduğundan emin olun (ek kütüphane gerektirmez)

## 📖 Kullanım

### Temel Kullanım

```bash
python foldersleuth.py /path/to/your/folder
```

### Örnekler

```bash
# Windows
python foldersleuth.py C:\Users\Username\Documents

# Linux/Mac
python foldersleuth.py /home/username/projects
python foldersleuth.py ./my-folder
```

### İlk Çalıştırma
İlk çalıştırmada tüm dosyalar "yeni eklenen" olarak gösterilir. Bu normaldir - araç başlangıç durumunu kaydediyor.

### Sonraki Çalıştırmalar
Sonraki çalıştırmalarda sadece gerçek değişiklikler gösterilecek:
- ➕ Yeni eklenen dosyalar
- ➖ Silinen dosyalar  
- ✏️ İçeriği değişen dosyalar

## 📂 Çıktı Dosyaları

Araç çalıştıktan sonra aşağıdaki dosyalar oluşturulur:

- **`backup_state.pkl`** - Klasörün mevcut durumunu saklar (binary format)
- **`change_log.json`** - Tüm değişikliklerin zaman damgalı geçmişi
- **`last_report.txt`** - Son tarmanın detaylı raporu (UTF-8 encoding)

## 🔧 Nasıl Çalışır

1. **Tarama**: Belirtilen klasörü ve tüm alt klasörlerini tarar
2. **Hash Hesaplama**: Her dosya için SHA-256 hash hesaplar
3. **Karşılaştırma**: Önceki durum ile mevcut durumu karşılaştırır
4. **Raporlama**: Değişiklikleri kategorize eder ve raporlar
5. **Kaydetme**: Yeni durumu gelecekteki karşılaştırmalar için saklar

## 📋 Örnek Çıktı

```
[+] '/home/user/projects' klasörü taranıyor...
[✓] Tarama tamamlandı. Rapor oluşturuldu:

📁 Klasör: /home/user/projects
🕒 Zaman: 2025-01-15 14:30:22

➕ Eklenen Dosyalar: 2
  - src/new_feature.py
  - docs/changelog.md

➖ Silinen Dosyalar: 1
  - temp/old_file.txt

✏️ Değiştirilen Dosyalar: 3
  - src/main.py
  - config/settings.json
  - README.md
```

## ⚙️ Gereksinimler

- Python 3.6+
- Standart Python kütüphaneleri (ek kurulum gerekmez):
  - `os`, `hashlib`, `pickle`, `json`, `argparse`, `time`

## 🤝 Katkıda Bulunma

1. Projeyi fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

Detaylar için [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) dosyasını inceleyiniz.

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE.md](LICENSE.md) dosyasını inceleyiniz.

## 🐛 Sorun Bildirimi

Bir sorunla karşılaştıysanız, lütfen [Issues](https://github.com/ibrahimyigitcetin/FolderSleuth/issues) sayfasından bildirin.
