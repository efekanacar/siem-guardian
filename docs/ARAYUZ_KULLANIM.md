# Arayüz kullanım rehberi

Bu rehberde eski kaynak sürekliliği akışı da bulunur. Yeni **SIEM Guardian**
paneli için önce `checks.example.json` dosyasını
`checks.json` adıyla kopyalayıp gerçek index/host/sourcetype ve eşikleri yazın.
Arayüzde Splunk'a bağlanın, **Kontrol JSON / CSV yükle** ile dosyayı seçin ve
**Sağlık kontrolünü çalıştır** düğmesine basın. Sonuçlarda her kuralın durumu,
ölçülen değer, eşik, açıklama ve açılabilir SPL görünür. **CSV raporu indir** ile
sonuçları alın. Detection Dependency Monitoring bölümünde etkilenen tespitleri
görüp detection CSV raporunu indirebilirsiniz. Örnek JSON'u arayüzden de
indirebilirsiniz. Gerçek `checks.json`
yerel kalır. Kural türleri ve alanları için [README](../README.md#sağlık-kontrolleri)
bölümüne bakın.

## Ubuntu kurulumu

ZIP'i çıkarın ve `siem-guardian` klasöründe terminal açın.
Python 3.10+ gerekir. İlk kurulumda:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 webapp.py
```

Tarayıcıda **http://127.0.0.1:8787** açın. Terminal açık kalmalı; Ctrl+C sunucuyu
durdurur. Sonraki kullanımda proje klasörüne geçip `source .venv/bin/activate`
ve `python3 webapp.py` yeterlidir. Aktivasyon gerekmeyen alternatif:
`.venv/bin/python webapp.py`. Windows'ta `.venv\Scripts\python.exe webapp.py`.

Güncellemede önce eski sunucuyu terminalinde **Ctrl+C** ile durdurun. Yeni ZIP'i
ayrı klasöre çıkarıp o klasörden başlatın; tarayıcıyı yenileyip yeniden bağlanın.
Eski hedeflerinizi saklamak için güncellemeden önce **Hedef CSV indir** seçin ve
yeni arayüzde bu dosyayı yükleyin. Splunk arama sonuçları CSV'si, hedef CSV'si
yerine yüklenemez; doğru hedefleri **Splunk'tan getir** ile de alabilirsiniz.

## Bağlantı

Sol panel management adresi, kullanıcı adı ve parola ister. Başlangıç adresi
`https://192.168.3.131:8089`; ortamınızın gerçek adresi farklıysa değiştirin.
8000 Splunk Web portudur; araç bunu API olarak kabul etmez. Token sekmesinden
Bearer token ile de bağlanabilirsiniz. Arayüz .env'den kimlik bilgisi yüklemez.

**Bağlan**, `GET /services/authentication/current-context` yanıtını doğrular.
Başarılı cevap alınmadan bağlı gösterilmez. Bu bağlantı doğrulaması, bütün
indexlerde arama yetkisinin olduğunu tek başına kanıtlamaz.

TLS kutusu başlangıçta işaretlidir. Özel CA sertifikası ayrıntısında sunucunun
erişebildiği dosyanın tam yolunu yazabilirsiniz. Sertifika host/IP eşleşmesi
gerekir. Yalnız lab için TLS doğrulaması açıkça kapatılabilir; arayüz uyarır.
TLS kapalıysa özel CA yolunu boş bırakın. HTTP timeout 10, search job başına arama
timeout 60 saniyedir; arka planda çalışırken ilerleme gösterilir.

Giriş bilgileri yalnız sunucu belleğinde bulunur; dosyaya, rapora veya tarayıcı
depolamasına yazılmaz. Başarılı girişten sonra parola/token alanı temizlenir.
**Bağlantıyı kes** bunları oturumdan siler; devam eden işlem mevcut HTTP
isteğinden sonra durur. 30 dakika hareketsiz kalan oturum sonraki istekte sona
erer. Sunucuyu kapatmak bütün oturumları sona erdirir. Kimlik doğrulama bilgileri
başka bir hizmete aktarılmaz; yalnız girilen Splunk management adresine gider.

## Hedefler

- **Splunk'tan getir**: İndekslerden `tstats` ile gözlenen gerçek index/host/sourcetype
  birleşimlerini ve source dosyalarını/kanallarını getirir. Geleceğe tarihlenmiş
  olaylar keşifte dışarıda kalabilir. Yeni hedeflerin eşiği 30 dakikadır; değiştirilebilir.
  Mevcut hedefler, özel adlar ve eşikler korunur. Hiç görülmeyen beklenen kaynaklar
  keşifte bulunamayacağı için CSV ile veya elle eklenmelidir.
- **CSV yükle**: targets.csv seçin. Gerekli başlık:
  `name,index,host,sourcetype,max_delay_minutes`. Yükleme mevcut listeyi değiştirir.
- **Hedef ekle**: Bütün alanları doldurun; index/host/sourcetype tam eşleşmeli,
  ad benzersiz olmalı. Satırdaki çarpı yalnız oturum listesinden çıkarır.
- **Hedef CSV indir**: Düzenlenen listeyi targets.csv olarak kaydeder; CLI ile
  kullanılabilir. Mevcut kaynak dosyasına otomatik yazılmaz.

En fazla 500 hedef ve 900 KB yükleme kabul edilir. Keşif 500'den fazla birleşim
bulursa eksik bir liste döndürmek yerine hata verir; izlenecek kaynakları CSV
ile seçin. Source sütunu salt okunur; birden çok değer varsa listeyi açın.
Source, dosya/kanal; sourcetype, veri türüdür. Kontrol index + host + sourcetype
birleşimiyle yapılır. Aynı türde başka bir dosya akarken tek dosyanın kesilmesi
bu toplu kontrolle anlaşılmaz. Source bilgisi hedef CSV'sine eklenmez.
Wildcard hedefler desteklenmez. Kontrol penceresi bütün eşiklerden kesinlikle
uzun olmalı; eşitlik geçersizdir. Örneğin 30 dakika eşik ve 120 dakika pencere.

## Kontrol ve rapor

**Kontrolü çalıştır** Splunk'ın kendi saatini alır ve bütün hedefler için aynı UTC
başlangıç zamanını ve `[T-pencere, T)` aralığını kullanır. İstemci bilgisayarın
saati bu ölçümü kaydırmaz. Splunk saati alınamazsa kontrol başlamaz ve hata gösterilir.
Son geliş açıkça istenen `_indextime` alanının maksimumu ile ölçülür;
olay zamanı `_time` değildir. Arama normal tamamlanmadan sonuç alınmaz.
Hatalı hedef ERROR olur; diğer hedefler devam eder. Kontrol manuel başlatılır.

Araç hedef indexlerde **tek toplu arama** yapar ve index/host/sourcetype birleşimine
göre pencere içindeki son gelişleri alır. Geniş event-time sınırı
`earliest=0 latest=+10y`, eski olay zamanıyla yeni gelen logları da kapsar.
Kontrol aralığı `_index_earliest`/`_index_latest` ve kesin `_indextime` koşuluyla
uygulanır. Böylece tüm geçmişin eski bucket'ları gereksiz taranmaz. Pencereden
daha eski gelişler aranmamış olur; `NO_DATA` için son geliş zamanı boş bırakılır.
Hiç üçlü eşleşmiyorsa hedef alanlarını ve index yetkisini kontrol edin.
NO_DATA açıklaması, aynı host/sourcetype'ın başka bir hedef indexte görüldüğünü
veya aynı hosttan yalnız diğer logların geldiğini söyleyebilir. Makinenin açık
olması tek başına bu kanalın Splunk'a ulaştığını kanıtlamaz.
API boş/eksik satır döndürürken job'ın sonuç sayısı daha yüksekse ERROR verilir.

**Arama ayrıntıları** bölümünü açarak Splunk ölçüm zamanını, pencereyi, gerçek
SPL'yi, dönen kaynak satırı sayısını ve kaç hedefin tam eşleştiğini inceleyin.
Tablo, aramanın döndürdüğü gerçek index/host/sourcetype ve en son görünür gelişleri
gösterir. **Arama tanı raporunu indir**, JSON dosyası üretir; parola/token içermez.
Bu dosya gerçek kaynak bilgisi içerir, GitHub paylaşımına eklemeyin.

- **OK**: Gecikme eşik içinde; eşik sınırı dahil.
- **DELAYED**: Log bulundu ama geliş eşiği aşıldı.
- **NO_DATA**: Pencerede eşleşen log bulunamadı; kaynak kesin durmuş denemez.
- **ERROR**: Erişim, arama, timeout, kısmi sonuç veya veri işleme hatası.

Durum kartları tüm raporu sayar. Durum düğmeleri ve arama alanı görüntüyü
filtreler; indirilen rapor bütün hedefleri içerir. Hedef/pencere düzenlenince
eski rapor gizlenir; yeniden kontrol başlatın. **Raporu indir**, tamamlanan
raporu 8 alanla UTF-8 BOM CSV olarak indirir. NO_DATA ve ERROR için zaman ve
gecikme boş kalır. Raporlar diskte otomatik saklanmaz; gerektiğinde indirin.

## Ubuntu sanal makinede tarayıcı erişimi

Arayüz yalnız localhost'ta dinler. Tarayıcı Ubuntu içinde ise doğrudan
http://127.0.0.1:8787 açın. Başka bilgisayardan SSH erişiminiz varsa, uygulama
Ubuntu'da açıkken kendi bilgisayarınızda tünel oluşturun:

```bash
ssh -L 8787:127.0.0.1:8787 kullanici@UBUNTU_IP
```

Yer tutucuları kendi Ubuntu kullanıcı adı ve IP'siyle değiştirin; ardından
kendi tarayıcınızda http://127.0.0.1:8787 açın. SSH terminali açık kalmalı.
Arayüzü genel ağa açmak için bir host seçeneği sunulmaz; yerel, tek kullanıcılı araçtır.

## Sorun giderme

- **Port kullanımda**: `python3 webapp.py --port 8788`; tarayıcıda 8788 açın.
- **HTTP 401/403**: Splunk kimlik bilgisi, token ve rol yetkisini kontrol edin.
- **TLS hatası**: CA dosyası ve host/IP eşleşmesini kontrol edin.
- **Bağlantı/timeout**: Ubuntu'dan management 8089 portuna ağ erişimi gerekir.
- **Keşif boş**: Hesabın index görünürlüğünü ve ortamda veri bulunduğunu kontrol edin.
- **NO_DATA**: Kaynak aralıklı veya düşük hacimliyse pencereyi beklenen sıklığa göre
  büyütün; pencere her eşikten uzun olmalı.
  Hiç eşleşme yoksa gerçek index/host/sourcetype değerlerini ve index yetkisini doğrulayın.
  `source` dosya/kanal adını `sourcetype` yerine yazmayın. Splunk'tan getir, mevcut
  hedefleri silmez; eski veya yanlış hedef satırlarını elle kaldırabilirsiniz.
- **Bütün hedefler NO_DATA**: Arama ayrıntılarını açın. Dönen kaynak sayısı pozitif,
  eşleşen hedef sayısı sıfırsa hedef alanlarını tabloda görünen değerlerle karşılaştırın.
  Kontrol aralığını ve kaynakların gerçekten yeni log gönderip göndermediğini
  kontrol edin. Dönen satır sayısı sıfırsa gösterilen SPL'yi aynı hesapla Splunk Search'te
  **All time** seçerek deneyin. JSON tanı raporu bu farkı incelemek için kullanılabilir.
- **Bucket okuma hatası**: Splunk Search'teki **Show errors** listesini açın. Bozuk
  bucket kontrol penceresindeyse sonuç kısmi olabilir; araç bunu ERROR olarak bırakır.
  İlgili `search.log` ve bucket sağlığını Splunk yöneticisi incelemelidir.
- **Keşif uyarısı**: Kaldırılma veya tanınmayan WARN mesajı keşfi durdurmaz;
  sarı alanda açıklama görünür. Listeyi beklenen hedeflerinizle karşılaştırın.
- **Arama uyarısı/hatası**: Eksik sonuç, indexer, limit, yetki, lisans veya zaman
  aralığı sorunu tanınırsa sonuç kabul edilmez. Arayüzdeki açıklamayı takip edin;
  asıl mesaj için Splunk Search işinin mesajlarını açın. Süreklilik kontrolünde
  bütün uyarılar ERROR olarak kalır; hiçbir hata NO_DATA'ya dönüştürülmez.
- **Oturum sona erdi**: Sayfayı yenileyip yeniden bağlanın; hedefleri CSV ile yükleyin.
- **Eski rapor görünmüyor**: Hedef veya pencere değişince yeniden kontrol gerekir.

Test: `python3 -m unittest discover -s tests -v`. CLI: `python3 checker.py`.
Testler sahte REST yanıtlarıyla çalışır; **canlı Splunk bağlantısı test edilmedi**.
Kontrol ve kaynak keşfi için Splunk'a bağlanmak gerekir. Örnek CSV yalnız
dosya biçimini gösterir; sahte alanları gerçek hedeflerinizle değiştirin.
