# SIEM Guardian

**Splunk için yerel SIEM sağlık ve log kapsama aracı.** Bir hosttan herhangi bir log gelmesi, ihtiyaç duyduğunuz bütün güvenlik loglarının geldiği anlamına gelmez. SIEM Guardian, beklenen kaynakları ve belirli olay türlerini kontrol eder; bir tespitin ihtiyaç duyduğu loglar kaybolduğunda bunun tespit kabiliyetine etkisini gösterir.

Python 3.10+ ile çalışır. Sade bir yerel web arayüzü ve komut satırı (CLI) sunar. Splunk üzerinde yalnız **okuma amaçlı aramalar** yapar; index, forwarder veya detection ayarlarını değiştirmez.

![SIEM Guardian yerel dashboard ekran görüntüsü](docs/siem-guardian.png)

> Görüntü bir lab oturumundaki anlık sonuçtur; kurulumunuzda aynı sayılar beklenmez. Görünen `192.168.3.131` adresi örnek lab ortamınındır. Ekranda TLS doğrulaması lab için kapatılmıştır; varsayılan ayar açıktır.

## Neler yapar?

| Kontrol | Yanıtladığı soru |
| --- | --- |
| Kaynak sürekliliği | Beklenen `index + host + sourcetype` birleşiminden son log ne zaman geldi? |
| Log varlığı | Belirli `source` dosyası/kanalı seçilen aralıkta veri üretti mi? |
| Event ID | Örneğin Windows Security **4688** veya Sysmon **1** hâlâ geliyor mu? |
| Gerekli alan | Detection için gereken `CommandLine` gibi bir alan olaylarda dolu mu? |
| Zaman doğruluğu | Apache ham zaman damgası `_time` alanına doğru ayrıştırılmış mı? |
| Hacim | Önceki eşit aralığa göre log sayısı belirlenen oranda düştü mü? |
| Index yönlendirmesi | Aynı host ve sourcetype logları beklenen index yerine başka indexe mi gidiyor? |
| Detection bağımlılığı | Gerekli loglar eksikse hangi tespit kabiliyeti etkilenmiş olabilir? |

Örneğin **PowerShell tespiti**, Sysmon Event ID 1 **veya** PowerShell 4104'e bağlı olarak tanımlanabilir. İki akış da sorunluysa panel “PowerShell tespit kabiliyeti etkilenmiş olabilir” der. Bu, gerçek detection kuralının çalıştığını veya alarm ürettiğini doğrulamaz; **log bağımlılığını** ölçer.

Makineleriniz bazen kapalıysa kaynağı **aralıklı** seçebilirsiniz. Veri görülmemesi bu durumda `QUIET` olur; kesin arıza ilan edilmez. Aynı hosttan başka bir kontrol `OK` iken beklenen akış sessizse etkinlik referansı ile daha anlamlı bir `ALERT` üretilebilir. `NO_DATA` da tek başına “kaynak durmuş” kanıtı değildir.

## Ubuntu kurulumu

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
git clone https://github.com/efekanacar/siem-guardian.git
cd siem-guardian
/usr/bin/python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python webapp.py
```

Tarayıcıda **http://127.0.0.1:8787** açın. Terminal açık kalmalıdır; durdurmak için `Ctrl+C` kullanın. Port doluysa `python webapp.py --port 8788` çalıştırıp aynı portu tarayıcıda açın. Sanal ortamı normal kullanıcı hesabınızla oluşturun; eski, bozuk bir `(.venv)` etkinse önce `deactivate` yapın ve yeni klasörde `/usr/bin/python3 -m venv .venv` komutunu kullanın.

Arayüz yalnız `127.0.0.1` üzerinde dinler. Ubuntu VM'de çalıştırıp başka bilgisayardan erişmek isterseniz SSH tüneli açabilirsiniz:

```bash
ssh -L 8787:127.0.0.1:8787 kullanici@UBUNTU_IP
```

Ardından **kendi bilgisayarınızda** `http://127.0.0.1:8787` açın. [Ayrıntılı Türkçe arayüz rehberi](docs/ARAYUZ_KULLANIM.md) kurulum ve sorun giderme adımlarını içerir.

## Arayüzde kullanım

1. Solda Splunk **Management API** adresini (`https://SUNUCU:8089`) ve kullanıcı/parola **veya** Bearer token girip **Bağlan** seçin. `:8000` Splunk Web portudur; API adresi olarak kullanmayın.
2. **Splunk'tan getir** ile görünen `index`, `host`, `sourcetype` ve `source` değerlerini listeleyin. Henüz log göndermemiş ama beklediğiniz kaynakları **Hedef ekle** veya hedef CSV ile ayrıca girin. Keşif, beklenen envanterin yerine geçmez.
3. Genel geliş kontrolü için hedef eşiğini ve kontrol aralığını belirleyip sayfanın altındaki **Kontrolü çalıştır** düğmesine basın. Aralık bütün hedef eşiklerinden **uzun** olmalıdır. `OK`, `DELAYED`, `NO_DATA`, `ERROR` sonuçlarını ve CSV raporunu alın.
4. **İzlenecek kaynaklardan kurallar oluştur** ile her hedefe bir log varlığı kontrolü ekleyin. **Kontrol ekle** formuyla Event ID, alan, zaman, hacim veya yönlendirme kuralı ekleyin. `source` yalnız belirli dosya/kanalı izlemek istiyorsanız doldurulur. Aynı Splunk kaynak satırının alanlarını kullanın; wildcard desteklenmez.
5. **Detection ekle** formunda bir tespitin ihtiyaç duyduğu sağlık kontrollerini seçin. **Alternatif: biri yeterli** (`any`) veya **Zorunlu: hepsi gerekli** (`all`) seçimini yapın ve etki açıklamasını yazın.
6. **Sağlık kontrolünü çalıştır** düğmesine basın. Üstteki sağlık kartları ve Detection Dependency Monitoring paneli bu çalışmanın sonucuyla dolar. Her satırdaki **SPL ve iş bilgisi** ayrıntısını açabilir, CSV raporlarını indirebilirsiniz.
7. **Kuralları indir** (`checks.json`) ve **Hedef CSV indir** (`targets.csv`) ile yapılandırmanızı yedekleyin. Arayüz hedef ve kuralları aynı tarayıcının yerel depolamasında da tutar; parola/token burada tutulmaz. Gerçek envanter dosyalarını GitHub'a eklemeyin.

**Belirli log örneği:** Windows Security kaynağı için `Log varlığı` kontrolünde gerçek `index`, `host`, `sourcetype` ve isterseniz `source=WinEventLog:Security` girin. Ardından aynı kaynak için `Event ID` kontrolü ekleyip `event_id_field=auto`, `event_id=4688` seçin. Başka Security olayları gelirken 4688 gelmiyorsa sonuç `ALERT` olur. [Adım adım açıklama ve JSON örneği](docs/ARAYUZ_KULLANIM.md#json-ile-tanımlamak-isterseniz) rehberde bulunur.

Sağlık sonuçlarında `OK` eşik içinde, `ALERT` ölçülen bozulma, `QUIET` aralıklı kaynakta sessizlik, `NO_DATA` sürekli beklenen kaynakta görünmeyen veri, `INSUFFICIENT_BASELINE` karar için az veri, `ERROR` arama/erişim/işleme hatasıdır. Detection sonucu `COVERED`, `IMPAIRED`, `UNKNOWN` veya henüz ölçülmediyse `PENDING` olabilir. Splunk VM kapalıysa veya API ulaşılamıyorsa hata **veri yokmuş gibi** gösterilmez.

## CSV ve JSON ile yapılandırma

Arayüzden form kullanmak yeterlidir. Dosya tercih ederseniz `targets.example.csv` ve `checks.example.json` dosyalarını örnek alın; ikisi de **tamamen sahte** host/index değerleri içerir. Gerçek hedef CSV başlığı:

```csv
name,index,host,sourcetype,max_delay_minutes
Windows Security,GERCEK_INDEX,GERCEK_HOST,XmlWinEventLog:Security,30
```

Sağlık kontrolleri `checks.json` içindeki `checks` listesinde, detection bağımlılıkları `detections` listesinde tanımlanır. Örnek:

```json
{
  "checks": [
    {
      "name": "Windows 4688",
      "kind": "event_id",
      "index": "GERCEK_INDEX",
      "host": "GERCEK_HOST",
      "sourcetype": "XmlWinEventLog:Security",
      "window_minutes": 240,
      "availability": "intermittent",
      "event_id_field": "auto",
      "event_id": "4688",
      "min_events": 1
    }
  ],
  "detections": [
    {
      "name": "Süreç oluşturma kapsamı",
      "technique": "T1059",
      "mode": "all",
      "checks": ["Windows 4688"],
      "impact": "Süreç oluşturma tespit kabiliyeti etkilenmiş olabilir."
    }
  ]
}
```

`index`, `host`, `sourcetype` tam eşleşmelidir. `source` isteğe bağlıdır. Detection içindeki `checks` adları sağlık kontrollerinin `name` değerleriyle birebir aynı olmalıdır. Sysmon henüz kurulu değilse örnekteki Sysmon kuralını gerçek envantere eklemeyin.

## CLI kullanımı

Arayüzde kimlik bilgileri girilir; CLI için `.env` dosyası gerekir:

```bash
cp .env.example .env
cp targets.example.csv targets.csv
cp checks.example.json checks.json
# .env, targets.csv ve checks.json içindeki örnek değerleri kendi ortamınıza göre düzenleyin.
python checker.py --targets targets.csv --window-minutes 120 --output reports/continuity.csv
python healthcheck.py --checks checks.json --output reports/health.csv --show-spl
```

`.env` içinde `SPLUNK_BASE_URL=https://SUNUCU:8089` ve `SPLUNK_TOKEN` **veya** `SPLUNK_USERNAME` + `SPLUNK_PASSWORD` doldurun. TLS doğrulaması varsayılan açıktır; özel CA için `SPLUNK_CA_BUNDLE` kullanın. Yalnız lab için açıkça `SPLUNK_VERIFY_TLS=false` seçilebilir. HTTP ve Splunk search timeout'ları vardır; arama bitmeden sonuç alınmaz. İsteğe bağlı webhook/e-posta bildirimi CLI'da yapılandırılır ve yalnız `--notify` ile gönderilir; arayüz otomatik bildirim göndermez.

## Ölçüm ve sınırlar

Son log **gelişi** `_indextime` üzerinden ölçülür. `_time` olay zamanıdır; bugün indekslenen eski bir olayı yanlışlıkla bugünün olayı saymamak için geliş ve olay zamanı ayrı ele alınır. Kontrol penceresi `_index_earliest`/`_index_latest` ve kesin `_indextime` koşuluyla uygulanır; event-time aralığı gecikmiş veya yanlış parse edilmiş olayları kaçırmamak için geniş tutulur. Apache zaman kuralı, ham Apache zamanını `_time` ile ayrıca karşılaştırabilir. Hacim kuralı önceki **eşit uzunluktaki** aralığı kullanır; mesai/hafta döngülerine göre eşikleri sizin ayarlamanız gerekir.

Beklenen hedefler sonuçta korunur; görünmeyenler rapordan düşmez. Rol/index yetkisi veya bozuk/kısmi Splunk araması güvenilir ölçümü engelleyebilir. `ERROR` böyle durumlarda `NO_DATA`ya dönüştürülmez. Splunk hesabının hedef indexleri görebildiğini ayrıca doğrulayın. Gerçek Splunk ortamınızda uçtan uca sonucu kendi verinizle test edin.

Yalnız `requests`, `python-dotenv` ve Python standart kütüphanesi kullanılır. `.gitignore`; `.env`, gerçek hedefler, `checks.json`, raporlar ve sertifikaları dışlar. Kod ve örnekler için:

```bash
python -m unittest discover -s tests -v
```
