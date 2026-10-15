# SIEM Guardian arayüz kullanım rehberi

SIEM Guardian'ın web arayüzü tek bir işe odaklanır: Splunk'ta sizin
oluşturduğunuz alertleri bulur ve bu alertlerin ihtiyaç duyduğu logların seçilen
zaman aralığında gelip gelmediğini kontrol eder.

## Ubuntu kurulumu

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
git clone https://github.com/efekanacar/siem-guardian.git
cd siem-guardian
/usr/bin/python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python webapp.py
```

Tarayıcıdan `http://127.0.0.1:8787` adresini açın. Port kullanımdaysa:

```bash
python webapp.py --port 8788
```

Başka bir bilgisayardan Ubuntu üzerindeki arayüze erişmek için SSH tüneli:

```bash
ssh -L 8787:127.0.0.1:8787 kullanici@UBUNTU_IP
```

Ardından kendi bilgisayarınızda `http://127.0.0.1:8787` açın.

## Splunk bağlantısı

1. Management adresini `https://SPLUNK_IP:8089` biçiminde yazın. `8000`, web
   arayüzü portudur ve REST API adresi olarak kullanılmaz.
2. Alertleri hangi Splunk kullanıcısı oluşturduysa o kullanıcıyla giriş yapın.
   Token kullanıyorsanız token sahibinin alertleri kontrol edilir.
3. Geçerli bir sertifika kullanıyorsanız TLS doğrulamasını açık bırakın. Yalnız
   lab ortamındaki self-signed sertifika için doğrulamayı kapatabilirsiniz.
4. **Bağlan** düğmesine basın.

Araç `/services/authentication/current-context` üzerinden oturum sahibini
belirler. Sonra yalnız bu sahibin etkin ve zamanlanmış alertlerini okur. Başka
kullanıcıların, Splunk'ın veya kurulu uygulamaların alertleri listeye alınmaz.

## Alert loglarını kontrol etme

1. **Kontrol aralığı** alanına dakika yazın. Varsayılan `1440`, son 24 saattir.
   Sistemleriniz sürekli açık değilse `4320` ile son 3 günü veya `10080` ile son
   7 günü kontrol edebilirsiniz.
2. **Logları kontrol et** düğmesine basın.
3. Araç her alert SPL'inde açıkça yazılan `index`, `host`, `sourcetype`,
   `source`, `EventCode` ve `EventID` değerlerini çıkarır.
4. Her benzersiz log bağımlılığı Splunk'ta salt okunur bir SPL ile sorgulanır.
   Log geliş zamanı `_indextime` üzerinden ölçülür.
5. Alert satırını inceleyin. **Alert SPL ve kontrol sorguları** bölümü özgün
   alert sorgusunu ve aracın çalıştırdığı sağlık sorgularını gösterir.
6. **Alert CSV indir** ile sonucu raporlayabilirsiniz.

## Durumların anlamı

| Durum | Anlamı |
| --- | --- |
| `COVERED` | Alertin çıkarılabilen bütün log bağımlılıklarında veri görüldü. |
| `DEGRADED` | Bazı loglar geliyor, bazıları gelmiyor veya doğrulanamadı. |
| `BLIND` | Alertin açık log bağımlılıklarının hiçbirinde veri görülmedi. |
| `UNKNOWN` | SPL'den güvenilir bir kaynak çıkarılamadı. |
| `ERROR` | Splunk araması, erişim veya veri işleme hatası oluştu. |

`BLIND` veya `NO_DATA`, kaynağın kesin olarak durduğunu tek başına kanıtlamaz.
Seçilen kontrol aralığı, düşük log hacmi ve kapalı makineler sonucu etkileyebilir.

## Neden bazı alertler incelenmeli görünür?

Araç yalnız SPL içinde açıkça görülen sabit değerleri güvenle kontrol eder.
Aşağıdaki yapıların içindeki log kaynaklarını tahmin etmez:

- SPL makroları
- lookup dosyaları
- `tstats` ve veri modelleri
- wildcard içeren kaynak seçimleri
- çalışma anında token ile değişen değerler

Bu yaklaşım, araç çözemediği bir alerti yanlışlıkla sağlıklı göstermesin diye
seçilmiştir. Ayrıntı bölümündeki özgün SPL'i inceleyerek alertin gerçek kaynağını
görebilirsiniz.

## Beklediğiniz 31 alert görünmüyorsa

Splunk Search ekranında aşağıdaki salt okunur sorguyla alert sahiplerini kontrol
edebilirsiniz:

```spl
| rest /servicesNS/-/-/saved/searches
| search disabled=0 is_scheduled=1 alert_type!="none"
| stats count by eai:acl.owner
```

31 alert hangi kullanıcı altında görünüyorsa SIEM Guardian'a o kullanıcı veya o
kullanıcıya ait token ile bağlanın. Alert başka kullanıcıya aitse araç onu bilinçli
olarak listelemez.

## Güvenlik

- Splunk üzerinde yalnız GET ve arama işlemleri yapılır.
- Alert, index veya forwarder ayarı değiştirilmez.
- Parola ve token tarayıcı yerel depolamasına yazılmaz.
- Arayüz varsayılan olarak yalnız `127.0.0.1` üzerinde dinler.
- TLS doğrulaması varsayılan olarak açıktır.
