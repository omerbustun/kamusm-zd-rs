
# kamusm-zd-rs

> 🇬🇧 [English](README_EN.md)

RFC 3161 ve Kamu SM'nin kimlik doğrulama protokolünü destekleyen, Rust ile yazılmış, resmi Java istemcisiyle uyumlu Kamu SM zaman damgası istemcisi.

## İçindekiler

- [kamusm-zd-rs](#kamusm-zd-rs)
  - [İçindekiler](#i̇çindekiler)
  - [Protokol Mimarisi](#protokol-mimarisi)
    - [Identity Başlığı](#identity-başlığı)
  - [Kriptografi Kaynakları](#kriptografi-kaynakları)
  - [Gereksinimler](#gereksinimler)
  - [Kurulum](#kurulum)
    - [Kaynak Koddan Derleme](#kaynak-koddan-derleme)
    - [Doğrudan Çalıştırma](#doğrudan-çalıştırma)
  - [Kullanım](#kullanım)
    - [Temel Komut Yapısı](#temel-komut-yapısı)
    - [Zaman Damgası İsteme](#zaman-damgası-i̇steme)
      - [Dosya için zaman damgası](#dosya-için-zaman-damgası)
      - [Hex özet için zaman damgası](#hex-özet-için-zaman-damgası)
    - [Bakiye Sorgulama](#bakiye-sorgulama)
    - [Identity Başlığı Oluşturma](#identity-başlığı-oluşturma)
  - [Yapılandırma Seçenekleri](#yapılandırma-seçenekleri)
    - [Ortak Parametreler](#ortak-parametreler)
    - [Send Komutu Özel Parametreleri](#send-komutu-özel-parametreleri)
    - [Çıktı Dosyaları](#çıktı-dosyaları)
  - [Teknik İmplementasyon](#teknik-i̇mplementasyon)
    - [Kriptografik Yığın](#kriptografik-yığın)
    - [MessageImprint Oluşturma](#messageimprint-oluşturma)
    - [Hata Yönetimi](#hata-yönetimi)
    - [HTTP İstek Formatı](#http-i̇stek-formatı)
  - [Örnekler](#örnekler)
    - [Başarılı Zaman Damgası İsteği](#başarılı-zaman-damgası-i̇steği)
    - [Resmi İstemci ile Doğrulama](#resmi-i̇stemci-ile-doğrulama)
    - [Bakiye Kontrolü](#bakiye-kontrolü)
    - [Hata Durumu](#hata-durumu)
  - [Bazı Hatalar](#bazı-hatalar)
  - [Uygulama Notları](#uygulama-notları)
    - [Bağımlılıklar](#bağımlılıklar)

## Protokol Mimarisi

Kamu SM zaman damgası sunucuları, standart RFC 3161 TimeStampReq/TimeStampResp yapısını kullanır ancak kimlik doğrulama için özel bir `identity` başlığı gerektirir:

- **HTTP**: `POST /` ile `application/timestamp-query`
- **Gövde**: RFC 3161 TimeStampReq (ASN.1 DER)
- **Kimlik doğrulama**: `identity` başlığı ile kullanıcı kimlik doğrulaması
- **Yanıt**: Sertifika ile birlikte PKCS#7 SignedData

### Identity Başlığı

`identity`, şu ASN.1 yapısının DER kodlamasının BigInteger hex formatıdır:

```asn1
ESYAReqEx ::= SEQUENCE {
    userid                 INTEGER,
    salt                   OCTET STRING (16 bytes),
    iterationCount         INTEGER (100),
    iv                     OCTET STRING (16 bytes, salt ile aynı),
    encryptedMessageImprint OCTET STRING
}
```

**Şifreleme Akışı:**
1. 16-byte rastgele değer → salt ve IV olarak kullanılır
2. PBKDF2-HMAC-SHA256(password, salt, 100 iterations) → 32-byte AES anahtarı
3. AES-256-CBC(messageImprint, key, iv) + PKCS#7 padding → şifreli veri
4. ASN.1 yapı → DER encoding → BigInteger → hex string

Bu, her istekte farklı salt/IV kullanarak replay saldırılarını önler.

## Kriptografi Kaynakları

- **RFC 3161**: Time-Stamp Protocol - Zaman damgası protokolü standardı ([RFC 3161](https://tools.ietf.org/html/rfc3161))
- **PKCS#7**: Public Key Cryptography Standards #7 ([RFC 2315](https://tools.ietf.org/html/rfc2315))
- **PKCS#7 SignedData**: Dijital imzalı veri yapısı ([RFC 2315 Bölüm 9.1](https://tools.ietf.org/html/rfc2315#section-9.1))
- **ASN.1**: Abstract Syntax Notation One - Veri yapısı tanımlama notasyonu ([ITU-T X.680](https://www.itu.int/rec/T-REC-X.680/))
- **DER**: Distinguished Encoding Rules - ASN.1 binary kodlama kuralları ([ITU-T X.690](https://www.itu.int/rec/T-REC-X.690/))
- **PBKDF2**: Password-Based Key Derivation Function 2 - Parola tabanlı anahtar türetme fonksiyonu ([RFC 2898 Bölüm 5.2](https://tools.ietf.org/html/rfc2898#section-5.2))
- **HMAC**: Hash-based Message Authentication Code - Hash tabanlı mesaj doğrulama kodu ([RFC 2104](https://tools.ietf.org/html/rfc2104))
- **AES-256**: Advanced Encryption Standard, 256-bit anahtar uzunluğu ([FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final))
- **CBC**: Cipher Block Chaining - Blok şifreleme modu ([Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)))


## Gereksinimler

- Rust (1.85 ile test edilmiştir)
- Cargo
- Geçerli Kamu SM kullanıcı hesabı (müşteri ID ve parola)
- İnternet bağlantısı

## Kurulum

### Kaynak Koddan Derleme

```bash
# Depoyu klonlayın
git clone https://github.com/omerbustun/kamusm-zd-rs.git
cd kamusm-zd-rs

# Derleyin
cargo build --release

# Çalıştırılabilir dosya target/release/ dizininde oluşacak
```

### Doğrudan Çalıştırma

```bash
# Debug modunda çalıştırma
cargo run -- --help

# Release modunda çalıştırma
cargo run --release -- --help
```

## Kullanım

### Temel Komut Yapısı

```bash
kamusm-zd-rs <KOMUT> [SEÇENEKLER]
```

### Zaman Damgası İsteme

#### Dosya için zaman damgası

```bash
# SHA256 (önerilen/varsayılan)
kamusm-zd-rs send \
    --host "http://zd.kamusm.gov.tr" \
    --customer-id 123 \
    --password "parola" \
    --file dosya.txt \
    --hash sha256

# SHA1
kamusm-zd-rs send \
    --host "http://zd.kamusm.gov.tr" \
    --customer-id 123 \
    --password "parola" \
    --file dosya.pdf \
    --hash sha1
```

#### Hex özet için zaman damgası

```bash
kamusm-zd-rs send \
    --host "http://zd.kamusm.gov.tr" \
    --customer-id 123 \
    --password "parola" \
    --digest-hex "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
    --hash sha256
```

### Bakiye Sorgulama

```bash
kamusm-zd-rs credits \
    --host "http://zd.kamusm.gov.tr" \
    --customer-id 123 \
    --password "parola"
```

### Identity Başlığı Oluşturma

```bash
# Hex digest ile
kamusm-zd-rs identity \
    --customer-id 123 \
    --password "parola" \
    --digest-hex "abc123..."

# Timestamp ile (bakiye kontrolü için)
kamusm-zd-rs identity \
    --customer-id 123 \
    --password "parola" \
    --timestamp 1635724800000
```

## Yapılandırma Seçenekleri

### Ortak Parametreler

- `--host`: Kamu SM zaman damgası sunucu adresi
- `--customer-id`: Müşteri ID numarası
- `--password`: Müşteri parolası
- `--iterations`: PBKDF2 iterasyon sayısı (varsayılan: 100)

### Send Komutu Özel Parametreleri

- `--file`: Zaman damgası alınacak dosya yolu
- `--digest-hex`: Doğrudan hex formatında hash değeri
- `--hash`: Hash algoritması (`sha1` veya `sha256`, varsayılan: `sha256`)


### Çıktı Dosyaları

- Dosya tabanlı işlemler: `{dosya_adı}_zd.der`
- Hex digest işlemleri: `zd_{timestamp}.der`
- Çıktı dosyaları PKCS#7 SignedData formatındadır

## Teknik İmplementasyon

### Kriptografik Yığın
- **Anahtar Türetme**: PBKDF2-HMAC-SHA256 (100 iterasyon, 32-byte anahtar)
- **Simetrik Şifreleme**: AES-256-CBC + PKCS#7 padding
- **ASN.1 İşleme**: DER encoding/decoding
- **Hash Algoritmaları**: SHA1/SHA256 OID'ler ile RFC 3161 uyumlu

### MessageImprint Oluşturma
- **Zaman Damgası İsteği**: Dosya/veri hash'i (SHA1/SHA256)
- **Bakiye Kontrolü**: SHA1(customerID + timestamp_millis)
- **Kimlik Doğrulama**: Her durumda ilgili hash şifrelenerek identity header'da gönderilir

### Hata Yönetimi
Kamu SM, hata durumlarında standart HTTP 200 döner ancak ASN.1 yapısında hata mesajı içerir. 
İstemci, PKCS#7 SignedData OID'sini (`1.2.840.113549.1.7.2`) arar:
- **Bulunursa**: Geçerli zaman damgası, PKCS#7 işlenir
- **Bulunamazsa**: ASN.1 ayrıştırılarak UTF8String/PrintableString alanlarından hata mesajı çıkarılır

### HTTP İstek Formatı
```http
POST / HTTP/1.1
Host: zd.kamusm.gov.tr
Content-Type: application/timestamp-query
User-Agent: kamusm-zd-rs
identity: <hex_kodlu_ESYAReqEx>
Cache-Control: no-cache
Pragma: no-cache
Content-Length: <der_uzunlugu>

<RFC3161_TimeStampReq_DER>
```

## Örnekler

### Başarılı Zaman Damgası İsteği

```bash
$ kamusm-zd-rs send --host "http://zd.kamusm.gov.tr" --customer-id 123 --password "parola" --file test.txt
Yanıt durumu: 200 OK
Çıkarılan PKCS#7 SignedData test_zd.der dosyasına kaydedildi
```

### Resmi İstemci ile Doğrulama

Kamu SM'nin resmi Java konsol istemcisi ile zaman damgasını doğrulayabilirsiniz:

**İndirme**: [Kamu SM Yazılım Platformu - Zamane](https://yazilim.kamusm.gov.tr/?q=tr/content/zamane)

```bash
$ java -jar tss-client-console-3.1.30.jar -c test.txt test_zd.der
[2025-Eyl-27 16:04:45,054 ÖS] [INFO ] : Dosya zaman damgasi kontrolu yapilacak.
[2025-Eyl-27 16:04:45,093 ÖS] [INFO ] : Zaman damgasi gecerli, dosya degismemis.
```

### Bakiye Kontrolü

```bash
$ kamusm-zd-rs credits --host "http://zd.kamusm.gov.tr" --customer-id 123 --password "parola"
Yanıt durumu: 200 OK
Kalan zaman damgası bakiyesi: 847
```

### Hata Durumu

```bash
$ kamusm-zd-rs send --host "http://zd.kamusm.gov.tr" --customer-id 999 --password "yanlis"
Yanıt durumu: 200 OK
Hata yanıtı alındı (HTTP 200 OK)
Hata mesajları:
  User 999 is not known
```

## Bazı Hatalar

**"Account could not be authenticated"**
- Kullanıcı şifresi hatalı

**"User is not known"**
- Müşteri ID bulunamadı
- Yanlış müşteri numarası

**Bağlantı hataları**
- Sunucu adresini kontrol edin
- İnternet bağlantınızı kontrol edin
- Güvenlik duvarı ayarlarını kontrol edin


## Uygulama Notları

### Bağımlılıklar
- **yasna**: ASN.1 DER kodlama/çözme (ESYAReqEx, TimeStampReq oluşturma)
- **aes + cbc**: AES-256-CBC uygulaması (identity şifrelemesi)
- **pbkdf2 + hmac**: Anahtar türetme (PBKDF2-HMAC-SHA256)
- **reqwest**: HTTP istemcisi (rustls-tls arka ucu, blocking desteği/async sarmalayıcı için uygun)
- **num-bigint**: Java BigInteger.toString(16) uyumluluğu


