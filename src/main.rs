use aes::Aes256;
use anyhow::{Context, Result};
use cbc::{
    cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit},
    Encryptor,
};
use clap::{Parser, Subcommand};
use hmac::Hmac;
use memchr::memmem;
use num_bigint::BigUint;
use pbkdf2::pbkdf2;
use rand::RngCore;
use regex::Regex;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use yasna::{construct_der, models::ObjectIdentifier};

type Aes256Cbc = Encryptor<Aes256>;

const OID_SHA1: &[u64] = &[1, 2, 840, 113549, 2, 5];
const OID_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];

#[derive(Parser)]
#[command(name = "kamusm-zd-rs")]
#[command(about = "Rust ile yazılmış KamuSM zaman damgası istemcisi")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// "identity" başlığı oluştur
    Identity {
        #[arg(long)]
        customer_id: u32,
        #[arg(long)]
        password: String,
        #[arg(long, group = "input")]
        digest_hex: Option<String>,
        #[arg(long, group = "input")]
        timestamp: Option<u64>,
        #[arg(long, default_value_t = 100)]
        iterations: u32,
    },
    /// Zaman damgası isteği gönder
    Send {
        #[arg(long)]
        host: String,
        #[arg(long)]
        customer_id: u32,
        #[arg(long)]
        password: String,
        #[arg(long, group = "input")]
        file: Option<String>,
        #[arg(long, group = "input")]
        digest_hex: Option<String>,
        #[arg(long, default_value = "sha256")]
        hash: String,
        #[arg(long, default_value_t = 100)]
        iterations: u32,
        #[arg(long)]
        certreq: bool,
    },
    /// Bakiyeyi kontrol et
    Credits {
        #[arg(long)]
        host: String,
        #[arg(long)]
        customer_id: u32,
        #[arg(long)]
        password: String,
        #[arg(long, default_value_t = 100)]
        iterations: u32,
        #[arg(long)]
        timestamp: Option<u64>,
    },
}

fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let block_size = 16;
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(vec![pad_len as u8; pad_len]);
    padded
}

fn derive_key(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, iterations, &mut key).unwrap();
    key
}

fn encrypt_aes_cbc(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let padded = pkcs7_pad(plaintext);
    let cipher = Aes256Cbc::new(key.try_into()?, iv.try_into()?);
    let mut buffer = padded;
    cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
        .map_err(|e| anyhow::anyhow!("Şifreleme hatası: {:?}", e))?;
    Ok(buffer)
}

fn build_identity(
    customer_id: u32,
    password: &str,
    message_imprint: &[u8],
    iterations: u32,
) -> Result<String> {
    let mut rng = rand::thread_rng();
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut iv);
    let salt = iv;

    let key = derive_key(password, &salt, iterations);
    let ciphertext = encrypt_aes_cbc(&key, &iv, message_imprint)?;

    // ASN.1 ESYAReqEx yapısını oluştur
    let der = construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_u32(customer_id);
            writer.next().write_bytes(&salt);
            writer.next().write_u32(iterations);
            writer.next().write_bytes(&iv);
            writer.next().write_bytes(&ciphertext);
        })
    });

    // DER'ı büyük tamsayıya ve sonra hex string'e dönüştür
    let bigint = BigUint::from_bytes_be(&der);
    Ok(format!("{:x}", bigint))
}

fn compute_file_digest(path: &str, alg: &str) -> Result<Vec<u8>> {
    let data = fs::read(path).context("Dosya okunamadı")?;

    match alg.to_lowercase().as_str() {
        "sha1" => Ok(Sha1::digest(&data).to_vec()),
        "sha256" => Ok(Sha256::digest(&data).to_vec()),
        _ => anyhow::bail!("Desteklenmeyen hash algoritması: {}", alg),
    }
}

fn build_tsa_request(digest: &[u8], hash_alg: &str, certreq: bool) -> Result<Vec<u8>> {
    let oid = match hash_alg.to_lowercase().as_str() {
        "sha1" => ObjectIdentifier::from_slice(OID_SHA1),
        "sha256" => ObjectIdentifier::from_slice(OID_SHA256),
        _ => anyhow::bail!("Desteklenmeyen hash algoritması: {}", hash_alg),
    };

    // Anlık zamandan nonce oluştur
    let nonce =
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64 & ((1u64 << 63) - 1);

    let der = construct_der(|writer| {
        writer.write_sequence(|writer| {
            // sürüm (version)
            writer.next().write_u32(1);

            // mesaj izi (messageImprint)
            writer.next().write_sequence(|writer| {
                // hash algoritması
                writer.next().write_sequence(|writer| {
                    writer.next().write_oid(&oid);
                    writer.next().write_null(); // parametreler
                });
                // hash'lenmiş mesaj (hashedMessage)
                writer.next().write_bytes(digest);
            });

            // nonce
            writer.next().write_u64(nonce);

            // sertifika isteği (certReq)
            if certreq {
                writer.next().write_bool(true);
            }
        })
    });

    Ok(der)
}

fn parse_credits_from_body(body: &[u8]) -> Option<u32> {
    let text = String::from_utf8_lossy(body);
    let re = Regex::new(r"(\d+)").ok()?;
    re.find(&text)?.as_str().parse().ok()
}

fn is_valid_timestamp_response(body: &[u8]) -> bool {
    // PKCS#7 SignedData OID: 1.2.840.113549.1.7.2
    let pkcs7_signeddata_oid = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
    ];

    // Yanıtın PKCS#7 SignedData OID'sini içerip içermediğini kontrol et
    memmem::find(body, pkcs7_signeddata_oid).is_some()
}

fn extract_text_from_asn1(body: &[u8]) -> Vec<String> {
    let mut texts = Vec::new();
    let mut i = 0;

    while i < body.len().saturating_sub(2) {
        let tag = body[i];
        let length = body[i + 1];

        // ASN.1 metin string türlerini işle
        match tag {
            0x0C | // UTF8String
            0x13 | // PrintableString  
            0x14 | // TeletexString
            0x16 | // IA5String
            0x19 | // GraphicString
            0x1A | // VisibleString
            0x1B | // GeneralString
            0x1C   // UniversalString
            => {
                if length > 0 && i + 2 + length as usize <= body.len() {
                    let text_bytes = &body[i + 2..i + 2 + length as usize];
                    if let Ok(text) = String::from_utf8(text_bytes.to_vec()) {
                        if !text.trim().is_empty() && text.chars().all(|c| c.is_ascii() && !c.is_control() || c.is_whitespace()) {
                            texts.push(text.trim().to_string());
                        }
                    }
                    i += 2 + length as usize;
                } else {
                    i += 1;
                }
            },
            _ => {
                i += 1;
            }
        }
    }

    texts
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Identity {
            customer_id,
            password,
            digest_hex,
            timestamp,
            iterations,
        } => {
            let digest = if let Some(hex) = digest_hex {
                hex::decode(hex).context("Geçersiz hex digest")?
            } else if let Some(ts) = timestamp {
                let s = format!("{}{}", customer_id, ts);
                Sha1::digest(s.as_bytes()).to_vec()
            } else {
                anyhow::bail!("--digest-hex veya --timestamp parametrelerinden biri sağlanmalıdır");
            };

            let identity = build_identity(customer_id, &password, &digest, iterations)?;
            println!("{}", identity);
        }
        Commands::Send {
            host,
            customer_id,
            password,
            file,
            digest_hex,
            hash,
            iterations,
            certreq,
        } => {
            let (digest, output_filename) = if let Some(path) = &file {
                let digest = compute_file_digest(path, &hash)?;
                let input_path = Path::new(path);
                let filename = input_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("file");
                let output_filename = if let Some(parent) = input_path.parent() {
                    parent.join(format!("{}_zd.der", filename))
                } else {
                    Path::new(&format!("{}_zd.der", filename)).to_path_buf()
                };
                (digest, output_filename.to_string_lossy().to_string())
            } else if let Some(hex) = digest_hex {
                let digest = hex::decode(hex).context("Geçersiz hex digest")?;
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let output_filename = format!("zd_{}.der", timestamp);
                (digest, output_filename)
            } else {
                anyhow::bail!("--file veya --digest-hex parametrelerinden biri sağlanmalıdır");
            };

            let der = build_tsa_request(&digest, &hash, certreq)?;
            let identity = build_identity(customer_id, &password, &digest, iterations)?;

            let client = reqwest::Client::new();
            let response = client
                .post(&host)
                .header("Content-Type", "application/timestamp-query")
                .header("User-Agent", "kamusm-zd-rs")
                .header("identity", &identity)
                .header("Cache-Control", "no-cache")
                .header("Pragma", "no-cache")
                .header("Accept", "text/html, image/gif, image/jpeg, */*; q=0.2")
                .header("Connection", "keep-alive")
                .body(der)
                .send()
                .await
                .context("İstek gönderilemedi")?;

            let status = response.status();
            println!("Yanıt durumu: {}", status);

            let body = response.bytes().await.context("Yanıt gövdesi okunamadı")?;

            // yardımcı: PKCS#7 OID (1.2.840.113549.1.7.2) baytlarını bul ve çevreleyen SEQUENCE'ı çıkar
            fn extract_pkcs7_with_memmem(buf: &[u8]) -> Option<Vec<u8>> {
                // 1.2.840.113549.1.7.2 için OID baytları
                let oid = b"\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02";

                if let Some(pos) = memmem::find(buf, oid) {
                    // 16 bayt içinde önceki 0x30'u geriye doğru ara
                    let start_search = pos.saturating_sub(16);
                    for i in (start_search..=pos).rev() {
                        if buf[i] == 0x30 {
                            if i + 1 >= buf.len() {
                                continue;
                            }
                            let len_byte = buf[i + 1];
                            let total_len = if len_byte & 0x80 == 0 {
                                let l = len_byte as usize;
                                l + 2
                            } else {
                                let num_bytes = (len_byte & 0x7F) as usize;
                                if num_bytes == 0 || i + 1 + num_bytes >= buf.len() {
                                    continue;
                                }
                                if num_bytes > 4 {
                                    continue;
                                }
                                let mut l: usize = 0;
                                for b in &buf[i + 2..i + 2 + num_bytes] {
                                    l = (l << 8) | (*b as usize);
                                }
                                l + 2 + num_bytes
                            };

                            if i + total_len <= buf.len() {
                                if pos < i + total_len {
                                    return Some(buf[i..i + total_len].to_vec());
                                }
                            }
                        }
                    }
                }
                None
            }

            // Geçerli bir zaman damgası yanıtı olup olmadığını kontrol et
            if is_valid_timestamp_response(&body) {
                // Geçerli zaman damgası yanıtı - kaydet
                if let Some(pkcs7) = extract_pkcs7_with_memmem(&body) {
                    fs::write(&output_filename, &pkcs7).context("Yanıt yazılamadı")?;
                    println!(
                        "Çıkarılan PKCS#7 SignedData {} dosyasına kaydedildi",
                        output_filename
                    );
                } else {
                    fs::write(&output_filename, &body).context("Yanıt yazılamadı")?;
                    println!("Yanıt gövdesi {} dosyasına kaydedildi", output_filename);
                }
            } else {
                // Geçerli bir zaman damgası değil - muhtemelen hata yanıtı
                println!("Hata yanıtı alındı (HTTP {})", status);

                // ASN.1 yapısından metin çıkar
                let texts = extract_text_from_asn1(&body);
                if !texts.is_empty() {
                    println!("Hata mesajları:");
                    for text in texts {
                        println!("  {}", text);
                    }
                } else {
                    // Yedek: metin olarak göstermeye çalış veya binary olarak kaydet
                    match String::from_utf8(body.to_vec()) {
                        Ok(text) => println!("Yanıt gövdesi (metin):\n{}", text),
                        Err(_) => {
                            fs::write(&output_filename, &body).context("Yanıt yazılamadı")?;
                            println!(
                                "Binary hata yanıtı {} dosyasına kaydedildi",
                                output_filename
                            );
                        }
                    }
                }
            }
        }
        Commands::Credits {
            host,
            customer_id,
            password,
            iterations,
            timestamp,
        } => {
            // Timestamp'i belirle (ya sağlanan değer ya da şimdiki zaman milisaniye olarak)
            let ts = timestamp.unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64
            });

            // Bakiye kontrolü için SHA1 özet oluştur: SHA1("{customer_id}{timestamp}")
            let s = format!("{}{}", customer_id, ts);
            let digest = Sha1::digest(s.as_bytes()).to_vec();

            // Identity başlığını oluştur
            let identity = build_identity(customer_id, &password, &digest, iterations)?;

            // HTTP isteği gönder
            let client = reqwest::Client::new();
            let response = client
                .post(&host)
                .header("Content-Type", "application/timestamp-query")
                .header("User-Agent", "kamusm-zd-rs")
                .header("identity", &identity)
                .header("Cache-Control", "no-cache")
                .header("Pragma", "no-cache")
                .header("Accept", "text/html, image/gif, image/jpeg, */*; q=0.2")
                .header("Connection", "keep-alive")
                .header("credit_req", customer_id.to_string())
                .header("credit_req_time", ts.to_string())
                .header("Content-Length", "0")
                .body(Vec::<u8>::new()) // Boş gövde
                .send()
                .await
                .context("Bakiye kontrolü isteği gönderilemedi")?;

            println!("Yanıt durumu: {}", response.status());

            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            let body = response.bytes().await.context("Yanıt gövdesi okunamadı")?;

            if content_type.starts_with("application/timestamp-reply") {
                if let Some(credits) = parse_credits_from_body(&body) {
                    println!("Kalan zaman damgası bakiyesi: {}", credits);
                } else {
                    // Yedek: ham gövdeyi göster
                    match String::from_utf8(body.to_vec()) {
                        Ok(text) => println!("Yanıt gövdesi (metin):\n{}", text),
                        Err(_) => {
                            fs::write("timestamp_resp.der", &body).context("Yanıt yazılamadı")?;
                            println!("Binary yanıt; timestamp_resp.der dosyasına kaydedildi");
                        }
                    }
                }
            } else {
                println!("Content-Type: {}", content_type);
                match String::from_utf8(body.to_vec()) {
                    Ok(text) => println!("Yanıt gövdesi (metin):\n{}", text),
                    Err(_) => {
                        fs::write("timestamp_resp.der", &body).context("Yanıt yazılamadı")?;
                        println!("Binary yanıt; timestamp_resp.der dosyasına kaydedildi");
                    }
                }
            }
        }
    }

    Ok(())
}
