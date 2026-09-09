# 🛡️ AI-Augmented SOC Analyst

Bu proje; web sunucusu loglarını yerel kurallarla analiz ederek siber tehditleri tespit eden, dinamik risk puanlaması yapan ve elde edilen bulguları Google Gemini (`gemini-3.6-flash`) yardımıyla iş odaklı güvenlik analiz raporlarına dönüştüren bir CLI (komut satırı) aracıdır.

---

## Projenin Teknik Açıklaması

Bu projenin arkasındaki düşünce yapısı, yazılım geliştirme sürecinin kendisini ve yapay zeka entegrasyonunu siber güvenlik perspektifinden ele alır.

### 1. Projeyi Kodlama Amacımız (Neden?)
Bu projeye başlarken temel hedefim, sadece çalışan bir siber güvenlik aracı üretmek değildi. Asıl motivasyonum; siber güvenlik, yazılım geliştirme ve yapay zeka teknolojilerinin kesişiminde **kontrollü ve güvenilir bir yapay zeka iş akışı** tasarlamaktı. Yapay zeka modellerinin siber güvenlik gibi hata kabul etmeyen bir alanda doğrudan karar verici olarak kullanılması, yüksek maliyet ve "halüsinasyon" (uydurma bulgu) gibi büyük riskler taşır. Bu risklerin önüne geçebilmek adına, yapay zekayı bir asistan olarak konumlandırıp asıl tespiti yerel ve deterministik kurallara bırakan bir mimari kurmayı hedefledim.

### 2. Projeyi Nasıl Kodladık? (Metodoloji)
Kod üretim sürecini tamamen kontrol altında tutabilmek amacıyla yapay zekayı belirli kurallarla sınırlandırdım. Uyguladığım metodoloji şu adımlardan oluşuyor:
*   **Bağlam ve Kurallar Çerçevesi:** `.ai/CONTEXT.md` ile projenin vizyonunu, `.ai/RULES.md` ile yapay zekanın uyması gereken katı yazılım ve güvenlik sınırlarını, `.ai/LOGS.md` ile de projedeki mimari kararları (ADR) kayıt altına aldım.
*   **Modüler Mimari:** Projenin her bir katmanının sınırlarını net bir şekilde çizdim. Log ayrıştırıcı (Parser), tehdit tespit motoru (Detector), risk puanlayıcı (Risk Evaluator) ve yapay zeka zenginleştirme (AI Enricher) modüllerini birbirinden tamamen bağımsız çalışacak şekilde tasarladım.
*   **Güvenilirlik ve Değişmezlik:** Log verilerinin analiz sırasında değişmesini önlemek amacıyla veri modellerini değişmez (immutable) dataclass'lar olarak tanımladım. Yapay zeka servislerinin (API) kesilmesi veya erişilememesi durumuna karşı ise sistemin kesintisiz çalışabilmesini sağlayan bir lokal yedek (fallback) mekanizması entegre ettim.

### 3. Kodun Genel Çalışma Prensibi (Nasıl Çalışıyor?)
Sistem, ham bir log verisini alarak adım adım şu süreçlerden geçirir:
1.  **Ayrıştırma:** Ham log satırı, `ApacheLogParser` tarafından okunarak düzenli ifadeler yardımıyla parçalara ayrılır ve yapısal bir `LogEvent` nesnesine dönüştürülür.
2.  **Lokal Analiz:** Bu nesne, `SQLInjectionDetector` veya `XSSDetector` gibi yerel motorlarda siber güvenlik kurallarına tabi tutulur. Şüpheli bir durum tespit edildiğinde, internete ihtiyaç duymadan yerel bir bulgu (`Finding`) oluşturulur.
3.  **Risk Değerlendirmesi:** `RiskEvaluator`, bulunan tehdidi siber güvenlik risk metodolojisine göre puanlar. Tehdidin büyüklüğü ve sistemin bundan ne kadar emin olduğunun yanı sıra sunucunun verdiği yanıt (HTTP durum kodu) analiz edilir. Sunucunun `200` (Başarılı) döndüğü durumlar kritik, `403` (Engellenmiş) döndüğü durumlar ise daha düşük öncelikli olarak dinamik şekilde skorlanır.
4.  **AI ile Zenginleştirme:** Lokal analiz tamamlandıktan sonra, elde edilen bulgular `GeminiEnricher` aracılığıyla `gemini-3.6-flash` modeline gönderilir. Yapay zeka, bu teknik bulguyu iş dünyasının ve yöneticilerin anlayabileceği iş risklerine, teknik analiz raporuna ve siber müdahale rehberine dönüştürerek raporlar.

---

## 🛠️ Sistem Mimarisi

Proje, katmanların sorumluluklarının kesin olarak ayrıldığı (Separation of Concerns) modüler bir mimariye sahiptir:

```text
  Ham Log Satırı (Raw Apache Log)
                |
                v
       [ ApacheLogParser ] 
                |
          (LogEvent) (Değişmez Veri Modeli)
                |
                v
       [ Detection Engine ]
         ├── SQLInjectionDetector ---> (Yerel Regex İmzaları)
         └── XSSDetector ------------> (Yerel Regex İmzaları)
                |
            (Finding) (Güvenlik Bulgusu)
                |
                v
       [ Risk Evaluator ] -------> (Etki Derecesi + Sunucu Yanıtı Analizi)
                |
        (RiskAssessment) (0-100 Dinamik Risk Skoru)
                |
                v
       [ GeminiEnricher ] -------> API Aktif -> [ gemini-3.6-flash ] -> Canlı Rapor
                |                  API Pasif -> [ Yerel Fallback ] ---> Deterministik Özet
                v
        [ CLI Console ] ---------> (Yönetici Özeti + Kök Neden Analizi + Müdahale Rehberi)
```

---

## 🚀 Hızlı Başlangıç

### Gereksinimler
*   Python 3.11+
*   Google Gemini API Key (Opsiyonel)

### Kurulum

```bash
# Repoyu klonlayın
git clone https://github.com/KaiserBlanca/ai-augmented-soc-analyst.git
cd ai-augmented-soc-analyst

# Bağımlılıkları yükleyin
pip install -r requirements.txt
```

### Çalıştırma

```powershell
# Windows PowerShell üzerinde PYTHONPATH belirterek CLI aracını çalıştırın:
$env:PYTHONPATH="src"; python -m soc_analyst.cli
```

*Sisteminizde `GEMINI_API_KEY` ortam değişkeni tanımlı ise yapay zeka analiz raporu canlı olarak üretilir. Tanımlı değilse, sistem yerel deterministik yedek analizi ekrana basar.*

---

## 📂 Dosya Yapısı

*   `src/soc_analyst/`: Uygulamanın tüm kaynak kodları ve iş katmanları bu dizinde yer alır.
    *   `parsers/`: Log ayrıştırıcı modüller.
    *   `detection/`: Yerel siber güvenlik tespit motorları.
    *   `models/`: Veri bütünlüğünü korumak için tasarlanmış değişmez (immutable) veri sınıfları.
    *   `risk/`: Dinamik risk puanlama motoru.
    *   `ai/`: Google Gemini entegrasyonu ve yerel fallback modülü.
*   `tests/`: Projenin güvenirliğini kanıtlayan, internet bağımsız çalışan 71 adet birim test.
*   `.ai/`: Yapay zeka geliştirme sürecini yöneten bağlam ve kural dosyaları.

---

## 🧪 Testler ve Doğrulama

Sistemde bulunan 71 adet birim test, internet bağlantısına ihtiyaç duymadan `mock` mekanizmalarıyla çalışmaktadır. Bu testler, sistemin hem gerçek saldırıları (True Positive) kaçırmadığını hem de normal kullanıcı isteklerini (False Positive) hatalı değerlendirmediğini denetler.

Testleri çalıştırmak için:

```bash
python -m pytest
```

---

## 📜 Lisans

Bu proje MIT Lisansı altında açık kaynak olarak sunulmuştur. Detaylar için `LICENSE` dosyasına göz atabilirsiniz.

---

## 🇬🇧 In English (Short Version)

**AI-Augmented SOC Analyst** is a CLI-based security log analysis tool designed to demonstrate **AI Agent Governance and Confinement** under the Google Antigravity framework. 

By applying the core thesis of **"AI as the assistant, determinism as the judge"**, cyber threats (SQLi & XSS) are detected locally using high-fidelity offline regex signatures. The system dynamically calculates a **0-100 risk score** based on the HTTP response status code, ensuring a business-oriented risk alignment (GRC). 

Once local detection is complete, the tool leverages `gemini-3.6-flash` as a translation layer to construct detailed Executive Summaries, Root Cause Analyses, and Remediation Playbooks. Built-in **deterministic fallback mechanisms** ensure continuous execution even in offline environments. Features 71 fully-mocked, offline pytest cases running in under 0.4 seconds. Designed to bridge cyber security technology with business risk management.
