# Gemini AI Entegrasyonu Kurulumu

Bu extension artık Gemini AI'ya akıllı sözleşme kaynak kodlarını göndererek detaylı güvenlik analizi yapıyor.

## Kurulum

### 1. Gemini AI API Key Alın

1. [Google AI Studio](https://makersuite.google.com/app/apikey) adresine gidin
2. Google hesabınızla giriş yapın
3. "Create API Key" butonuna tıklayın
4. API key'inizi kopyalayın

### 2. Environment Variable Ayarlayın

Extension'ı çalıştırmadan önce Gemini API key'inizi ayarlayın:

```bash
export GEMINI_API_KEY="your_actual_api_key_here"
```

### 3. Extension'ı Çalıştırın

```bash
npm run build
```

## Özellikler

### 🤖 Gemini AI Analizi

- **Gerçek Source Code Analizi**: Contract kaynak kodları Gemini AI'ya gönderilir
- **Scam/Rugpull Tespiti**: AI tarafından detaylı güvenlik analizi
- **Kısa ve Öz Sonuçlar**: JSON formatında yapılandırılmış analiz
- **Fallback Sistemi**: API erişilemezse yerel analiz kullanılır

### 📊 Analiz Kapsamı

Gemini AI şu konularda analiz yapar:

- Scam/rugpull göstergeleri
- Güvenlik açıkları
- Merkezi kontrol mekanizmaları
- Backdoor fonksiyonları
- Fee/tax mekanizmaları
- Erişim kontrolü sorunları
- Reentrancy açıkları
- Mint/burn yetenekleri

### 🎯 Risk Seviyeleri

- 🟢 **LOW** - Güvenli
- 🟡 **MEDIUM** - Dikkatli ol
- 🔴 **HIGH** - Yüksek risk
- ⚫ **CRITICAL** - Kritik risk

## API Limitleri

- **Token Limiti**: 10,000 karakter (uzun kodlar kısaltılır)
- **Rate Limiting**: Google'ın API limitlerine tabidir
- **Maliyet**: Gemini API kullanım ücretleri geçerlidir

## Sorun Giderme

### API Key Hatası

```
Gemini AI not configured - using local analysis
```

**Çözüm**: `GEMINI_API_KEY` environment variable'ını ayarlayın

### Network Hatası

```
Gemini AI unavailable, using local analysis
```

**Çözüm**: İnternet bağlantınızı kontrol edin

### JSON Parse Hatası

```
AI analysis completed but results could not be parsed
```

**Çözüm**: Gemini AI response'u beklenen formatta değil, fallback analiz kullanılır

## Geliştirme

### Test Etmek İçin

1. Gemini API key'inizi ayarlayın
2. Extension'ı build edin
3. Bir web sitesinde transaction yapmaya çalışın
4. Console'da Gemini AI response'larını kontrol edin

### Debug

Console'da şu log'ları görebilirsiniz:

- `[Rugsense/inpage] Sending source code to Gemini AI...`
- `[Rugsense/inpage] Gemini API response:`
- `[Rugsense/inpage] Parsed Gemini analysis:`

## Güvenlik

- API key'inizi güvenli tutun
- Production'da environment variable kullanın
- API key'inizi public repository'lerde paylaşmayın
