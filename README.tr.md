<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.png">
    <img src="docs/assets/logo-light.png" alt="Security Monitor logosu: bir gözün iki yanında dışa bakan iki kuzgun başı" width="220">
  </picture>
</p>

<h1 align="center">Security Monitor</h1>

<p align="center"><strong>Repoda düzelttin. Production hâlâ açık mı?</strong></p>

<p align="center">
  <a href="https://github.com/umitaltinozzz/security-monitor/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/umitaltinozzz/security-monitor/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="Lisans: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <img alt="Platformlar: Windows, macOS, Linux" src="https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey">
  <a href="https://umitaltinozzz.github.io/security-monitor/"><img alt="Belgeler" src="https://img.shields.io/badge/docs-site-informational"></a>
</p>

<p align="center"><a href="README.md">English</a></p>

<p align="center">
  <img src="docs/assets/demo.gif" alt="Demo: proje ekleyip yerel hızlı tarama, bir bulgunun neden önemli olduğu ve host key doğrulandıktan sonra production sunucusu eşleştirme" width="900">
  <br><sub>Demo, masaüstü arayüzünden örnek veriyle kaydedildi (lodash 4.17.20, GHSA-35jh-r3h4-6jhm); gerçek bir tarama veya sunucu değildir.</sub>
</p>

Security Monitor (`secmon`), projelerin ve Linux sunucuların için açık kaynaklı, yerel öncelikli bir güvenlik izleme aracıdır. Bağımlılıklarını güvenlik duyurularıyla kendi bilgisayarında eşleştirir, sonra production'da gerçekte neyin çalıştığına bakar. Böylece deploy edilmemiş bir düzeltme bitmiş gibi görünmez.

Hesap yok. Bulut paneli yok. Kaynak kod, lockfile'lar ve envanter, sen belirli bir aktarımı onaylamadıkça cihazından çıkmaz.

> **Durum: yayın öncesi.** v1.0'ın kodu tamamlandı; imzalı kurulum paketleri henüz yayımlanmadı. Denemek için kaynaktan derleyin. Eksik, eski veya doğrulanmamış veri her zaman *doğrulanamadı* olarak gösterilir, asla güvenli olarak değil.

## Ne yapar

- **Açıklı bağımlılıkları yerelde bulur.** Lockfile envanteri, çevrimdışı OSV verisi, GHSA, CISA KEV ve EPSS; ayrıca OSV-Scanner, Trivy ve Semgrep adaptörleri.
- **Repoyu production ile karşılaştırır.** Salt okunur Linux ajanı (veya ajansız SSH) neyin kurulu olduğunu ve çalıştığını bildirir; yeniden başlatma bekleyen kernel'ler ve silinmiş kütüphaneleri hâlâ kullanan süreçler dahil.
- **Açıklı kod push edilmeden önce uyarır.** `secmon hook` yalnızca değişen lockfile'lara, çevrimdışı ve üç saniyenin altında bakar.
- **Kodlama ajanınla çalışır.** Tek komut Claude Code, Codex veya OpenCode'u yerel MCP sunucusuna ve Security Monitor skill'lerine bağlar.
- **Senin onayladığın düzeltmeleri hazırlar.** Düzeltmeler izole bir Git worktree'de hazırlanır ve ağı kapalı bir sandbox'ta test edilir; onayın olmadan hiçbir şey uygulanmaz.

## Neden farklı

| | Security Monitor | Tipik SaaS tarayıcılar | Repo tarayıcıları (Dependabot, OSV-Scanner, Trivy) |
| --- | --- | --- | --- |
| Hesap gerekir mi | Hayır | Evet | Değişir |
| Kaynak kod cihazdan çıkar mı | Yalnızca açık onayla | Genellikle | Hayır |
| Sunucunda çalışanı görür mü | Evet, salt okunur | Bazıları, bulut ajanlarıyla | Hayır |
| "Repoda düzeldi, production'da hâlâ çalışıyor" | Evet | Nadiren | Hayır |
| Eksik veriyi güvenli gösterir mi | Asla | Değişir | Değişir |
| Maliyet | Ücretsiz, Apache-2.0 | Ücretli planlar | Ücretsiz |

Security Monitor; OSV-Scanner, Trivy ve Semgrep'i yerel adaptör olarak kullanır. Onların yerine geçmez, üzerine kurulur.

## Nasıl çalışır

```mermaid
flowchart LR
  Repo[Yerel projeler ve lockfile'lar] --> Local[Yerel envanter ve eşleştirme]
  Host[SSH ile onaylı, salt okunur Linux envanteri] --> Local
  Feeds[Güvenlik duyurusu ve RSS/Atom akışları] --> Local
  Local --> Store[(Yerel SQLite veritabanı)]
  Store --> Desktop[Masaüstü uygulaması ve tepsi]
  Store --> CLI[secmon CLI ve Git hook'ları]
  Store --> MCP[Yerel MCP araçları]
  MCP --> AI[Seçtiğin isteğe bağlı AI sağlayıcısı]
```

Ajanda uzaktan komut çalıştırma özelliği yoktur: yalnızca derleme zamanında sabitlenmiş, salt okunur toplayıcıları çalıştırır ve root yetkisi istemez.

## Gizlilik: cihazından ne çıkar

| Veri | Cihazdan çıkar mı? |
| --- | --- |
| Kaynak kod, lockfile'lar, proje envanteri | Hayır; belirli bir AI isteğini veya dışa aktarımı onaylamadıkça |
| Sunucu envanteri | Her toplamayı onayladıktan sonra, sabitlenmiş SSH bağlantısıyla sunucundan cihazına gelir |
| Duyuru ve akış güncellemeleri | Yalnızca genel indirmeler açıksa; OSV isteği paketlerini değil, ekosistemi belirtir |
| AI istekleri | Yalnızca redakte edilmiş istemi, hedefi, araçları ve maliyet sınırını inceledikten sonra; bütçeler varsayılan olarak sıfırdır |
| Sırlar (SSH anahtarları, API anahtarları, webhook'lar) | Yalnızca işletim sisteminin kimlik deposunda |
| Telemetri | Yok |

Ayrıntılar için [Gizlilik](docs/privacy.md).

## Hızlı başlangıç (kaynaktan)

Rust, Node.js 22 veya üzeri, pnpm 10.27.0 ve [Tauri önkoşullarını](https://v2.tauri.app/start/prerequisites/) kurun.

```text
pnpm install --frozen-lockfile
pnpm -C apps/desktop tauri dev
```

CLI:

```text
cargo run -p secmon -- scan <proje-yolu> --offline
cargo run -p secmon -- report --format sarif
cargo run -p secmon -- hook install --pre-push --mode warn
cargo run -p secmon -- integrate claude-code --dry-run
```

Linux ajanı: statik binary'yi derleyin, checksum'ını doğrulayın ve verilen betikle kurun. Eşleştirmeden önce SSH host-key parmak izini bağımsız olarak doğrulayın. Bkz. [Linux ajan kurulumu](docs/agent-install.md).

## Kodlama ajanlarıyla

```text
secmon integrate <claude-code|codex|opencode> --dry-run
secmon integrate <claude-code|codex|opencode>
secmon integrate remove <claude-code|codex|opencode>
```

Bu komut yerel MCP sunucusunu, Security Monitor skill'lerini ve destekleniyorsa ajan push etmeden önce `secmon hook run` çalıştıran bir hook ekler. `--dry-run` tam diff'i gösterir, `remove` önceki dosyaları geri yükler. Ajanlar bulguları okuyup not bırakabilir; bir bulgunun durumunu veya önceliğini değiştiremez. Bkz. [Kodlama ajanı entegrasyonları](docs/integrations.md).

## Ekran görüntüleri

<p align="center">
  <img src="docs/screenshots/review-dark.png" alt="Koyu temada inceleme ekranı" width="820">
</p>

<details>
<summary>Diğer ekranlar (açık ve koyu)</summary>

| Ekran | Açık | Koyu |
| --- | --- | --- |
| Bulgular | ![Açık temada bulgular](docs/screenshots/findings-light.png) | ![Koyu temada bulgular](docs/screenshots/findings-dark.png) |
| Projeler | ![Açık temada projeler](docs/screenshots/projects-light.png) | ![Koyu temada projeler](docs/screenshots/projects-dark.png) |
| Sunucular | ![Açık temada sunucular](docs/screenshots/servers-light.png) | ![Koyu temada sunucular](docs/screenshots/servers-dark.png) |
| Geçmiş | ![Açık temada geçmiş](docs/screenshots/history-light.png) | ![Koyu temada geçmiş](docs/screenshots/history-dark.png) |
| Ayarlar | ![Açık temada ayarlar](docs/screenshots/settings-light.png) | ![Koyu temada ayarlar](docs/screenshots/settings-dark.png) |

</details>

Ekran görüntüleri gerçek bir taramadan veya sunucudan değil, deterministik test fixture'ından alınmıştır.

## Belgeler

Tüm belgeler: **[umitaltinozzz.github.io/security-monitor](https://umitaltinozzz.github.io/security-monitor/)**

- Kullanım: [CLI](docs/cli.md) · [Linux ajan kurulumu](docs/agent-install.md) · [Kodlama ajanı entegrasyonları](docs/integrations.md) · [AI sağlayıcıları](docs/ai-providers.md) · [Yerel MCP](docs/local-mcp.md) · [Paylaşılan yerel hafıza](docs/shared-memory.md)
- Nasıl çalışır: [Mimari](docs/architecture.md) · [Tarayıcı adaptörleri](docs/scanners.md) · [Bulgu korelasyonu](docs/correlation.md) · [Repo-production drift](docs/drift.md) · [Deploy ID](docs/deploy-id.md) · [Tarama orkestrasyonu ve bildirimler](docs/orchestration.md)
- Güven: [Gizlilik](docs/privacy.md) · [Tehdit modeli](docs/threat-model.md) · [Veri kaynakları](docs/data-sources.md) · [İmzalı sürümler ve güncellemeler](docs/release.md) · [Performans bütçeleri](docs/performance.md)

## Katkı ve güvenlik

Değişiklik yapmadan önce [CONTRIBUTING.md](CONTRIBUTING.md) dosyasını okuyun. Hata, özellik isteği ve yanlış pozitif bildirimleri için issue formlarını kullanın. Güvenlik açıklarını herkese açık issue olarak değil, [SECURITY.md](SECURITY.md) belgesindeki özel yöntemle bildirin.

## Lisans, veri ve sorumluluk reddi

Kaynak kod [Apache-2.0](LICENSE) lisanslıdır. Güvenlik açığı ve duyuru verileri kendi kaynak lisanslarını korur; bkz. [Veri kaynakları](docs/data-sources.md). cve.now özetleri [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) kapsamında [cve.now](https://cve.now/) kaynağına atfedilir. This product uses data from the NVD API but is not endorsed or certified by the NVD.

Eksik bulgu, yazılımın veya ortamın güvenli olduğunun kanıtı değildir. Güvenlik kararı vermeden önce sonuçları özgün duyurular ve kendi ortamınızla doğrulayın.
