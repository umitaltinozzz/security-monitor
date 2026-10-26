# Yol haritası

Security Monitor 0.1 temel sürüm. Bu sayfa ürünün 1.0'a nasıl büyüyeceğini ve sonrasında nereye gidebileceğini anlatıyor.

0.1'den sonraki her şey **planlanan özelliklerdir, henüz yayınlanmadı**. Sıra ve kapsam kullanıcı geri bildirimine göre değişir. Buradaki bir madde senin için önemliyse [özellik isteği](https://github.com/umitaltinozzz/security-monitor/issues/new/choose) aç ya da [tartışma](https://github.com/umitaltinozzz/security-monitor/discussions) başlat. Bugün neyin çalıştığı için [Özellik durumu](feature-status.md) sayfasına bak.

## Değişmeyen ilkeler

Her sürüm aynı kurallara uyar:

- **Yerel öncelikli.** Hesap yok, bulut paneli yok. Kaynak kod, lockfile ve envanter, belirli bir aktarımı onaylamadıkça cihazında kalır.
- **Varsayılan salt okunur.** Sunucu ajanında uzaktan komut çalıştırma özelliği yoktur; kontrolleri derleme zamanında belirlenmiş bir izin listesinden gelir. Bağlantılar önce yalnızca okuma yetkisi ister; her yazma işlemi ayrı ve kayıtlı bir onaydır.
- **Varsayılan olarak asla yeşil yok.** Eksik, eskimiş veya doğrulanamayan veri "doğrulanamadı" olarak gösterilir, asla güvenli diye değil. "Belirti bulunamadı" sonucu her zaman neyin kontrol edildiğini ve neyin edilemediğini listeler.
- **Yalnızca kendi varlıkların.** Aktif kontroller yalnızca sahipliği doğrulanmış varlıklara yapılır.
- **AI önerir, sen karar verirsin.** AI açıklayabilir ve öneri sunabilir; ama öncelik puanını değiştiremez, bir bulguyu "erişilemez", "yanlış pozitif" veya "kabul edilmiş risk" olarak işaretleyemez.
- **Gizli bilgiler işletim sisteminin kimlik deposunda kalır.** Veritabanına, loglara veya hata mesajlarına asla girmez.

## Kısaca

| Sürüm | Tema | Hedef |
| --- | --- | --- |
| **0.1** (şimdi) | Temel | Projelerdeki ve Linux sunuculardaki bilinen açıkları bulmak ve bir düzeltmenin gerçekten production'a ulaşıp ulaşmadığını göstermek |
| **0.2** | Boşlukları kapat | Yeni bir dış hesap bağlamadan her bulgu için "ne yapmalıyım?" sorusunu cevaplamak |
| **0.3** | Bağlantılar ve hizmetler | Zaten kullandığın servisleri kanıt kaynağı ve düzeltme kanalı yapmak; güvendiğin bir hizmet hacklendiğinde haberdar olmak |
| **0.4** | Önle ve saldırı yüzeyi | Açıklı kodun kod tabanına girmesini engellemek ve dışarıdan görünen her şeyi bilmek |
| **0.5** | Fark et ve müdahale et | Bir açık uzun süre açık kaldıysa "biri girdi mi?" sorusuna cevap aramak |
| **0.6** | Platformlar | Linux sunucuların ötesindeki varlıkları kapsamak |
| **0.7** | Ekip ve uyumluluk | Ekip olarak çalışmak ve toplanan kanıtı denetim malzemesine dönüştürmek |
| **1.0** | Derin analiz | Erişilebilirlik analizi, tedarik zinciri kanıtı ve açıklanabilir güvenlik durumu |

## 0.1 — Temel (şimdi)

- Bağımlılık envanterinin güvenlik duyurularıyla (OSV, GitHub Advisory Database, NVD, CISA KEV, EPSS) yerelde eşleştirilmesi; deterministik ve gerekçeli önceliklendirme.
- Olgun açık kaynak tarayıcılar için adaptörler.
- Zorunlu komut (forced command) ve sabitlenmiş host anahtarıyla SSH üzerinden toplanan salt okunur Linux ajanı; daemon yok, açık port yok.
- Repo ile production arasındaki fark (drift): repoda yapılan düzeltme, sunucu çalıştığını kanıtlayana kadar bitmiş gösterilmez.
- Masaüstü uygulaması (Windows, macOS, Linux), CLI, JSON/SARIF/CycloneDX/OpenVEX raporları, Git hook'ları.
- Kodlama ajanı entegrasyonları, yerel MCP sunucusu ve onaya bağlı AI katmanı.
- Masaüstü, webhook, Slack, Discord ve e-posta bildirimleri.

## 0.2 — Boşlukları kapat

**Hedef:** Her bulgu net bir sonraki adımla gelsin ve bu sürümdeki hiçbir özellik yeni bir dış hesap gerektirmesin.

### Destek bitişi (EoL) ve runtime güncelliği

"Bilinen açık yok" ile "güvende" aynı şey değil: desteği bitmiş yazılıma güvenlik yaması gelmez.

- Yaşam döngüsü verisi endoflife.date'ten alınır, yerelde önbelleğe yazılır ve günlük yenilenir.
- Sunucudaki kaynaklar: işletim sistemi sürümü, runtime'lar (Node.js, Python, PHP, Java, Ruby, Go) ve servisler (nginx, PostgreSQL, MySQL, Redis).
- Projedeki kaynaklar: `engines`, `.nvmrc`, `.python-version`, `requires-python`, Composer ve Go sürümleri, Dockerfile `FROM` satırları, CI matrisleri.
- Bulgu türleri: desteği bitmiş, desteği 90/30 gün içinde bitecek ve aynı ana sürümün son güvenlik sürümünün gerisinde.
- Sürüm okunamıyor veya eşleştirilemiyorsa sonuç sessizce atlanmaz, "doğrulanamadı" olur.
- Rehberli yükseltme skill'i bir sonraki LTS sürümünü önerir, bağımlılık uyumluluğunu kontrol eder ve testleri sandbox'ta çalıştırır.

### Risk sahipliği: SLA, sorumlu, istisna, metrikler

- Makul varsayılanlarla SLA politikası (kritik 3, yüksek 14, orta 45, düşük 90 gün); aktif olarak istismar edilen ve internete açık production bulguları için daha sıkı hedef; proje bazında değiştirilebilir.
- Her bulgu için bir sorumlu; proje bazında varsayılan sorumlu.
- Kabul edilmiş risk istisnası onaylayan, gerekçe ve **bitiş tarihi** ister (en fazla 365 gün); süresi dolan istisna otomatik olarak yeniden açılır.
- Metrikler: önem derecesine ve projeye göre düzeltme süresi, SLA uyumu, açık bulgu eğilimi, deploy gecikmesi (repoda düzeldi → production'da çalışıyor), en çok bulgu üreten bağımlılıklar, en eski açık bulgular. CSV/JSON olarak dışa aktarılabilir.

### Sunucu yapılandırma denetimi (CIS-lite)

Yeni salt okunur ajan toplayıcılarıyla toplanan ve imzalı kural paketleriyle dağıtılan yaklaşık 40 başlangıç kuralı:

- **SSH:** root ve parola girişi, eski anahtar değişim ve şifreleme algoritmaları, `MaxAuthTries`, X11 yönlendirme, `AllowUsers`.
- **Ağ:** dinleyen portlar ve süreçleri, tüm arayüzlerde dinleyen veritabanı veya önbellekler, firewall durumu.
- **Güncellemeler:** otomatik güvenlik güncellemeleri açık mı, bekleyen güvenlik güncellemeleri.
- **Web sunucuları:** TLS protokolleri, sürüm sızıntısı, dizin listeleme, güvenlik başlıkları, erişilebilir `.git`/`.env`.
- **Hesaplar ve dosyalar:** parolasız sudo, ek UID 0 hesapları, herkesin yazabildiği web kökleri, web kökündeki yedek dosyalar.
- **Docker:** root çalışan container'lar, privileged mod, host ağı, Docker socket bağlama, `latest` etiketleri.

Ajan hiçbir zaman düzeltme uygulamaz. Uygulama önerilen değişikliği, kural seni sunucudan kilitleyebilecekse bir uyarıyı ve geri alma adımını gösterir. Sunucuda Lynis zaten kuruluysa raporu ek kaynak olarak okunabilir.

### CI/CD ve repo kontrolleri (yerel dosyalar)

- **GitHub Actions:** commit SHA'sına sabitlenmemiş action'lar, geniş varsayılan izinler, checkout ile birlikte `pull_request_target`, `run:` içinde doğrudan kullanılan güvenilmez `github.event` ifadeleri, `secrets: inherit`, public repolarda self-hosted runner.
- **GitLab CI:** `latest` imajlar, korumasız değişkenler, başarısız olmasına izin verilen güvenlik işleri.
- **Dockerfile:** `latest`, root olarak çalışma, uzak URL'den `ADD`, `ENV`/`ARG` ile imaja giren gizli bilgiler.

### Rehberli düzeltme skill'leri

İlk altı düzeltme skill'i en yaygın zayıflık sınıflarını kapsar: SQL injection, cross-site scripting, komut enjeksiyonu, path traversal, koddaki gizli bilgiler (rotasyon kontrol listesiyle birlikte) ve zayıf kriptografi. Her skill kalıbın neden tehlikeli olduğunu açıklar, dil ve framework'e göre güvenli kalıbı gösterir, sık yapılan **yanlış** düzeltmeleri listeler, bir regresyon testi ekler ve bulgunun kapandığını doğrulamak için tarayıcıyı yeniden çalıştırır. Her değişiklik mevcut worktree → sandbox testi → senin onayın akışından geçer.

### Yeni ekosistemler ve CI entegrasyonları

- Java (Maven, Gradle), .NET ve Ruby lockfile'ları.
- Önbelleğe alınmış güvenlik duyurusu veritabanıyla çevrimdışı çalışan ve SARIF yükleyen resmî bir GitHub Action ve GitLab CI şablonu.

### Self-hosted PaaS için ajansız drift

Bağımsız geliştiricilerin çoğu zaten hangi commit'in ve imajın nerede çalıştığını bilen bir self-hosted platformla deploy ediyor. **Dokploy, Coolify, Openship, CapRover, Dokku ve Kamal** için salt okunur bağlantılar, ajan kurmadan deploy kanıtı sağlar:

- Uygulamalar, ortamlar, son başarılı deploy (commit, branch, imaj digest'i), çalışan imajlar, domain'ler ve TLS durumu, ortam değişkeni **adları** (değerleri asla).
- Yalnızca izin listesindeki okuma uçları çağrılabilir; deploy, yeniden başlatma ve silme uçları kodda hiç yoktur.
- Platform verisi karar değil kanıttır: production ancak deploy edilen commit düzeltmeyi içeriyorsa **ve** çalışan imaj o commit'ten üretildiyse düzeltilmiş gösterilir.

## 0.3 — Bağlantılar ve hizmetler

**Hedef:** Zaten kullandığın servisleri kanıt kaynağına ve düzeltme kanalına dönüştürmek; biri hacklendiğinde seni uyarmak.

- **Bağlantı çerçevesi:** Her bağlantı adresini, kimlik doğrulama yöntemini ve ayrı okuma/yazma yetkilerini tanımlar. Token'lar yalnızca işletim sisteminin kimlik deposunda tutulur; her çalıştırma tazeliği kaydeder, eskiyen kanıt hesaba katılmaz.
- **Telafi edici kontroller:** Bir WAF kuralı, kapatılmış bir firewall portu veya devre dışı bir özellik, kanıtı ve yaşı gerekçede gösterilerek bulgunun önceliğini düşürebilir. Kullanıcının beyan ettiği kontroller "doğrulanmadı" etiketi taşır. Bulgu kapanmaz, *hafifletildi* olur.
- **GitHub:** Çapraz kontrol için Dependabot ve secret scanning uyarıları, branch koruması, zorunlu review, Actions ayarları; issue ve pull request yalnızca onayla.
- **Cloudflare:** Origin IP'sini açığa çıkaran proxy'siz kayıtlar, boşta kalan kayıtlar (subdomain devralma riski), zayıf TLS ayarları ve bir CVE için yönetilen WAF kuralı olup olmadığı. **Sanal yama:** Önerilen özel WAF kuralı önce log modunda başlar, 24 saat sonra eşleşen istekleri gösterir ve yalnızca onayınla engelleme moduna geçer. Kod düzeltilip deploy edilince uygulama kuralı kaldırmanı hatırlatır.
- **Bulut ve hosting firewall'ları:** Hetzner Cloud, DigitalOcean, AWS security group ve GCP firewall; ajan verisiyle birleştirilir ("dinliyor ve dışarıya açık", "dinliyor ama engelli", "kullanılmayan kural").
- **Ek deploy kanıtı:** Vercel, Netlify, Render, Railway ve Fly; açıklı kodun gerçekten çalıştığına dair ek sinyal olarak Sentry trace'leri.
- **Issue takip sistemleri:** GitHub Issues, GitLab, Jira ve Linear. İçerik gönderilmeden önce önizlenir ve redakte edilir, kod varsayılan olarak eklenmez; issue kapanınca bulgu "doğrulama bekliyor" durumuna geçer.
- **Üçüncü taraf hizmet envanteri ve olay takibi:** Her projenin güvendiği hizmetleri SDK paketlerinden, ortam değişkeni adlarından, deploy yapılandırmasından ve DNS'ten çıkarır; değerler asla okunmaz. Bir hizmet güvenlik olayı duyurduğunda hangi projelerin ve hangi anahtarların etkilendiğini öğrenirsin, bir rotasyon kontrol listesi alırsın ve her anahtarı yenilenene kadar takip edebilirsin. Resmî duyurular olay sayılır; haberler doğrulanana kadar doğrulanmamış sinyal olarak kalır.
- **Altı düzeltme skill'i daha:** SSRF, güvensiz deserialization, kimlik doğrulama ve oturum sorunları, kırık erişim kontrolü, açık yönlendirme ve güvensiz dosya yükleme. Dart, Swift ve Elixir lockfile'ları.
- **Bağımlılık güncelleme asistanı:** En küçük güvenli sürüm, sürüm notlarından kırılma değişiklikleri, kodunda etkilenen yerler, ana sürüm yükseltmeleri için adım adım plan ve sandbox'ta test.

## 0.4 — Önle ve saldırı yüzeyi

**Hedef:** Açıklı kod kod tabanına girmesin ve dışarıdan görünen her şey bilinsin.

- **Sahiplik doğrulama:** Bağlı DNS veya bulut hesapları, ajanın doğruladığı sunucu IP'leri ya da DNS TXT kaydı. Sahiplik düşerse aktif kontroller hemen durur.
- **Varlık keşfi:** Sahip olduğun ama eklemediğin varlıkları bulut ve DNS hesaplarından, yerel SSH, Docker ve Kubernetes bağlamlarından ve doğrulanmış alan adları için Certificate Transparency kayıtlarından bulur. Envanter karşılaştırması izlenenleri, bulunup izlenmeyenleri ve kaybolanları gösterir.
- **Dış saldırı yüzeyi (yalnızca kendi varlıkların):** Varsayılan olarak pasif kontroller (DNS, CT subdomain'leri, boşta kalan kayıtlar, SPF/DKIM/DMARC, CAA). Hafif aktif kontroller yalnızca açık onay ve doğrulanmış sahiplikle: TLS süresi ve yapılandırması, güvenlik başlıkları ve sürüm sızıntıları, düşük hızda basit GET istekleriyle kısa ve sabit bir hassas yol listesi ve küçük bir port özeti. Dışarıdan görünüp envanterde olmayan servisler raporlanır.
- **Tehdit istihbaratı zenginleştirme:** Bir CVE'nin şu anda toplu olarak istismar edildiğine dair sinyaller ve yerelde önbelleğe alınmış açık engelleme listeleri. Yalnızca CVE kimlikleri sorgulanır; verini dışarı gönderecek IP sorguları isteğe bağlıdır ve varsayılan olarak kapalıdır. Sinyaller öncelik gerekçesinde görünür; AI puanı değiştiremez.
- **Pull request güvenlik incelemesi:** Yalnızca değişen satırlar; statik analiz, bağımlılık farkı ve onaya bağlı AI incelemesi birlikte. Engelleme kararı yalnızca deterministik kurallardan gelir.
- **Zararlı paket tespiti:** Bilinen zararlı paket kayıtları, typosquatting, ağ erişimi veya gizleme içeren kurulum betikleri, ani bakımcı değişiklikleri. Varsayılan olarak yalnızca yerel sinyaller kullanılır; registry meta veri sorguları isteğe bağlıdır.
- **Bağımlılık politikası:** Yasaklı lisanslar, minimum paket yaşı, kurulum betiği olan yeni paketler için onay, izinli registry'ler; Git hook'larında ve CI'da uygulanır.
- **Güvenli varsayılanlar:** Next.js, Express, FastAPI ve Laravel için skill'ler (güvenlik başlıkları, CSP, hız sınırı, cookie ayarları) ve üretilmiş yetkilendirme ve girdi doğrulama testleri.

## 0.5 — Fark et ve müdahale et

**Hedef:** Bir açık production'da uzun süre açık kaldıysa "biri girdi mi?" sorusuna cevap aramak. Bu bir SIEM veya EDR değildir; "görülmedi" asla "olmadı" anlamına gelmez ve bu her ekranda yazar.

- **Açığa özel ele geçirilme kontrolleri:** Production'da hâlâ açık olan ve aktif olarak istismar edilen CVE'ler için: izin verilen log yollarında yayımlanmış göstergeler, web kökünde açığın duyurulmasından sonra oluşmuş şüpheli dosyalar, beklenmeyen cron girdileri, yeni SSH anahtarları, kullanıcılar veya systemd birimleri. Kurallar lisansı uyumlu topluluk Sigma ve YARA setlerinden gelir ve imzalı paketlerle dağıtılır. Sonuçlar "Belirti bulunamadı (şu 6 kontrol yapıldı, şu 2'si yapılamadı)" veya "İncelenmeli: bu dosya açığın duyurulmasından 3 gün sonra oluşmuş" biçimindedir; asla "temiz" değil.
- **Hafif dosya bütünlüğü izleme:** Senin seçtiğin dizinler için (web kökü, `/etc/ssh`, cron, sudoers, systemd). Taban çizgisi onayınla alınır; bilinen bir deploy'la eşleşen değişiklikler beklenen olarak kabul edilebilir. Mevcut AIDE veya Wazuh raporları da okunabilir.
- **Yerel olay özetleri:** Ajan journald, kimlik doğrulama logları ve web sunucusu loglarını sayılara ve redakte edilmiş örneklere dönüştürür; ham loglar sunucudan asla çıkmaz. Kaba kuvvet denemeleri, ilk kez görülen başarılı girişler, alışılmadık saatlerde root etkinliği, açık CVE'lerle eşleşen istekler ("denendi" ile "başarılı olmuş olabilir" ayrı tutularak) ve yeni port veya servis gibi ani değişiklikleri kapsar.
- **Canary token'lar:** `.env` dosyalarına, repolara ve sunuculara sahte anahtarlar yerleştirmek için rehber, nereye konduklarının envanteri ve bulgulara bağlanan uyarılar. canarytokens.org veya kendi OpenCanary kurulumun kullanılır; Security Monitor kendi tetikleme sunucusunu çalıştırmaz.
- **Müdahale rehberleri:** Web shell, sızdırılmış gizli bilgi, ele geçirilmiş bağımlılık, sızdırılmış SSH anahtarı ve üçüncü taraf ihlali için adım adım kontrol listeleri; kanıt koruma notları, ne zaman profesyonel destek alınacağı ve veri ihlali bildirim hatırlatmaları (hukuki tavsiye değildir). MITRE ATT&CK ve D3FEND ile eşlenmiştir.
- **Gizli bilgi envanteri ve rotasyon takibi:** Hangi tür gizli bilginin nerede olduğu (değerler asla), son rotasyon tarihleri, yaş politikaları ve sızıntı şüphesinde tek tıkla "bunları yenile" listesi.

## 0.6 — Platformlar

**Hedef:** Linux sunucuların ötesindeki varlıkları kapsamak. Bu sürüm daha küçük adımlarla çıkabilir.

- **Windows Server ve macOS ajanları:** Windows'ta kurulu yazılımlar, servisler, IIS siteleri, .NET runtime'ları, bekleyen güncellemeler ve Defender durumu; macOS'ta Homebrew, uygulamalar ve bekleyen güncellemeler. Aynı kurallar geçerli: derleme zamanı izin listesi, genel komut çalıştırma yok, shell yok.
- **Self-hosted relay ile push tabanlı ajan:** NAT arkasındaki veya SSH'ı olmayan sunucular için. Relay senin sunucunda çalışır ve uçtan uca şifrelidir; masaüstü yalnızca "topla" sinyali gönderebilir, asla komut gönderemez. Kendi tehdit modeli ve bağımsız denetimiyle gelir.
- **Kubernetes ve container registry'leri:** Çalışan imaj digest'lerinin workload'larla ve repolarla eşleştirilmesi (Kubernetes için drift); GHCR, Docker Hub ve GitLab Registry imajlarının yerelde taranması.
- **Hosting panelleri ve CMS'ler:** Salt okunur cPanel ve Plesk envanteri; WordPress ve Joomla eklenti ve tema envanteri.
- **Ağ cihazları ve appliance'lar:** Ajan kurulamayan firewall ve VPN ağ geçitleri elle, salt okunur üretici API'leriyle (FortiGate, PAN-OS, MikroTik, SonicOS, Cisco RESTCONF), SNMPv3 ile veya dış yüzeyden keşfedilerek envantere eklenir. Üretici PSIRT akışları, CISA KEV ve NVD ile eşleştirilir; aktif olarak istismar edilen sürümlerde internete açık yönetim arayüzleri en üste çıkar ve geçici önlem olarak "internetten kaldır" önerilir. Firmware destek bitişi de takip edilir.
- **Geliştirici bilgisayarları (isteğe bağlı, yerel):** İşletim sistemi ve tarayıcı sürümleri, IDE eklentileri (zararlı, ele geçirilmiş, typosquat veya aşırı yetkili), global geliştirici araçları, firmware ve parolasız ya da eski algoritmalı SSH anahtarları (anahtar içerikleri asla okunmaz).
- **Ek Linux dağıtımları:** SUSE, Arch, Amazon Linux ve Wolfi.

## 0.7 — Ekip ve uyumluluk

**Hedef:** Ekip olarak çalışmak ve zaten topladığın kanıtı denetim malzemesine dönüştürmek. Bireysel kullanım ücretsiz ve hesapsız kalır.

- **Self-hosted ekip paneli** (tek binary veya Docker, PostgreSQL). Masaüstü uygulamaları yalnızca kararları ve meta veriyi senkronize eder; kaynak kod ve ham envanter varsayılan olarak senkronize edilmez. Görüntüleyici, onaylayıcı ve yönetici rolleri, onay zincirleri (ör. kabul edilmiş risk için iki onay), OIDC ile tek oturum açma ve denetim kaydı dışa aktarımı.
- **Uyumluluk kanıt raporları:** Zafiyet yönetimi, SLA uyumu, yama geçmişi, yapılandırma denetimleri ve onay kayıtları ISO 27001, SOC 2, PCI DSS ve KVKK kontrollerine eşlenir; PDF/HTML rapor ve CSV kanıt dizini olarak. Sertifika iddiası olarak değil, kanıt toplama yardımı olarak etiketlenir.
- **Blue team araçlarına dışa aktarım:** Bulgular ve SBOM'lar DefectDojo ve Dependency-Track'e, olay özetleri Wazuh ve Elastic'e, onaylı vakalar TheHive'a.

## 1.0 — Derin analiz

- **Erişilebilirlik (reachability):** Açıklı fonksiyonun gerçekten çağrılıp çağrılmadığını gösteren çağrı grafiği analizi; önce JavaScript/TypeScript ve Python. Kanıt olarak gösterilir; bir bulguyu "erişilemez" olarak yalnızca sen işaretleyebilirsin.
- **Tedarik zinciri kanıtı:** SLSA provenance ve Sigstore imza doğrulama ile "bu production imajı şu commit'ten şu pipeline ile üretildi" zinciri; drift'in kriptografik hâli.
- **Açıklanabilir güvenlik durumu:** Proje ve sunucu başına, neden düştüğünü ve neyin yükselteceğini gösteren, formülü belgelenmiş bir özet.
- **Plugin SDK:** Üçüncü taraf tarayıcılar, veri kaynakları, toplayıcılar ve skill'ler; açık ağ ve dosya izinleriyle WASM sandbox'ında çalışan imzalı eklentiler.
- **Kendi test ortamına karşı DAST:** İzinli host, yol ve hızları tanımlayan bir kapsam dosyasıyla sınırlanmış, OWASP ZAP gibi olgun bir aracın orkestrasyonu. Production için varsayılan kapalı ve sahiplik doğrulamasına bağlı. Sonuçlar statik bulgularla birleşir ("hem kodda hem çalışan uygulamada doğrulandı").
- **Bulut ve Kubernetes güvenlik durumu:** Herkese açık bucket'lar, aşırı yetkili IAM, şifrelenmemiş diskler, RBAC, pod güvenliği ve ağ politikaları için salt okunur kontroller; Prowler veya kube-bench çıktısını okuma seçeneği.

## 1.0 sonrası: küçük ekipler için mini SOC

Taahhüt değil, araştırma yönü. Amaç, küçük bir ekibe bir güvenlik operasyon merkezini işletmenin maliyeti olmadan çekirdeğini vermek:

- **Ele geçirilme değerlendirmesi:** Rehberli bir "bu sunucu ele geçirildi mi?" akışı: kim erişiyor, sunucu kiminle konuşuyor, kalıcılık, yönetim yüzeyi, dış itibar ve kendi çalıştırdığın tarayıcıların raporları. Önce Linux, sonra Windows olay logları.
- **Kimlik ve erişim olay tespiti:** Kaba kuvvet, parola püskürtme, başarısız denemelerden sonra başarılı giriş, mesai dışı girişler, yeni hesaplar, firewall veya uzak erişim portu değişiklikleri, yerel engelleme listelerindeki IP'lerden girişler. Otomatik engelleme yok; öneriler veya onayınla tek seferlik, geri alınabilir engellemeler. Denetim kayıtları kapalıysa sonuç "denetim kapalı, doğrulanamadı" olur.
- **Savunma kapsama haritası ve olgunluk kontrolü:** Her varlık için hangi savunma katmanlarının (kanıtıyla) bulunduğu ve puan yerine "sonraki üç adımın" ile biten kısa bir öz değerlendirme.
- **Kapsama ve kalite KPI'ları:** Eskimiş envanter, taranmamış projeler, kural başına yanlış pozitif oranı, hiç tetiklenmeyen kurallar ve ATT&CK kapsaması.
- **Kontrollerin çerçevelere eşlenmesi:** Her kuralın NIST CSF, ISO 27001, CIS Controls, SOC 2, PCI DSS, MITRE ATT&CK ve Türkiye'deki KVKK rehberlerine eşlenmesi.
- **OCSF çıktısı:** Splunk, Microsoft Sentinel ve AWS Security Lake gibi SIEM'ler için; her zaman önizlenir ve onaylanır.
- **Bulut ve SaaS güvenlik durumu:** En değerli 30–50 kontrol için.
- **Security Monitor'ün çalıştığı makinenin sıkılaştırılması:** Uygulama tüm sunucuların anahtarlarını tuttuğu için disk şifrelemesini, güncellemeleri, ekran kilidini ve veri dizini izinlerini kontrol eder.
- **Tespit mühendisliği yaşam döngüsü:** Her kural için pozitif ve negatif testler, yerel tetiklenme ve yanlış pozitif istatistikleri ve üç aylık gözden geçirmeler.
- **Sürekli dış yüzey izleme:** Yeni subdomain'ler, boşta kalan DNS kayıtları, devralma imzaları, sertifika değişiklikleri ve yeni açık portlar; Prowler, Kubescape ve Trivy çıktılarının içe aktarılması.
- **İsteğe bağlı ağ sensörü:** Log özetleri okunan ayrı bir Zeek veya Suricata sensörü (ham paketler sensörden asla çıkmaz); beaconing, DNS tünelleme, sahte DHCP ve gece veri çıkışı gibi tespitler. "Sensör sustu" durumu güvenli değil, kör olarak raporlanır.
- **Şüpheli dosyaların statik ön incelemesi:** Hash, dosya türü, entropi, bölümler, içe aktarılanlar, YARA eşleşmeleri ve yerel hash listeleri. Dinamik çalıştırma yok; dosyanın kendisi asla yüklenmez.
- **Laboratuvar ve öz test:** `secmon lab up` beş dakikalık uçtan uca bir demo için bilinen sorunlar içeren yerel ve izole bir ortam başlatır; `secmon selftest` saldırı kalıplarını ürünün kendi tespitlerine tekrar oynatarak neyin çalıştığını ve neyin kör olduğunu gösterir.

## Asla kapsamda olmayacaklar

| Konu | Neden |
| --- | --- |
| Sahibi olmadığın sistemleri test etmek, taramak veya istismar etmek | Ürün savunma amaçlıdır ve yalnızca kendi varlıkların içindir |
| Production'a otomatik yama, deploy veya root erişimi | Her değişiklik onaylı ve izoledir |
| Ajanda genel komut kanalı | Tek bir zayıflık tüm sunucuları açar |
| Tam EDR, XDR, SIEM veya antivirüs olduğunu iddia etmek | Hafif yerel özetler var, bu iddia yok |
| Zero-day keşif garantisi | Sinyaller ve ele geçirilme kontrolleri yardımcı olur, garanti vermez |
| Haber veya sosyal medyadan doğrudan bulgu oluşturmak | Haber sinyal olarak kalır; resmî duyuru olay olur |
| Yönetilen SaaS | Yerine self-hosted ekip paneli |
| Telemetri | Gizlilik vaadiyle çelişir |
