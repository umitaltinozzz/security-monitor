# Linux ajanı: gerçek sunucuya ilk kurulum

`secmon-agent`, salt okunur ve çekme (pull) tabanlı bir toplayıcıdır; servis (daemon) değildir. Masaüstü uygulaması SSH ile bağlanır ve tek bir envanter ister. Sunucuda gelen bağlantıya açılan yeni bir port yoktur ve ajanda genel komut çalıştırma özelliği bulunmaz. Ayrıntılı başvuru için İngilizce [agent-install.md](agent-install.md) sayfasına bakın.

Bu adımlar iki Oracle Cloud ücretsiz sunucusu için yazıldı; benzer her Linux sunucuda geçerlidir:

| Sunucu | Tip | İşletim sistemi | Varsayılan kullanıcı | Ajan dosyası |
| --- | --- | --- | --- | --- |
| A | Ampere A1, 2 OCPU / 12 GB | Oracle Linux 9 (`aarch64`) | `opc` | `secmon-agent-linux-aarch64` |
| B | AMD micro, 1 GB | Ubuntu 24.04 (`x86_64`) | `ubuntu` | `secmon-agent-linux-x86_64` |

systemd birimi yoktur, başlatılacak bir şey de yoktur: ajan yalnızca masaüstü kısıtlı eşleme anahtarıyla SSH oturumu açtığında çalışır, bir envanter yazdırır ve kapanır.

## 1. Ağ erişimi

- Sunucuya kendi SSH anahtarınızla bağlanın. Oracle imajlarında parolayla giriş kapalıdır; öyle kalsın.
- **Networking → Virtual Cloud Networks → VCN → Security Lists** bölümünde yalnızca `22/tcp` girişine izin verin; mümkünse kaynağı kendi IP'nizle sınırlayın (`x.x.x.x/32`). Tailscale kullanıyorsanız, Tailscale üzerinden SSH çalıştıktan sonra genel `22/tcp` kuralını kaldırabilir ve masaüstünü Tailscale adresiyle eşleyebilirsiniz.
- Oracle Linux `firewalld` kullanır ve SSH'a varsayılan olarak izin verir. Oracle'ın Ubuntu imajları kendi `iptables` kurallarıyla gelir (`/etc/iptables/rules.v4`); SSH'ın açık kalacağından emin olmadan bunların yerine `ufw` açmayın, sunucudan kilitlenebilirsiniz.

## 2. Ajan dosyasını alın (masaüstünüzde)

İlk sürüm çıkana kadar `main` dalının CI artifact'ini kullanın. Bu dosya `.sha256` ile bütünlük kontrolünden geçer ama minisign ile **imzalı değildir**; güven, GitHub'a kimlik doğrulamalı indirmenizden gelir. Sürümlerdeki binary'lerin ayrıca `.minisig` imzası vardır.

```sh
gh run list -R umitaltinozzz/security-monitor -w CI -b main -s success -L 1
gh run download <run-id> -R umitaltinozzz/security-monitor -n secmon-agent-linux-aarch64 -D agent-a
gh run download <run-id> -R umitaltinozzz/security-monitor -n secmon-agent-linux-x86_64 -D agent-b
```

Uygun binary'yi, `.sha256` dosyasını ve repo kökündeki `install.sh`'ı sunuculara kopyalayın:

```sh
scp agent-a/secmon-agent-linux-aarch64 agent-a/secmon-agent-linux-aarch64.sha256 install.sh opc@SUNUCU_A:
scp agent-b/secmon-agent-linux-x86_64 agent-b/secmon-agent-linux-x86_64.sha256 install.sh ubuntu@SUNUCU_B:
```

## 3. Kurulum (her sunucuda)

```sh
uname -m                     # A'da aarch64, B'de x86_64
case "$(uname -m)" in
  x86_64) agent=secmon-agent-linux-x86_64 ;;
  aarch64) agent=secmon-agent-linux-aarch64 ;;
  *) echo "desteklenmeyen mimari" >&2; exit 1 ;;
esac
sha256sum -c "$agent.sha256"
read -r agent_sha256 _ < "$agent.sha256"
chmod +x install.sh
sudo ./install.sh --binary "./$agent" --sha256 "$agent_sha256"
```

Çıktı `secmon-agent installed at /usr/local/bin/secmon-agent.` ile bitmelidir. Kurulum betiği `secmon` sistem hesabını (ev dizini `/var/lib/secmon`, kullanılabilir parolası yok), `/etc/secmon/agent.toml` dosyasını ve `/etc/secmon/deployments.d` dizinini oluşturur.

Toplama çalıştırmadan kontrol:

```sh
ls -l /usr/local/bin/secmon-agent          # sahibi root, izin 0755
getent passwd secmon                       # ev dizini /var/lib/secmon, kabuk /bin/sh
sudo cat /etc/secmon/agent.toml            # yol ekleyene kadar boş
```

## 4. İsteğe bağlı: ajanın bir uygulamayı görmesi

Bağımlılık dosyaları ve deploy kimliği yalnızca izin verdiğiniz yollarda okunur. `/srv/demo` içindeki bir demo uygulama için:

```sh
sudo tee /etc/secmon/agent.toml >/dev/null <<'EOF'
allowed_paths = ["/srv/demo"]
docker_cli_approved = false
max_processes = 4096
EOF
```

Drift karşılaştırması için uygulamaya bir deploy kimliği verin: `/srv/demo/.secmon-deploy.json` ya da `/etc/secmon/deployments.d/<servis>.json` (biçim için [deploy-id.md](deploy-id.md)). Docker erişiminin root yetkisine denk olduğunu bilerek kabul etmediyseniz `docker_cli_approved = false` olarak bırakın.

## 5. Masaüstünden eşleme

1. Masaüstüyle karşılaştırmak için sunucuda host-key parmak izlerini yazdırın:

   ```sh
   for key in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$key"; done
   ```

2. Masaüstünde **Sunucular → Linux sunucusu eşleştir** ekranını açın. Takma ad, hostname veya IP (ya da Tailscale adresi), SSH kullanıcı adı `secmon`, port `22` ve ortamı girin.
3. Gösterilen SHA-256 parmak izini 1. adımdaki satırla karşılaştırın. Yalnızca birebir aynıysa onay kutusunu işaretleyin. Farklıysa durun.
4. Masaüstünün gösterdiği kısıtlı `authorized_keys` satırını kopyalayıp sunucuya kurun:

   ```sh
   sudo install -d -o secmon -g secmon -m 0700 /var/lib/secmon/.ssh
   sudo tee /var/lib/secmon/.ssh/authorized_keys >/dev/null <<'EOF'
   MASAÜSTÜNDEKİ SATIRI BURAYA YAPIŞTIRIN
   EOF
   sudo chown secmon:secmon /var/lib/secmon/.ssh/authorized_keys
   sudo chmod 0600 /var/lib/secmon/.ssh/authorized_keys
   ```

5. **Oracle Linux ve SELinux'u zorlayan (enforcing) diğer sistemler:** OpenSSH, `/var/lib` altındaki anahtarları SSH etiketi olmadan okumayabilir:

   ```sh
   getenforce
   sudo semanage fcontext -a -t ssh_home_t '/var/lib/secmon/\.ssh(/.*)?'
   sudo restorecon -Rv /var/lib/secmon/.ssh
   ```

   `semanage` yoksa `policycoreutils-python-utils` paketini kurun.
6. Masaüstüne dönüp tek bir envanter aktarımını onaylayın.

## 6. Doğrulama listesi

Masaüstünde gördüğünüzü her madde için not edin:

- [ ] Toplama "tamamlandı" ya da "kısmi" olarak biter; sessizce başarılı görünmez. Kısmi alanların nedeni yazar.
- [ ] **Paketler:** liste dolu. B'de (Ubuntu) işletim sistemi paketleri güncel yerel OSV verisiyle değerlendirilir. A'da (Oracle Linux) durum *"Doğrulanamadı — bu dağıtım için OSV veri kaynağı yok"* olarak görünür, "açık yok" değil.
- [ ] **Kernel:** çalışan kernel görünür; daha yeni bir kernel kuruluysa yeniden başlatma uyarısı çıkar.
- [ ] **Servisler:** `sshd` ve çalışan diğer birimler listelenir.
- [ ] **Container'lar:** `docker_cli_approved = false` iken container envanteri boş değil, "kullanılamıyor" olarak görünür.
- [ ] **Deploy kimliği:** deploy verisi olmayan servis "bilinmiyor" görünür ya da listelenmez; asla "doğrulandı" denmez.
- [ ] **Drift:** sunucuyu bir projeyle bağlayın (**Burada çalışan projeler → Proje bağla**). O proje için repo ve production durumu görünür; bağlantı yoksa production durumu doğrulanamadı olarak kalır.
- [ ] Bir paketi ya da deploy kimliğini değiştirdikten sonraki ikinci toplama değişikliği gösterir.

## 7. Sorun çıkarsa

Aşağıdaki komutların hepsi yalnızca okur.

| Belirti | Nereye bakılır |
| --- | --- |
| Masaüstü bağlanamıyor | `sudo journalctl -u sshd -n 50 --no-pager` (Oracle Linux) ya da `sudo journalctl -u ssh -n 50 --no-pager` (Ubuntu) |
| Anahtar reddediliyor | `sudo ls -laZ /var/lib/secmon/.ssh` (izinler `0700`/`0600`, sahibi `secmon`, SELinux tipi `ssh_home_t`); SELinux'ta `sudo ausearch -m avc -ts recent` |
| Host key uyuşmuyor | Yeni anahtarı kabul etmeyin. `ssh-keygen -lf` çıktısını yeniden karşılaştırın ve anahtarın neden değiştiğini bulun. |
| Yanlış mimari | `uname -m` ve `file /usr/local/bin/secmon-agent` |
| Toplama kısmi | Masaüstünde her alan için yazan nedeni okuyun; izin reddedilen alanlar tasarım gereği kısmi kalır. |
| Port kapalı | Oracle konsolundaki Security List giriş kuralları; `sudo firewall-cmd --list-all` (Oracle Linux) ya da `sudo iptables -S` (Ubuntu) |

Masaüstünün kendi logu uygulama veri dizinindeki `logs/` klasöründedir; maskelenmiştir ve özel anahtar içermez.

## Ajanı kaldırma

```sh
sudo rm -f /usr/local/bin/secmon-agent /var/lib/secmon/.ssh/authorized_keys
sudo userdel -r secmon
sudo rm -rf /etc/secmon
```

Erişimi asıl kapatan, `authorized_keys` satırını silmektir. Masaüstünde henüz sunucu eşlemesini kaldırma komutu yok; bu yüzden sabitlenmiş host key, envanter geçmişi ve işletim sistemi kimlik deposundaki özel anahtar o özellik gelene kadar cihazda kalır.
