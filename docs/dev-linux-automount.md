# Panduan Mitigasi Linux Desktop Automount untuk USB Sentinel

Dokumen ini menjelaskan risiko keamanan automount pada laptop/PC desktop pengembang dan konfigurasi untuk menonaktifkannya, serta perbandingannya dengan lingkungan produksi Raspberry Pi headless.

---

## 1. Risiko Automount pada Lingkungan Linux Desktop

Pada sistem operasi Linux desktop (seperti Parrot OS, Ubuntu, Debian Desktop, Fedora, Arch) yang menjalankan Desktop Environment (GNOME, KDE Plasma, XFCE, MATE):

1. **Auto-Mount via `udisks2` & `gvfs`:**
   Begitu USB flashdisk dicolokkan, daemon `udisks2` dan helper desktop (`gvfs-udisks2-volume-monitor`) secara otomatis me-mount partisi flashdisk ke direktori pengguna (misalnya `/media/$USER/...` atau `/run/media/$USER/...`).
2. **Eksploitasi Parsial & Metadata Parser Host:**
   Setelah mount otomatis, file manager (Nautilus, Dolphin, Thunar) sering kali memindai folder dan menjalankan thumbnailer otomatis (seperti `evince-thumbnailer`, `gstreamer`, `ffmpegthumbnailer`, parser JPEG/PNG/SVG). Jika flashdisk berisi exploit buffer overflow pada parser gambar atau PDF, host desktop dapat terkompromi **sebelum** Sentinel sempat memeriksa atau memblokir perangkat tersebut.
3. **Konflik Akses Partisi:**
   Automount desktop dapat menyebabkan locking pada device node atau me-mount partisi dalam mode read-write (`rw`), melanggar Invarian 8 (hanya boleh mount `ro,noexec,nosuid,nodev`).

---

## 2. Solusi & Mitigasi pada Mesin Desktop Pengembang

Untuk memastikan flashdisk yang dicolokkan ke mesin Sentinel tidak pernah disentuh oleh udisks desktop:

### A. Udev Rule: Abaikan Perangkat USB di `udisks2`

Tambahkan aturan udev yang menandai seluruh block device dari bus USB dengan flag `UDISKS_IGNORE=1`.

Buat file `/etc/udev/rules.d/99-sentinel-udisks-ignore.rules`:

```udev
# /etc/udev/rules.d/99-sentinel-udisks-ignore.rules
# Mencegah udisks2 / gvfs me-mount otomatis perangkat USB block
SUBSYSTEM=="block", ENV{ID_BUS}=="usb", ENV{UDISKS_IGNORE}="1"
```

Terapkan aturan baru:
```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Dengan aturan ini:
- `udisks2` akan sepenuhnya mengabaikan flashdisk yang dicolokkan.
- File manager desktop tidak akan memunculkan popup atau me-mount partisi.
- Sentinel tetap dapat menangkap udev event melalui Netlink dan me-mount partisi secara aman ke direktori isolasi (`/mnt/sentinel/`).

### B. Menonaktifkan Automount pada Desktop GNOME (Opsional)

Jika menggunakan GNOME Desktop:
```bash
gsettings set org.gnome.desktop.media-handling automount false
gsettings set org.gnome.desktop.media-handling automount-open false
```

---

## 3. Catatan Produksi: Raspberry Pi Headless

Pada implementasi perangkat keras produksi (Raspberry Pi 4 / Compute Module 4 menjalankan Raspberry Pi OS Lite):

- **Bebas Masalah Automount Desktop:**
  Lingkungan Pi OS Lite bersifat *headless* (tanpa server display X11/Wayland dan tanpa desktop environment).
- Daemon automounter berbasis GUI (seperti `gvfs`, `nautilus`, atau thumbnailer) tidak terpasang di sistem.
- Kernel dan `udev` menangani perangkat secara murni tingkat sistem operasi, sehingga `sentinel.service` memiliki kontrol eksklusif penuh sejak deteksi fisik hingga unmount.
