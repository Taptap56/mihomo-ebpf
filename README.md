# mihomo-ebpf-kit (v4)

Kit eBPF untuk **mihomo resmi v1.19.32** (versi dikunci, **tanpa fork** —
repo ini isinya kit saja, workflow mengambil source resminya sendiri).

Di v4, eBPF adalah **listener mihomo kelas satu** — padanan persis
inbound `"ebpf"` di sing-box: terdaftar di parser listener core
(`listener/parse.go`), dibuat/dimatikan core mengikuti siklus config,
punya nama (`ebpf-in`), dan koneksinya bertipe `Ebpf` di dashboard.
(Versi kit sebelumnya, v3, memakai seksi config tempelan + glue di
executor — sudah dibuang.)

Datapath-nya **library yang sama persis** dengan sing-box CHIZI:
**`github.com/CHIZI-0618/sing-ebpf` v0.1.0-alpha.13** (objek BPF sudah
ter-compile di dalam library, tidak perlu clang). Consumer-nya ditulis
native untuk mihomo di kit ini.

## Cara kerja listener `"ebpf"` (ringkas)

- **Local (HP sendiri):** program BPF di hook cgroup socket-address
  membelokkan trafik TCP & UDP aplikasi ke port listener internal;
  tujuan asli dipulihkan dari map library (`LookupOriginal`).
- **Shared (hotspot):** program TC packet-rewrite di interface AP
  (mis. `wlan1`) menangkap trafik klien hotspot TCP+UDP
  (`LookupFlow`); interface yang belum ada ditunggu lewat reconcile
  berkala.
- **DNS:** `dns_mode: hijack` mengintersep query UDP/53 di kedua
  jalur dan meneruskannya ke `dns-listen`.
- **Attach anti-EPERM (Android 15):** ditangani library sing-ebpf
  (penggantian placeholder netd secara aman + pemulihan saat detach),
  sama seperti build sing-box CHIZI yang terbukti jalan.
- **Kebijakan:** default intersep; UID 0 (mihomo sendiri) lolos;
  alamat privat lolos bila `bypass-private-address` aktif.
- Koneksi diserahkan ke tunnel mihomo dengan tipe khusus **`EBPF`**
  (konstanta baru di `constant/metadata.go`, ditambahkan di akhir enum
  agar nomor tipe lama tidak bergeser) dan nama inbound sesuai nama
  listener.

Consumer ini lebih ramping dari consumer sing-box CHIZI: tanpa
filter UID/paket per aplikasi, tanpa diagnostik daemon, tanpa FakeIP
ICMP echo, tanpa batching UDP. Self-bypass per-soket outbound tidak
dipakai — kebijakan UID 0 menutup jalur loop-nya.

## Config

Satu entri di seksi `listeners:` (lihat `examples/config-ebpf.yaml`):

```yaml
listeners:
  - name: ebpf-in
    type: ebpf
    port: 15361
    dns-listen: 127.0.0.1:1053
    local:
      enabled: true
      ipv6: false
      dns-mode: hijack
      bypass-private-address: true
    shared:
      enabled: true
      ipv6: false
      dns-mode: hijack
      interface: ["wlan1"]
      bypass-private-address: true
```

- `port` — port listener internal bersama kedua plane (default 15361).
- `dns-listen` — target hijack DNS (default `127.0.0.1:1053`).
- `local.cgroup-path` — opsional, default `/sys/fs/cgroup`.
- Interface hotspot tidak universal: MediaTek sering `wlan1`,
  Qualcomm sering `ap0`. Cek dengan `ip link` saat hotspot menyala.

## Isi kit

| Isi | Fungsi |
| --- | --- |
| `new-files/listener/ebpf/` (6 file) | Consumer datapath: manager, listener TCP/UDP, stub non-linux |
| `new-files/listener/config/ebpf.go` | Tipe config datapath (`local`/`shared`) |
| `new-files/listener/inbound/ebpf.go` | Opsi + wrapper listener `"ebpf"` (sistem listener mihomo) |
| `new-files/listener/ebpf_*_test.go` | Tes registrasi listener |
| `ebpf.patch` (48 baris, 2 file) | Tipe koneksi `EBPF` di `constant/metadata.go` + `case "ebpf"` di `listener/parse.go` |
| `apply-ebpf.sh` | Pasang semua di atas ke source mihomo |
| `.github/workflows/build-android-arm64.yml` | Build otomatis di GitHub Actions |
| `examples/config-ebpf.yaml` | Contoh entri listener |

## Build via GitHub Actions (disarankan)

Repo cukup berisi **kit ini saja** — source mihomo v1.19.32 diambil
otomatis oleh workflow dari MetaCubeX/mihomo:

1. Taruh **semua isi folder kit ini** di root repo, commit & push.
2. Tab **Actions** → *Build mihomo android-arm64 + ebpf listener
   (v1.19.32)* → **Run workflow**.
3. Ambil binary `mihomo` dari **Artifacts**
   (`mihomo-android-arm64-ebpf-1.19.32`).

Workflow: checkout source resmi tag `v1.19.32` → apply kit →
`go get github.com/CHIZI-0618/sing-ebpf@v0.1.0-alpha.13` →
`GOFLAGS=-tags=with_ebpf go mod tidy` → build android/arm64
`-tags with_ebpf` **tanpa strip**, versi dilabeli `v1.19.32`.
Go di-pin **1.25.5** (library sing-ebpf membutuhkannya).

Tanpa tag `with_ebpf`, listener `"ebpf"` tetap terdaftar tapi
menolak jalan dengan pesan `ebpf: datapath is not included in this
build` (aman untuk build biasa).

## Build manual

```sh
# di root source mihomo v1.19.32, isi kit sudah dicopy ke sana juga
./apply-ebpf.sh
go get github.com/CHIZI-0618/sing-ebpf@v0.1.0-alpha.13
GOFLAGS=-tags=with_ebpf go mod tidy
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -tags with_ebpf \
  -trimpath -ldflags "-X github.com/metacubex/mihomo/constant.Version=v1.19.32" \
  -o mihomo-android-arm64 .
```

## Status & batasan

- **Terverifikasi lokal:** kit ter-apply bersih di clone murni
  v1.19.32; build linux & android/arm64 lolos dengan dan tanpa tag;
  tes registrasi lulus — `ParseListener` mendecode entri `ebpf`
  (nama, port, `local`/`shared`, perbandingan `Equal` untuk reload),
  dan build tanpa tag menolak `Listen` dengan pesan yang jelas.
- **Datapath-nya kode yang sama** dengan kit v3 yang **sudah jalan
  di HP** (attach cgroup lolos, internet jalan, tangkapan bersumber
  token redirect 127.128.0.0/9) — yang baru di v4 cuma cara core
  mendaftarkan & memanggilnya. Attach runtime binary v4 = tes
  lapangan pertama.
- **Wajib root** (attach eBPF) dan kernel `CONFIG_CGROUP_BPF=y`.
- Perpindahan dari v3: hapus seksi `ebpf:` di config, ganti entri
  `listeners:` di atas.

- **Kredit & lisensi:** library sing-ebpf karya **CHIZI-0618**
  (GPLv3, sama seperti mihomo). Kit ini cuma memindahkannya ke
  mihomo.
