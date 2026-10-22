#!/bin/sh
# apply-ebpf.sh — pasang kit eBPF ala CHIZI ke source mihomo v1.19.32.
# Jalankan di root source mihomo RESMI v1.19.32 (pristine, tanpa modifikasi),
# dengan isi kit ini sudah dicopy ke root yang sama.
#
# Isi kit ini:
#   new-files/listener/ebpf/          -> copy ke listener/ebpf/
#        (consumer mihomo untuk library sing-ebpf: manager, listener,
#         jalur TCP/UDP lokal-cgroup + hotspot packet-rewrite)
#   new-files/listener/config/ebpf.go  -> copy ke listener/config/ebpf.go
#        (tipe config datapath)
#   new-files/listener/inbound/ebpf.go -> copy ke listener/inbound/ebpf.go
#        (opsi + listener "ebpf" untuk sistem listener mihomo)
#   new-files/listener/ebpf_*_test.go  -> copy ke listener/
#        (tes registrasi listener)
#   ebpf.patch                        -> git apply (2 file:
#        constant/metadata.go — tipe koneksi EBPF baru;
#        listener/parse.go   — case "ebpf" di parser listener)
#
# eBPF di sini adalah LISTENER mihomo (seperti inbound "ebpf" di
# sing-box): config-nya entri listeners: bertipe ebpf, dibuat dan
# dimatikan oleh core mengikuti siklus config — bukan seksi tempelan.
#
# Dependensi diambil workflow/langkah build via:
#   go get github.com/CHIZI-0618/sing-ebpf@v0.1.0-alpha.13
#   GOFLAGS=-tags=with_ebpf go mod tidy
set -e
cd "$(dirname "$0")"

echo "== copy file baru =="
mkdir -p listener/ebpf listener/config listener/inbound
cp -r new-files/listener/ebpf/* listener/ebpf/
cp new-files/listener/config/ebpf.go listener/config/ebpf.go
cp new-files/listener/inbound/ebpf.go listener/inbound/ebpf.go
cp new-files/listener/ebpf_parse_test.go new-files/listener/ebpf_stub_test.go listener/
echo "   listener/ebpf/{manager,listener,tcp,udp}_linux.go + manager_other.go"
echo "   listener/config/ebpf.go, listener/inbound/ebpf.go, listener/ebpf_*_test.go"

echo "== apply patch (tipe EBPF + registrasi listener) =="
git apply --check ebpf.patch && git apply ebpf.patch
echo "   constant/metadata.go + listener/parse.go OK"

echo ""
echo "SELESAI. Langkah lanjut:"
echo "  1. Dependensi: go get github.com/CHIZI-0618/sing-ebpf@v0.1.0-alpha.13"
echo "                 GOFLAGS=-tags=with_ebpf go mod tidy"
echo "  2. Build: CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -tags with_ebpf -trimpath -ldflags \"-X github.com/metacubex/mihomo/constant.Version=v1.19.32\" -o mihomo-android-arm64 ."
echo "  (Atau pakai workflow GitHub Actions di kit ini — otomatis.)"
