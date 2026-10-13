# Lab: Thực hành khai thác Email Hijacking

## Mục đích

Hiểu cách giao thức truyền tin không mã hóa (dịch vụ check mail
cũ) làm lộ mailbox password qua sniffing, dẫn đến chiếm quyền hộp
thư của nạn nhân (đọc mail riêng + gửi mail mạo danh).

## Kiến thức yêu cầu

- Linux cơ bản (`tcpdump`, `telnet`, `curl`, `grep`)
- Hiểu bắt gói tin cơ bản, ARP spoofing (MITM) và giao thức plaintext
- username/password, web session cơ bản

## Kiến trúc

```
victim (172.26.0.4) ──plaintext login mỗi ~25s──▶ victim-mail (172.26.0.2)
attacker (172.26.0.3) ──arpspoof MITM + tcpdump──▶ sniff ──▶ webmail login
```

- `victim`: máy nhân viên, tự động check mail định kỳ qua dịch vụ legacy
- `victim-mail`: webmail `http://victim-mail:8000` + dịch vụ legacy
  plaintext `victim-mail:2323`; 2 mailbox `victim`/`attacker`
- `attacker`: terminal thực hành (`arpspoof`, `tcpdump`, `telnet`,
  `curl`, `grep`, `python3`)

## Cách chạy (khuyến nghị: imodule + DockerHub)

```bash
cd ~/labtainer/labtainer-student
imodule https://github.com/Taamne/tamdtt-hijacking/raw/main/email-hijacking/imodule_web-attk-email-hijacking.tar
labtainer web-attk-email-hijacking
```

Image đã publish tại `taamne/web-attk-email-hijacking.{attacker,victim-mail,victim}.student`
(`https://hub.docker.com/u/taamne`) nên sinh viên không cần build local.

Cách thủ công (không dùng imodule): copy thư mục `lab/` vào
`~/labtainer/trunk/labs/web-attk-email-hijacking` rồi chạy `labtainer`
như trên (lần đầu sẽ tự build image).

## Nhiệm vụ (không lời giải)

1. MITM giữa victim và victim-mail, sniff password mailbox victim,
   lưu output đọc được vào `/tmp/output.txt`.
2. Dùng password đó đăng nhập webmail với tài khoản victim.
3. Đọc mail riêng (payroll token) của victim.
4. Gửi 1 mail mạo danh victim.
5. Chạy checkwork:

```bash
checkwork web-attk-email-hijacking
```

Kết quả mong muốn:

```
 Y - credential_discovered
 Y - mailbox_login
 Y - email_hijacked
```

## Reset / dừng

```bash
labtainer -r web-attk-email-hijacking  # làm lại từ đầu
stoplab web-attk-email-hijacking       # dừng lab
```

## Nguồn lab

Thư mục `lab/` chứa toàn bộ source Labtainer (`config/`,
`dockerfiles/`, `attacker/`, `victim/`, `victim-mail/`,
`instr_config/`, `docs/`). Không commit secret thật, build artifact
hay log máy local.
