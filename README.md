# Đồ án tốt nghiệp — Các kỹ thuật Hijacking (Labtainer)

Ba bài lab độc lập, mỗi bài chứng minh đúng một kỹ thuật:

| Thư mục | Lab | Trạng thái |
|---|---|---|
| `account-hijacking/` | Account Hijacking | ✅ hoàn thành, đã test |
| `email-hijacking/` | Email Hijacking | ✅ hoàn thành, đã test |
| `token-hijacking/` | Token Hijacking | ✅ hoàn thành, đã test |

## Yêu cầu môi trường

- Ubuntu VM (khuyến nghị Ubuntu 24.04 trên VMware/VirtualBox)
- Docker
- Labtainer (cài theo hướng dẫn chính thức tại https://nps.edu/web/c3o/labtainers)

> Ghi chú: lab được phát triển và test trên Omarchy (Arch-based) với
> Labtainer dựng thủ công từ GitHub `mfthomps/labtainers`. Sinh viên dùng
> đúng Ubuntu + Labtainer chuẩn là chạy được, không phụ thuộc máy dev
> (không hard-code path/username/IP máy dev trong lab).

## Cách dùng chung

```bash
# Copy thư mục lab vào labs của Labtainer, ví dụ:
cp -r account-hijacking/lab ~/labtainer/trunk/labs/web-attk-account-hijacking

cd ~/labtainer/labtainer-student
labtainer web-attk-account-hijacking   # build (lần đầu) + chạy
checkwork web-attk-account-hijacking   # chấm điểm
labtainer -r web-attk-account-hijacking # reset làm lại từ đầu
stoplab web-attk-account-hijacking     # dừng lab
```

Chi tiết từng bài xem README trong thư mục tương ứng.
