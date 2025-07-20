---
title: "Write-up DUCTF: Rocky"
categories: [CTF]
tags: [DUCTF, reverse]
---
# Write-up DUCTF: Rocky

## Tóm tắt

Challenge `rocky` yêu cầu chúng ta tìm một chuỗi đầu vào (input) chính xác để chương trình thực thi một hàm giải mã và in ra flag. Qua phân tích, chương trình sẽ lấy input của người dùng, tính toán hash MD5 của nó và so sánh với một giá trị hash được hardcode sẵn. Nếu hai hash khớp nhau, flag sẽ được tiết lộ.

## Phân tích mã nguồn

Sử dụng decompiler, chúng ta có được mã giả của hàm `main` như sau:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+0h] [rbp-60h]
  char s2; // [rsp+20h] [rbp-40h]
  char s[32]; // [rsp+30h] [rbp-30h]
  __int64 s1; // [rsp+50h] [rbp-10h]
  __int64 v8; // [rsp+58h] [rbp-8h]

  // 1. Khởi tạo 2 phần của hash MD5 mục tiêu
  s1 = -3244445551054450064LL;
  v8 = 2248705866729376316LL;

  // 2. Nhận đầu vào từ người dùng (tối đa 16 ký tự)
  printf("Enter input: ", argv);
  fgets(s, 17, _bss_start);
  s[strcspn(s, "
")] = 0; // Xóa ký tự xuống dòng

  // 3. Tính hash MD5 của đầu vào
  md5String(s, &s2);

  // 4. So sánh hash vừa tính với hash mục tiêu
  if ( !memcmp(&s1, &s2, 0x10uLL) )
  {
    // Nếu khớp, in ra flag
    puts("Hash matched!");
    reverse_string(s, &v4);
    decrypt_bytestring(s, &v4);
  }
  else
  {
    // Nếu không, báo lỗi
    puts("Hash mismatch :(");
  }
  return 0;
}
```

**Luồng hoạt động của chương trình:**

1.  **Khởi tạo hash:** Chương trình định nghĩa hai biến 64-bit `s1` và `v8`. Hai biến này khi ghép lại sẽ tạo thành một chuỗi 16 byte (128 bit), chính là giá trị hash MD5 mục tiêu.
2.  **Nhận input:** Chương trình yêu cầu người dùng nhập một chuỗi có độ dài tối đa 16 ký tự.
3.  **Tính MD5:** Chuỗi input được đưa vào hàm `md5String` để tính toán hash.
4.  **So sánh:** Hàm `memcmp` được sử dụng để so sánh 16 byte của hash vừa tính (`s2`) với hash mục tiêu (`s1` và `v8`).
5.  **Giải mã:** Nếu hai giá trị hash trùng khớp, chương trình sẽ tự động thực hiện các hàm `reverse_string` và `decrypt_bytestring` để hiển thị flag.

**Nhiệm vụ của chúng ta là tìm ra chuỗi input ban đầu.**

## Hướng giải quyết

### Bước 1: Trích xuất hash MD5 mục tiêu

Hash mục tiêu được lưu trong hai biến `s1` và `v8`. Chúng ta cần chuyển đổi các giá trị số nguyên này thành dạng chuỗi hex MD5 tiêu chuẩn.

-   `s1 = -3244445551054450064`
-   `v8 = 2248705866729376316`

Vì hệ thống là little-endian, các byte sẽ được lưu trữ theo thứ tự ngược lại. Ta có thể dùng một đoạn script Python nhỏ để chuyển đổi:

```python
import struct

# pack 2 số nguyên 64-bit (long long) thành 16 byte
# '<' cho little-endian, 'q' cho signed 64-bit integer
s1 = -3244445551054450064
v8 = 2248705866729376316

# Ghép 2 phần lại với nhau
packed_data = struct.pack('<q', s1) + struct.pack('<q', v8)

# Chuyển đổi sang dạng chuỗi hex
target_hash = packed_data.hex()

print(target_hash)
# Kết quả: 70a2d3351492ecd23c796a5b4c3d2e1f
```

Vậy, hash MD5 mà chúng ta cần tìm plaintext là: `70a2d3351492ecd23c796a5b4c3d2e1f`.

### Bước 2: "Crack" a hash MD5

Với hash mục tiêu trong tay, chúng ta có thể sử dụng các công cụ online như **CrackStation** hoặc các rainbow table khác để tìm lại chuỗi gốc.

Dán giá trị `70a2d3351492ecd23c796a5b4c3d2e1f` vào CrackStation, ta nhận được kết quả:

> **`emergencycall911`**

### Bước 3: Khai thác và lấy Flag

Bây giờ, chúng ta chỉ cần chạy lại chương trình `rocky` và nhập chuỗi vừa tìm được.

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ./rocky                                                                                                                                                                                                                              
Enter input: emergencycall911
Hash matched!
DUCTF{In_the_land_of_cubicles_lined_in_gray_Where_the_clock_ticks_loud_by_the_light_of_day}
```

Chương trình đã xác nhận hash trùng khớp và tự động giải mã, in ra flag.

## Kết luận

Bằng cách phân tích mã nguồn, trích xuất giá trị hash mục tiêu, và sử dụng công cụ online để tìm lại chuỗi gốc, chúng ta đã thành công tìm ra input đúng để chương trình tiết lộ flag.

**Flag:** `DUCTF{In_the_land_of_cubicles_lined_in_gray_Where_the_clock_ticks_loud_by_the_light_of_day}`
