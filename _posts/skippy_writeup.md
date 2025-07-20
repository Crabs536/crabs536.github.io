---
title: "Thám mã tấn công module chung"
categories: [CTF]
tags: [DUCTF, reverse]
---
# Write-up: Skippy.exe Reverse Engineering Challenge

## 1. Giới thiệu thử thách

Thử thách `skippy.exe` là một bài toán đảo ngược (reverse engineering) trên nền tảng Windows 64-bit. Tiêu đề của thử thách là "Skippy seems to be in a bit of trouble skipping over some sandwiched functions. Help skippy get across with a hop, skip and a jump!". Tiêu đề này gợi ý rằng chương trình có các hàm bị "kẹp" (sandwiched) và chúng ta cần tìm cách vượt qua một vấn đề nào đó để chương trình có thể tiếp tục thực thi.

## 2. Phân tích ban đầu và xác định vấn đề

Chúng ta bắt đầu với đoạn mã `main` của chương trình:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v4; // [rsp+20h] [rbp-40h]
  __int64 v5; // [rsp+28h] [rbp-38h]
  char v6; // [rsp+30h] [rbp-30h]
  __int64 v7; // [rsp+40h] [rbp-20h]
  __int64 v8; // [rsp+48h] [rbp-18h]
  char v9; // [rsp+50h] [rbp-10h]

  _main();
  v7 = -1675634963676735770i64;
  v8 = -4697000515349853488i64;
  v9 = 64;
  sandwich((char *)&v7); // Lần gọi sandwich đầu tiên
  v4 = -2387219227114421546i64;
  v5 = -2387225703656530210i64;
  v6 = 64;
  sandwich((char *)&v4); // Lần gọi sandwich thứ hai
  decrypt_bytestring((__int64)&v7, (__int64)&v4);
  return 0;
}
```

Từ đoạn mã này, chúng ta thấy:
*   Chương trình khởi tạo hai khối dữ liệu (`v7, v8, v9` và `v4, v5, v6`).
*   Hàm `sandwich` được gọi hai lần với các khối dữ liệu này.
*   Cuối cùng, hàm `decrypt_bytestring` được gọi với địa chỉ của `v7` và `v4`.

Khi chạy chương trình `skippy.exe`, nó ngay lập tức in ra "Oh no! Skippy is about to trip!" và thoát.

### 2.1. Phân tích `strings_skippy.txt`

Kiểm tra tệp `strings_skippy.txt` cho thấy các chuỗi đáng chú ý:
*   "Oh no! Skippy is about to trip!"
*   "Uh oh... Skippy sees a null zone in the way..."
*   Các hàm API Windows như `Sleep`, `VirtualProtect`, `VirtualQuery`, `GetLastError`, `SetUnhandledExceptionFilter`.

## 3. Phân tích mã nguồn (`skippy_src.txt`) và xác định cơ chế chống phân tích

Việc có tệp `skippy_src.txt` (được tạo từ IDA Pro) là cực kỳ hữu ích để hiểu sâu hơn về hành vi của chương trình. Phân tích mã nguồn đã tiết lộ:

*   **Lỗi `ACCESS_VIOLATION`:** Mã nguồn xác nhận rằng lỗi `STATUS_ACCESS_VIOLATION` (0xc0000005) xảy ra tại địa chỉ `0x140001570` (tương ứng với `0x7ff73d3e1570` trong bộ nhớ runtime) trong hàm `stone`. Cụ thể, lệnh `mov [rax], dl` đang cố gắng ghi một byte vào địa chỉ của chuỗi "Oh no! Skippy is about to trip!", vốn là một chuỗi hằng được lưu trữ trong vùng bộ nhớ chỉ đọc. Việc cố gắng ghi vào vùng chỉ đọc này gây ra lỗi.

*   **Cơ chế "Sandwiched Functions":** Hàm `stone` được gọi hai lần bởi hàm `sandwich`:

    ```assembly
    sandwich        proc near
    ; ...
        call    stone
    ; ...
        call    decryptor
    ; ...
        call    stone
    ; ...
    sandwich        endp
    ```

    Điều này xác nhận rằng `stone` là một cơ chế chống phân tích, được thiết kế để gây lỗi nếu chương trình không được thực thi trong môi trường mong muốn (ví dụ: không bị gỡ lỗi hoặc giả mạo). Việc chương trình thoát ngay lập tức sau khi in thông báo "Oh no! Skippy is about to trip!" là do cơ chế này.

## 4. Phân tích logic giải mã chính

Sau khi hiểu được nguyên nhân gây lỗi, chúng ta tập trung vào hàm `decrypt_bytestring` được gọi trong `main`, vì đây là nơi chứa logic giải mã thực sự.

```c
decrypt_bytestring((__int64)&v7, (__int64)&v4);
```

Phân tích `skippy_src.txt` cho thấy `decrypt_bytestring` thực hiện các bước sau:
1.  Gọi `AES_init_ctx_iv` với `&v7` (khối 1) làm khóa và `&v4` (khối 2) làm IV.
2.  Sao chép dữ liệu được mã hóa từ một vị trí `precomputed` vào một bộ đệm.
3.  Gọi `AES_CBC_decrypt_buffer` để giải mã dữ liệu.
4.  In ra dữ liệu đã giải mã bằng `puts`.

### 4.1. Trích xuất Khóa, IV và Dữ liệu được mã hóa

Từ `main`:
*   **Khóa gốc (Key):** Được tạo từ `v7` và `v8`.
    *   `v7 = -1675634963676735770i64`
    *   `v8 = -4697000515349853488i64`
*   **IV gốc (IV):** Được tạo từ `v4` và `v5`.
    *   `v4 = -2387219227114421546i64`
    *   `v5 = -2387225703656530210i64`

Chuyển đổi các giá trị `__int64` này sang byte little-endian:

```python
key_v7 = -1675634963676735770
key_v8 = -4697000515349853488
iv_v4 = -2387219227114421546
iv_v5 = -2387225703656530210

original_key = key_v7.to_bytes(8, byteorder='little', signed=True) + \
               key_v8.to_bytes(8, byteorder='little', signed=True)
original_iv = iv_v4.to_bytes(8, byteorder='little', signed=True) + \
              iv_v5.to_bytes(8, byteorder='little', signed=True)

# Kết quả:
# Key (hex): e6d6d2e0e0f2bee8d0cabec4eae6d0be
# IV (hex): d6c2dccec2e4dededededededededede
```

Dữ liệu được mã hóa (`precomputed`) được tìm thấy trong `skippy_src.txt` tại địa chỉ `0x14000A000`. Kích thước của dữ liệu được mã hóa là `0x60` (96 byte).

```
.data:000000014000A000 precomputed     db 0AEh ; ®             ; DATA XREF: decrypt_bytestring+68↑o
.data:000000014000A001                 db  27h ; '
; ... (tiếp tục 96 byte) ...
```

Trích xuất 96 byte này cho chúng ta:
`ae27241b7ffd2c8b3265f22ad1b063f0915b6b95dcc0eec14de2c563f7715594007d2bc75e5d614e5e51190f4ad1fd21c5c4b1ab89a4a725c5b8ed3cb37630727b2d2ab722dc9333264725c6b5ddb00dd3c3da6313f1e2f4df5180d5f3831843`

### 4.2. Phép biến đổi Khóa và IV

Quan trọng nhất, hàm `decryptor` (được gọi bởi `sandwich`) thực hiện một phép biến đổi trên dữ liệu đầu vào của nó. Cụ thể, nó thực hiện phép toán `shr dl, 1` (dịch phải 1 bit, tương đương với chia cho 2) trên mỗi byte.

Vì `sandwich` được gọi trên cả khóa và IV, chúng ta cần áp dụng phép biến đổi này cho cả hai trước khi sử dụng chúng để giải mã AES.

## 5. Giải mã AES và thu thập Flag

Sử dụng thư viện `PyCryptodome` trong Python để thực hiện giải mã AES-128 CBC.

```python
from Crypto.Cipher import AES

original_key_hex = "e6d6d2e0e0f2bee8d0cabec4eae6d0be"
original_iv_hex = "d6c2dccec2e4dededededededededede"
encrypted_data_hex = "ae27241b7ffd2c8b3265f22ad1b063f0915b6b95dcc0eec14de2c563f7715594007d2bc75e5d614e5e51190f4ad1fd21c5c4b1ab89a4a725c5b8ed3cb37630727b2d2ab722dc9333264725c6b5ddb00dd3c3da6313f1e2f4df5180d5f3831843"

def transform_bytes(byte_string):
    transformed = bytearray()
    for b in byte_string:
        transformed.append(b // 2) # Integer division by 2
    return bytes(transformed)

original_key = bytes.fromhex(original_key_hex)
original_iv = bytes.fromhex(original_iv_hex)
encrypted_data = bytes.fromhex(encrypted_data_hex)

# Áp dụng phép biến đổi cho khóa và IV
key = transform_bytes(original_key)
iv = transform_bytes(original_iv)

print(f"Transformed Key (hex): {key.hex()}")
print(f"Transformed IV (hex): {iv.hex()}")

cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted_data = cipher.decrypt(encrypted_data)

print(f"Decrypted data (bytes): {decrypted_data}")
print(f"Decrypted data (UTF-8): {decrypted_data.decode('utf-8', errors='ignore')}")
```

## 6. Kết quả

Chạy tập lệnh Python trên cho ra kết quả:

*   **Transformed Key (hex):** `736b697070795f7468655f627573685f` (ASCII: `skippy_the_bush_`)
*   **Transformed IV (hex):** `6b616e6761726f6f6f6f6f6f6f6f6f6f` (ASCII: `kangaroooooooooo`)

Và flag đã giải mã là:

**`DUCTF{There_echoes_a_chorus_enending_and_wild_Laughter_and_gossip_unruly_and_piled}`**

## 7. Bài học rút ra

*   **Phân tích tĩnh là chìa khóa:** Việc có mã nguồn (hoặc đầu ra dịch ngược chất lượng cao) là cực kỳ quan trọng để hiểu sâu về logic chương trình, đặc biệt là các cơ chế chống phân tích và thuật toán mã hóa.
*   **Nhận diện cơ chế chống phân tích:** Các lỗi `ACCESS_VIOLATION` hoặc các thông báo bất thường thường là dấu hiệu của các kỹ thuật chống gỡ lỗi hoặc chống giả mạo. Việc hiểu nguyên nhân gốc rễ của chúng (thông qua phân tích tĩnh) là quan trọng hơn việc cố gắng bỏ qua chúng một cách mù quáng.
*   **Hiểu rõ luồng dữ liệu và biến đổi:** Theo dõi cách dữ liệu được khởi tạo, biến đổi và sử dụng trong các hàm khác nhau là rất quan trọng, đặc biệt là trong các thuật toán mã hóa. Một phép biến đổi nhỏ (như chia cho 2) có thể thay đổi hoàn toàn kết quả.
*   **Sử dụng công cụ phù hợp:** Mặc dù các công cụ gỡ lỗi động như Frida có thể hữu ích để xác định các điểm lỗi và quan sát hành vi, nhưng đối với các thử thách phức tạp, phân tích tĩnh với các trình dịch ngược/dịch ngược (như IDA Pro hoặc Ghidra) thường cung cấp cái nhìn sâu sắc cần thiết để giải quyết vấn đề.
