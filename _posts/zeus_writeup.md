# Write-up CTF: Zeus

## 1. Giới thiệu

Challenge "Zeus" cung cấp cho chúng ta một file thực thi trên Linux. Mục tiêu là tìm ra cách thực thi chương trình một cách chính xác để nhận được flag. Công cụ chính được sử dụng trong bài phân tích này là IDA Pro để dịch ngược (decompile) file thực thi về dạng mã C giả (pseudo-code), giúp chúng ta hiểu được logic hoạt động của nó.

## 2. Phân tích mã nguồn từ IDA Pro

Sau khi mở file `zeus` bằng IDA Pro và thực hiện decompile, chúng ta thu được mã giả của hàm `main` như sau:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  // Khai báo các biến chứa dữ liệu được mã hóa
  __int64 v4; // [rsp+10h] [rbp-90h]
  __int64 v5; // [rsp+18h] [rbp-88h]
  // ... (các biến khác)
  __int64 v10; // [rsp+50h] [rbp-50h]
  __int64 v11; // [rsp+58h] [rbp-48h]
  __int64 v12; // [rsp+60h] [rbp-40h]
  __int64 v13; // [rsp+68h] [rbp-38h]
  __int64 v14; // [rsp+70h] [rbp-30h]
  __int64 v15; // [rsp+78h] [rbp-28h]

  // Khai báo các chuỗi hằng
  const char *v16; // [rsp+90h] [rbp-10h]
  char *s2; // [rsp+98h] [rbp-8h]

  // 1. Khởi tạo dữ liệu
  // Chuỗi cần thiết để chương trình chạy đúng
  s2 = "To Zeus Maimaktes, Zeus who comes when the north wind blows, we offer our praise, we make you welcome!";
  // Khóa để giải mã
  v16 = "Maimaktes1337";
  // Dữ liệu flag đã được mã hóa
  v10 = 873434613382001673LL;
  v11 = 77988709201106461LL;
  v12 = 6503512442910555656LL;
  v13 = 3752071361029364050LL;
  v14 = 1320500633443699477LL;
  v15 = 16344253587394318LL;
  *(_DWORD *)((char *)&v15 + 7) = 1313495552;

  // 2. Logic kiểm tra đầu vào
  if ( argc == 3 && !strcmp(argv[1], "-invocation") && !strcmp(argv[2], s2) )
  {
    // 3. Nhánh thực thi đúng (giải mã)
    puts("Zeus responds to your invocation!");
    // Sao chép dữ liệu mã hóa để chuẩn bị giải mã
    v4 = v10;
    v5 = v11;
    v6 = v12;
    v7 = v13;
    v8 = v14;
    v9 = v15;
    *(_DWORD *)((char *)&v9 + 7) = *(_DWORD *)((char *)&v15 + 7);
    
    // Gọi hàm giải mã XOR
    xor(&v4, v16);
    
    // In kết quả (flag)
    printf("His reply: %s\n", &v4);
  }
  else
  {
    // 4. Nhánh thực thi sai
    puts("The northern winds are silent...");
  }
  return 0;
}
```

### Phân tích chi tiết:

-   **Khởi tạo dữ liệu:**
    -   Biến `s2` là "câu thần chú" mà chúng ta cần cung cấp.
    -   Biến `v16` (`Maimaktes1337`) là khóa (key) để giải mã.
    -   Các biến từ `v10` đến `v15` chứa dữ liệu của flag đã bị mã hóa.

-   **Logic kiểm tra đầu vào (Điều kiện `if`):**
    Đây là phần cốt lõi để chương trình chạy đúng.
    -   `argc == 3`: Chương trình yêu cầu đúng 3 tham số dòng lệnh.
    -   `!strcmp(argv[1], "-invocation")`: Tham số thứ nhất phải là chuỗi `-invocation`.
    -   `!strcmp(argv[2], s2)`: Tham số thứ hai phải là chuỗi dài được gán cho `s2`.

-   **Nhánh thực thi đúng:**
    Nếu các điều kiện trên được thỏa mãn, chương trình sẽ thực hiện giải mã bằng phép toán XOR lặp (repeating XOR) với khóa `v16` và in ra kết quả.

## 3. Xây dựng lệnh thực thi và lấy Flag

Từ phân tích trên, chúng ta xây dựng được dòng lệnh hoàn chỉnh để cung cấp đúng các tham số cho chương trình:

```bash
./zeus -invocation 'To Zeus Maimaktes, Zeus who comes when the north wind blows, we offer our praise, we make you welcome!'
```

Khi chạy lệnh này, chương trình sẽ thỏa mãn điều kiện, thực hiện giải mã và in ra flag.

### Kết quả:

```
Zeus responds to your invocation!
His reply: DUCTF{king_of_the_olympian_gods_and_god_of_the_sky}
```

> **FLAG:** `DUCTF{king_of_the_olympian_gods_and_god_of_the_sky}`

## 4. Kết luận

Đây là một bài reverse engineering cơ bản, trong đó thử thách chính là đọc hiểu mã C đã được dịch ngược để tìm ra các tham số dòng lệnh chính xác. Khi các tham số này được cung cấp đúng, chương trình sẽ tự động thực hiện quá trình giải mã và trả về flag.
