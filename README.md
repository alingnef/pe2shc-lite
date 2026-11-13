# pe2shc lite

Chuyển **EXE Windows native x86/x64 → `input.exe.shc`** và chạy đầu ra bằng runner đi kèm. Python dùng thư viện chuẩn; không cần cài package qua `pip`. Giải thích nguyên lý trong [how_it_works.md](how_it_works.md).

## Chạy nhanh trên Windows

Giải nén gói, mở PowerShell trong thư mục `pe2shc-lite`, rồi dùng hai lệnh sau với EXE **64-bit**:

```powershell
python .\pe2shc.py .\input.exe
.\runshc.exe .\input.exe.shc
```

Với EXE **32-bit**:

```powershell
python .\pe2shc.py .\input32.exe
.\runshc32.exe .\input32.exe.shc
```

Converter tự nhận diện kiến trúc và in lệnh runner phù hợp. `input.exe` là EXE của bạn; hai file runner đã có sẵn trong gói.

**File `.exe.shc` phải chạy qua runner, không nhấp đúp trực tiếp.** Runner chạy nội dung trong tiến trình của chính nó. Nếu EXE gọi `ExitProcess`, runner cũng kết thúc.

## Yêu cầu

- Python **3.10 trở lên** để chuyển đổi. Kiểm tra bằng `python --version`; trên Windows có thể dùng `py -3` thay `python`.
- Windows để chạy `runshc.exe` hoặc `runshc32.exe`.
- Runner phải cùng kiến trúc với EXE: Windows 64-bit không có nghĩa mọi EXE đầu vào đều là x64.
- EXE đầu vào là native x86/x64, có base relocations và thuộc phạm vi hỗ trợ bên dưới.
- Các DLL phụ thuộc của EXE phải có sẵn/phân giải được trong môi trường Windows chạy runner.

Không cần compiler nếu dùng runner biên dịch sẵn. Converter có thể chạy trên Linux/WSL bằng `python3 pe2shc.py input.exe`; đầu ra vẫn dành cho runner Windows.

## Các file trong gói

| File | Vai trò |
|---|---|
| `pe2shc.py` | Converter; chứa sẵn loader x86/x64 |
| `runshc.c` | Source C dùng để build cả hai runner |
| `runshc.exe` | Runner x64 biên dịch sẵn |
| `runshc32.exe` | Runner x86 biên dịch sẵn |
| `README.md` | Hướng dẫn sử dụng |
| `how_it_works.md` | Giải thích chi tiết cơ chế và giới hạn |
| `LICENSE.txt` | Giấy phép và ghi công |

## Tùy chọn sử dụng

### Đường dẫn có dấu cách

```powershell
python .\pe2shc.py "D:\My Project\demo.exe"
.\runshc.exe "D:\My Project\demo.exe.shc"
```

Mặc định, output nằm cạnh input và có tên bằng tên input cộng thêm `.shc`. Ví dụ `demo.exe` tạo thành `demo.exe.shc`.

### Chọn tên đầu ra

```powershell
python .\pe2shc.py .\input.exe -o .\result.shc
.\runshc.exe .\result.shc
```

Tùy chọn dài tương đương là `--output`. Nếu chọn đường dẫn trong một thư mục con, hãy tạo thư mục đó trước.

### Xem trợ giúp

```powershell
python .\pe2shc.py --help
```

Converter không ghi đè file đã có. Nếu gặp lỗi `File exists`, chọn tên output mới bằng `-o`, hoặc chủ động xóa đầu ra cũ rồi chạy lại. Không có tùy chọn `--force` trong bản này.

Runner hiện chỉ nhận đường dẫn `.shc`; không có tùy chọn truyền thêm đối số riêng cho chương trình được nạp.

## Đọc kết quả chạy

Với mẫu console `demo.c` dùng `WriteFile` ở phía dưới, khi API thành công và entry trả về, runner in:

```text
[+] Entry returned 1337; loader status=2
```

`1337` là giá trị trả về của mẫu console `demo.c`. Mẫu GUI `test.c` dùng `MessageBoxA` trả `0` khi API thành công hoặc `1` khi thất bại. Sau khi đóng hộp thoại của mẫu GUI thành công, dòng dự kiến là:

```text
[+] Entry returned 0; loader status=2
```

`loader status=2` cho biết loader đã chuyển đến entry. Cần đọc thêm giá trị trả về và kết quả thực tế của chương trình.

Kiểm tra mã kết thúc runner trong PowerShell:

```powershell
$LASTEXITCODE
```

Runner trả `0` khi lời gọi trở về với status bằng 2, và `1` ở các nhánh lỗi được xử lý. Nó không chuyển trực tiếp giá trị như `1337` thành exit code. Nếu EXE tự kết thúc tiến trình hoặc bị crash, kết quả tuân theo tình huống đó.

## Tự build runner - tùy chọn

### MinGW-w64

Dùng GCC **nhắm đến Windows**, chẳng hạn toolchain MinGW-w64. GCC mặc định của Ubuntu không biên dịch trực tiếp chương trình dùng WinAPI này.

Trong terminal toolchain x64:

```powershell
gcc -O2 -Wall -Wextra -municode runshc.c -o runshc.exe
```

Trong terminal toolchain x86:

```powershell
gcc -O2 -Wall -Wextra -municode runshc.c -o runshc32.exe
```

Nếu toolchain đang dùng hỗ trợ multilib, có thể chọn x86 bằng `-m32`. Chỉ đổi tên output thành `runshc32.exe` không làm compiler chuyển sang x86.

`-municode` cần cho entry `wmain` của runner.

### Visual Studio

Mở **x64 Native Tools Command Prompt**:

```bat
cl /nologo /O2 /W4 runshc.c /Fe:runshc.exe
```

Hoặc mở **x86 Native Tools Command Prompt**:

```bat
cl /nologo /O2 /W4 runshc.c /Fe:runshc32.exe
```

Runner được Windows loader nạp như một chương trình thông thường, nên Windows có thể khởi tạo CRT/TLS của runner. EXE nằm trong `.shc` được loader nhúng nạp thủ công và phải đáp ứng giới hạn TLS của loader này. Vì vậy lệnh build runner dùng startup mặc định, còn hai EXE mẫu phía dưới dùng `-nostdlib`.

Không cần CMake hoặc libpeconv.

## Tạo một EXE nhỏ để thử - tùy chọn

Nếu chưa có input phù hợp, lưu đoạn sau thành `demo.c`. Ví dụ dùng entry riêng, không cần CRT startup; con trỏ toàn cục tạo nhu cầu base relocation.

```c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static const char message[] = "Hello from the converted EXE!\r\n";
static const char * volatile relocated_message = message;

int __cdecl entry(void)
{
    DWORD written = 0;
    return WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), relocated_message,
                     sizeof(message) - 1, &written, NULL) ? 1337 : -1;
}
```

Build với **MinGW-w64 x64**, rồi chuyển đổi và chạy:

```powershell
gcc -Os -fno-stack-protector -nostdlib demo.c "-Wl,-e,entry" "-Wl,--dynamicbase" -lkernel32 -o demo.exe
python .\pe2shc.py .\demo.exe
.\runshc.exe .\demo.exe.shc
```

Nếu các lời gọi WinAPI thành công, mẫu in `Hello from the converted EXE!`, rồi trả `1337`. `demo.c`/`demo.exe` là file bạn tạo thêm theo hướng dẫn này, không phải file có sẵn trong gói.

### Trường hợp `test.c` dùng `MessageBoxA` trên CMD

Nếu bạn viết source với hàm `entry()` thay vì `main()` thì **không build bằng `gcc test.c -o test`**. Lệnh mặc định liên kết mã khởi động của MinGW; linker tìm `main` hoặc `WinMain` và có thể báo:

```text
undefined reference to `WinMain'
```

Khi build mặc định thành công với `main()`, runtime MinGW/CRT cũng có thể đưa `.CRT`, `.tls`, TLS Directory và các imports của CRT vào EXE. Bản EXE cũ `test.exe`, được build kèm runtime và dùng để chẩn đoán lỗi `Static TLS is unsupported`, có **TLS template 8 byte**, hai TLS callbacks và imports UCRT/TlsGetValue. Sự hiện diện của `.tls` ở file đó đến từ kết quả liên kết, dù source ứng dụng không trực tiếp khai báo biến TLS.

Để tạo chương trình GUI nhỏ dùng WinAPI, lưu nội dung sau vào `test.c`:

```c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static const char message[] = "Flag: flag{Hello_from_WinAPI!}";
static const char title[] = "This is your gift";
static const char *volatile message_ptr = message;
static const char *volatile title_ptr = title;

int __cdecl entry(void)
{
    return MessageBoxA(
        NULL,
        message_ptr,
        title_ptr,
        MB_OK
    ) ? 0 : 1;
}
```

Trong **CMD trên Windows** có Strawberry GCC x64/MinGW-w64, dùng nguyên lệnh:

```bat
gcc -Os -fno-stack-protector -nostdlib test.c "-Wl,-e,entry" "-Wl,--subsystem,windows" "-Wl,--dynamicbase" -luser32 -lkernel32 -o test-min.exe
python pe2shc.py test-min.exe
runshc.exe test-min.exe.shc
```

`-nostdlib` bỏ các startup object và thư viện mặc định. `-Wl,-e,entry` đặt hàm `entry` làm entry point của PE. `-luser32` cung cấp `MessageBoxA` và `--subsystem,windows` đặt GUI subsystem. Hai con trỏ toàn cục chứa địa chỉ tuyệt đối, tạo các vị trí cần base relocation. `--dynamicbase` bật cờ hỗ trợ ASLR. Converter kiểm tra relocation directory và các entry, không yêu cầu riêng cờ `DYNAMIC_BASE`. `-fno-stack-protector` tránh phụ thuộc phần hỗ trợ stack protector của runtime.

Với mẫu `test.c` này, khi API thành công, hộp thoại có tiêu đề `This is your gift`, nội dung `Flag: flag{Hello_from_WinAPI!}`, rồi entry trả `0`.

Với mẫu C tối giản trên, dùng đúng hàm `int __cdecl entry(void)` và lệnh build đi kèm. Khi áp dụng cho source khác, cần kiểm tra các phụ thuộc CRT và mã khởi tạo mà chương trình sử dụng. Compiler cũng có thể sinh lời gọi hỗ trợ như `memcpy` hoặc `memset`. Chỉ đổi tên `main` thành `entry` chưa đủ để xác nhận một chương trình bất kỳ phù hợp loader.

Nếu linker báo thiếu symbol, kiểm tra hàm và thư viện tương ứng. Hãy build lại từ source phù hợp khi gặp lỗi TLS. Việc xóa `.tls` khỏi EXE cũ có thể làm hỏng runtime đang sử dụng TLS đó.

### Phân biệt các mẫu được nhắc trong tài liệu

| Mẫu | Vai trò | Kết quả đã xác định |
|---|---|---|
| `demo.c` → `demo.exe` | Mẫu console dùng `WriteFile` | Đã chạy trong giả lập, trả `1337`, status `2` |
| `test.c` → `test-min.exe` | Mẫu GUI dùng `MessageBoxA` | Source và binary phù hợp nhau, không có TLS Directory, có hai relocation `DIR64` |
| `test-min.exe.shc` | Đầu ra của mẫu GUI | Trùng toàn bộ bytes với kết quả converter từ `test-min.exe` đã đối chiếu |
| `test.exe` cũ | EXE build kèm MinGW/UCRT, dùng để chẩn đoán | Có TLS template 8 byte, bị converter từ chối |

Các file mẫu là tài liệu thử bổ sung cho bộ công cụ. Tên `test.exe` cũ chỉ xuất hiện để giải thích lỗi trước đây. Đầu vào của lệnh chạy mẫu GUI là **`test-min.exe`**.

Cặp GUI đã đối chiếu có `SizeOfImage = 0x8000`, entry RVA `0x1000`, loader x64 dài `0x600`, nên `.shc` dài `0x8600 = 34.304` byte. Chưa có kết quả chạy runner trên Windows thật được xác nhận trong lần đối chiếu này. Phép kiểm tra toàn bộ bytes được mô tả ở mục 17 của [how_it_works.md](how_it_works.md).

## Lỗi thường gặp

| Thông báo / hiện tượng | Nguyên nhân và cách xử lý |
|---|---|
| `python` không được nhận diện | Kiểm tra Python/PATH hoặc thử `py -3` trên Windows |
| `File exists` | Đầu ra đã tồn tại; chọn tên khác bằng `-o` |
| `Already converted` | Bạn chọn lại `.shc`; hãy dùng EXE gốc |
| `Architecture mismatch` | Dùng runner x64 cho EXE x64, runner x86 cho EXE x86 |
| `undefined reference to 'WinMain'` khi `gcc test.c -o test` | Source dùng `entry()` nhưng lệnh build mặc định tìm điểm vào CRT. Dùng lệnh CMD `-nostdlib` và `-Wl,-e,entry` ở mục `MessageBoxA` phía trên |
| `EXE needs base relocations` hoặc `Expected EXE with relocations, not DLL` | Input thiếu relocation, bị strip relocation hoặc là DLL; cần input phù hợp, không chỉ đổi đuôi file |
| `.NET/CLR`, `Delay imports`, `Bound imports` | Input sử dụng tính năng chưa hỗ trợ |
| `Static TLS is unsupported` | EXE có TLS template, thường do CRT/toolchain liên kết vào. Với ví dụ nhỏ, dùng source `entry()` và lệnh build không CRT ở trên; không chỉ xóa điều kiện kiểm tra hay xóa `.tls` trong file cũ |
| `Expected a fresh EXE converted by pe2shc.py` | File không khớp output sạch của converter; chuyển đổi lại từ EXE gốc |
| `Entry returned -5; loader status=0` | Loader không load/resolve được import; kiểm tra DLL phụ thuộc và kiến trúc |
| Không có dòng `Entry returned` | EXE có thể tự kết thúc tiến trình, còn đang chạy hoặc đã crash; kiểm tra hành vi/exit code thực tế |

Các giới hạn layout hoặc lỗi PE khác được converter in cụ thể. Xem phân tích validator và mã trả về trong [how_it_works.md](how_it_works.md).

## Phạm vi hỗ trợ và kiểm thử

Bản này nhận **EXE native x86/x64** theo layout thông thường, có relocations, import theo tên/ordinal và có thể có TLS callbacks. Không nhận DLL, .NET, ARM, driver, static TLS, bound imports hoặc delay imports. Loader không tái tạo đầy đủ Windows loader, bảng unwind, startup và trạng thái tiến trình; vì vậy không bảo đảm chạy được mọi EXE dù đã chuyển đổi thành công.

Các fixture x86/x64 và mẫu console `demo.c` đã được kiểm tra bằng Unicorn với Windows API giả lập. Hai runner đã cross-compile thành công. Bộ kiểm tra phát triển và các fixture chưa được kèm trong gói Simple.

Với mẫu GUI `test.c` và cặp `test-min.exe`/`.shc` đã đối chiếu, kết quả xác nhận gồm metadata, luồng mã entry và sự trùng khớp toàn bộ output converter. **Chưa xác nhận việc chạy mẫu GUI bằng runner trên Windows thật.** Chi tiết và checksum nằm ở mục 17 của tài liệu nguyên lý.

