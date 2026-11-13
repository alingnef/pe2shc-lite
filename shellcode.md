# Shellcode
Về cơ bản thì shellcode là một đoạn mã máy rất nhỏ được thiết kế để CPU có thể thực thi một cách trực tiếp, thường được viết bằng Assembly rồi được biên dịch thành các byte opcode. Tên “shellcode” xuất phát từ việc shellcode cổ điển thường dùng để mở một command shell như /bin/sh, nhưng ngày nay shellcode không nhất thiết phải tạo shell. Nó có thể làm bất kỳ việc gì mà mã máy có thể làm, ví dụ gọi syscall, đọc/ghi dữ liệu, thoát chương trình, hoặc chạy một đoạn logic nhỏ.

Ví dụ:
```asm
mov rax, 60
mov rdi, 0
syscall
```

Khi compile thành machine code (mã máy) thì ta có thể nhận một chuỗi byte như này:
```
B8 3C 00 00 00          mov     eax, 60
BF 00 00 00 00          mov     edi, 0          ; error_code
0F 05                   syscall                 ; LINUX - sys_exit
```

Ta có thể hình dung quá trình đó có dạng là:
```
Assembly
   ↓
Assembler (NASM)
   ↓
Machine code / opcode
   ↓
Shellcode bytes
   ↓
CPU thực thi
```
Tuy nhiên, shellcode thực tế thường có một số đặc điểm đặc biệt. Nó thường nhỏ, ít phụ thuộc vào thư viện, gọi syscall trực tiếp và thường cố gắng position-independent, nghĩa là có thể chạy dù được đặt ở địa chỉ bộ nhớ nào.

Điểm quan trọng nữa là phân biệt khi ta có một file source assembly chẳng hạn như `main.asm` và trình biên dịch nó thành file Object dạng `main.o` và cuối cùng tạo thành file executable như `.exe` hay elf thì bản thân các file đó không phải shellcode. Chúng chứa header, section, metadata, relocation… Trong khi shellcode thường chỉ cần phần mã máy cần thiết để CPU chạy.

Thế cho nên, khi thực hiện khai thác thì shellcode thường xuất hiện theo mô hình:
```
Bug của chương trình
        ↓
ghi dữ liệu vào memory
        ↓
đưa shellcode vào memory
        ↓
điều khiển RIP/EIP
        ↓
RIP → địa chỉ shellcode
        ↓
CPU chạy shellcode
```

Chẳng hạn:
```
Stack
──────────────────────────
0x7fffffffe000   shellcode
0x7fffffffe008   shellcode
0x7fffffffe010   shellcode
...
──────────────────────────

RIP = 0x7fffffffe000
          │
          └──→ CPU bắt đầu chạy shellcode
```

# Một vài shellcode cơ bản cho người mới học
## Exit(0)
Cho đoạn mã Assembly sau:
```asm
section .text
    global _start

_start:
    mov rax, 60
    mov rdi, 0
    syscall
```

Khi thực hiện `syscall`, quyền điều khiển bây giờ sẽ chuyển từ user-mode sang cho kernel. Khi này, hệ thống sẽ kiểm tra xem syscall number hiện tại đang có trong thanh ghi RAX và đối chiếu với danh sách syscall number đối với kiến trúc x86_64 để thực thi lệnh dựa trên syscall number đó. Thực ra thì nó sẽ là CPU thực hiện cơ chế SYSCALL của x86-64 để chuyển sang kernel mode và nhảy tới syscall entry point mà kernel đã cấu hình trước. Như trong ví dụ trên thì `RAX = 60`, và 60 trong syscall x86_64 sẽ là lệnh `exit`. Cùng với đó là `RDI = 0` đóng vai trò làm tham số đầu tiên truyền vào exit, tức nó sẽ là `exit(0)`. Vì vậy, đoạn mã assembly ở trên thực chất là đang thực hiện `exit(0)`, hay như trong C thì nó sẽ có dạng kiểu như:
```c
#include <stdio.h>
int main()
{
    return 0;
}
```

Về phần argument của syscall number thì theo Linux x86-64 syscall ABI, các argument được truyền theo thứ tự:

| arch   | syscall NR | return | arg0 | arg1 | arg2 | arg3 | arg4 | arg5 |
|--------|------------|--------|------|------|------|------|------|------|
| arm    | r7         | r0     | r0   | r1   | r2   | r3   | r4   | r5   |
| arm64  | x8         | x0     | x0   | x1   | x2   | x3   | x4   | x5   |
| x86    | eax        | eax    | ebx  | ecx  | edx  | esi  | edi  | ebp  |
| x86_64 | rax        | rax    | rdi  | rsi  | rdx  | r10  | r8   | r9   |


Nhưng đó chưa phải là tất cả. Mục tiêu của chúng ta là sẽ tạo ra một shellcode bằng cách biên dịch từ mã Assembly thành các opcode, để rồi từ đó có thể dùng chúng để thực thi một cách trực tiếp.

Ví dụ như trên khi ta muốn có một shellcode thực hiện việc `exit(0)` thì ta có mã Assembly đơn giản như sau:
```asm
; main.asm
section .text
    global _start

_start:
    mov rax, 60
    mov rdi, 0
    syscall
```

Thực hiện biên dịch bằng Makefile có nội dung là:
```make
make:
	nasm -f elf64 main.asm -o main.o
	ld main.o -o main

clean:
	rm -f main.o main
```
Khi này, ta sẽ nhận được hai file là file thực thi `main` và file object `main.o`. Dump nội dung từ file object này ra, ta thu được:
```
(sage) aling@DESKTOP-KNONVD9:/mnt/d/Computing 101/Assembly$ objdump -d main

main:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <_start>:
  401000:       b8 3c 00 00 00          mov    $0x3c,%eax
  401005:       bf 00 00 00 00          mov    $0x0,%edi
  40100a:       0f 05                   syscall
```

Các giá trị hex rời rạc kia chính là các opcode mà ta cần tìm. Lấy các opcode ta nhận được 1 shellcode như sau:
```
\xb8\x3c\x00\x00\x00\xbf\x00\x00\x00\x00\x0f\x05
```

Để kiểm tra xem shellcode có chạy không, ta có thể viết 1 file c như sau:
```c

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

unsigned char shellcode[] =
    "\xb8\x3c\x00\x00\x00"
    "\xbf\x00\x00\x00\x00"
    "\x0f\x05";

int main(void)
{
    size_t len = sizeof(shellcode) - 1;

    void *mem = mmap(NULL, len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    memcpy(mem, shellcode, len);

    if (mprotect(mem, len, PROT_READ | PROT_EXEC) == -1) {
        perror("mprotect");
        munmap(mem, len);
        return 1;
    }

    ((void (*)(void))mem)();

    munmap(mem, len);
    return 0;
}
```



## /bin/sh
Tiếp đến là một trường hợp rất quen thuộc cũng như đây chính là lý do tại sao chúng ta gọi nó là shellcode. Đó chính là việc mở một command shell như /bin/sh. Cũng giống như trên, trước hết ta có một đoạn mã Assembly cho việc tạo shell trên Linux như sau:
```asm
section .text
    global _start

_start:
    xor rdx, rdx
    push rdx                    ; NULL terminator

    mov rbx, 0x68732f2f6e69622f
    push rbx                    ; "/bin//sh"

    mov rdi, rsp                ; filename

    push rdx                    ; argv[1] = NULL
    push rdi                    ; argv[0] = filename
    mov rsi, rsp                ; argv

    mov rax, 59                 ; execve
    syscall
```

Khi compile, ta sẽ thu được một file thực thi và file object, dump file object đó ra ta có:
```
(sage) aling@DESKTOP-KNONVD9:/mnt/d/Computing 101/Assembly$ objdump -d main

main:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <_start>:
  401000:       48 31 d2                xor    %rdx,%rdx
  401003:       52                      push   %rdx
  401004:       48 bb 2f 62 69 6e 2f    movabs $0x68732f2f6e69622f,%rbx
  40100b:       2f 73 68 
  40100e:       53                      push   %rbx
  40100f:       48 89 e7                mov    %rsp,%rdi
  401012:       52                      push   %rdx
  401013:       57                      push   %rdi
  401014:       48 89 e6                mov    %rsp,%rsi
  401017:       b8 3b 00 00 00          mov    $0x3b,%eax
  40101c:       0f 05                   syscall
```

Shellcode của chúng ta là:
```
"\x48\x31\xd2\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\xb8\x3b\x00\x00\x00\x0f\x05"
```

Chạy thử trên C, ta có:
```c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

unsigned char shellcode[] =
    "\x48\x31\xd2\x52\x48\xbb\x2f\x62\x69\x6e"
    "\x2f\x2f\x73\x68\x53\x48\x89\xe7\x52\x57"
    "\x48\x89\xe6\xb8\x3b\x00\x00\x00\x0f\x05";

int main(void)
{
    size_t len = sizeof(shellcode) - 1;

    void *mem = mmap(NULL, len,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);

    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    memcpy(mem, shellcode, len);

    if (mprotect(mem, len, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect");
        munmap(mem, len);
        return 1;
    }

    printf("Shellcode: %zu bytes\n", len);
    fflush(stdout);

    void (*execute)(void) = (void (*)(void))mem;
    execute();

    munmap(mem, len);
    return 0;
}
```

Kết quả:
```
(sage) aling@DESKTOP-KNONVD9:/mnt/d/Computing 101/WinAPI$ gcc test.c -o test
(sage) aling@DESKTOP-KNONVD9:/mnt/d/Computing 101/WinAPI$ ./test
Shellcode: 30 bytes
$ ls
Theory.md  images  process.zip  test  test.c  test.exe  test.exe.i64
$ 
```