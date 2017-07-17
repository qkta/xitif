Who are you
================
Binary được nén với UPX.     
Load vào x64dbg, sau khi dừng tại Entry Point của chương trình, step qua các instruction push thanh ghi vào stack, đặt một hardware 
breakpoint tại `rsp` và continue (`F9`). Chương trình dừng tại các lệnh pop stack (triggered hw bp).   
Tại đây quá trình unpack đã hoàn thành, tìm kiếm các string và reference đến hàm main của chương trình:   
![main function](https://nightst0rm.net/wp-content/uploads/2017/07/main_func.png)
Hàm `main` đọc 8 bytes từ input và lưu vào thanh ghi `rcx` (là đối số duy nhất của hàm `check_flag`)   
Hàm `check_flag` thực hiện các phép tính đơn giản bao gồm `sub`, `add`, `xor`, `rol`, `ror` đối với giá trị input, flow được điều khiển 
bởi các lệnh `jump`.      
Ý tưởng: sử dụng scripting để ghi lại các instruction đã thực thi, bỏ qua các lệnh `jump`     
Sử dụng IDApython (IDA Pro)   
```python
disas = [GetDisasm(ScreenEA())]
while 1:
    StepOver()
    GetDebuggerEvent(WFNE_SUSP, -1)a
    ea = ScreenEA()
    mnem = GetMnem(ea)
    if mnem.startswith("ret"):
        print "End of flag_check()"
        break
    if not mnem.startswith("j"):
        disas.append(GetDisasm(ea))
 ```
 Kết quả:
 ```asm
rol     rbx, 0x0A7
mov     rax, 0x0DDF9FB1EEEA42D00
sub     rbx, rax
rol     rbx, 0x22
mov     rax, 0x3D351578B4AD3395
add     rbx, rax
...
mov     rax, 0x18CBB7849EF17CC2
sub     rax, rbx
ret
```
Nhận xét:
* Kết quả trả về của hàm này phải bằng 0 (xem lại hàm main), có nghĩa là sau quá trình tính toán trên, giá trị input phải bằng
`0x18CBB7849EF17CC2`
* Các phép toán thực hiện chỉ bao gồm 2 thanh ghi `rax` và `rbx` (input)
* Các phép tính đều có thể inverse   

Có thể tính-toán-ngược để tìm lại giá trị input phù hợp:
* Đảo ngược thứ tự thực hiện các instructions
* `ror` -> `rol`
* `rol` -> `ror`
* `add` -> `sub`
* `sub` -> `add`
* Đảo ngược thứ tự của instruction `mov rax, ...` và instruction liền kề trước nó (sau khi đã đảo 1 lần nói trên)

Sử dụng [Keystone engine](http://www.keystone-engine.org/) và [Unicorn engine](http://www.unicorn-engine.org) để thực thi các 
instructions, cờ nhận được là `MeePwnCTF{f4k3f4k3}`. Tuy nhiên cờ không được chấp nhận, thử nhập lại key 
`f4k3f4k3` thì vẫn nhận được thông báo `nope! Go and find yourself :(` (hóa là là fake thật) -> Anti debug.     
Hàm `main` của chương trình bắt đầu tại địa chỉ `0x140001230`, để kiểm tra quá trình code modify của chương trình, mình sẽ 
đặt một hardware breakpoint tại đây và run lại chương trình. Sau khi break (packer bắt đầu ghi hàm main lên memory), chuyển qua Graph
View của debugger, có thể dễ dàng nhận ra trick antidebug của tác giả ngay sau vòng lặp này:     
![Anti debug](https://nightst0rm.net/wp-content/uploads/2017/07/anti_debug.png)     
Trick quen thuộc: tác giả kiểm tra cờ `BeingDebugged` trong PEB, nếu giá trị này bằng 0 (nghĩa là chương trình đang-không-bị-debug) thì
thực hiện ghi vào memory tại địa chỉ `0x1400061B3` giá trị `0x6BA8F103D6E0FF17` ghi đè lên giá trị `0x18CBB7849EF17CC2` ở trên.      
 Thực hiện chạy lại script với giá trị `rbx` mới để nhận được flag: `MeePwnCTF{uNp4ck3r}`     
 Script:
 ```python
 from keystone import *
from unicorn import *
from unicorn.x86_const import *

ADDR = 0x400000

def solve_asm(d):
    for i in xrange(1, len(d)):
        expr = d[i]
        if expr.startswith("add"):
            expr = expr.replace("add", "sub")
        elif expr.startswith("sub"):
            expr = expr.replace("sub", "add")
        elif expr.startswith("rol"):
            expr = expr.replace("rol", "ror")
        elif expr.startswith("ror"):
            expr = expr.replace("ror", "rol")
        elif not (expr.startswith("mov") or not expr.startswith("xor")):
            # print expr
            pass
        d[i] = expr
        if expr.startswith("mov"):
            d[i], d[i-1] = d[i-1], d[i]

RunTo(0x140001265)
GetDebuggerEvent(WFNE_SUSP, -1)
StepInto()
GetDebuggerEvent(WFNE_SUSP, -1)
d = []
while 1:
    StepOver()
    GetDebuggerEvent(WFNE_SUSP, -1)
    ea = ScreenEA()
    mnem = GetMnem(ea)
    if mnem.startswith("ret"):
        break
    if not mnem.startswith("j"):
        d.append(GetDisasm(ea))
# Anti-anti-debug
d[-2:] = ["mov  rbx, 6BA8F103D6E0FF17h"]
d.reverse()
solve_asm(d)
ks = Ks(KS_ARCH_X86, KS_MODE_64)
code = ""
for i in xrange(len(d)):
	encoding, count = ks.asm(d[i])
	code += "".join([chr(x) for x in encoding])
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(ADDR, 1024 * 1024)
mu.mem_write(ADDR, code)
mu.emu_start(ADDR, ADDR + len(code))
rbx = mu.reg_read(UC_X86_REG_RBX)
print "Flag is: MeePwnCTF{{{}}}".format(hex(rbx)[2:].replace("L", "").decode("hex")[::-1])
 ```
