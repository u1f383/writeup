## Qemu

- Quick Emulator
- System mode / User mode
- Target arch 轉成 TCG-IR (frontend)，後半在轉成 host arch (backend)
- `TB` (translation block) - 翻譯後執行的最小執行單位
- `TCGContext` - **binary 轉化**過程中，儲存相關資料的結構
  - TCGPool - mem 相關
    - first: 第一個 pool
    - current: 使用哪個 pool
    - cur: pool addr 的當前
    - end: pool addr 的結尾
  - `tcg_malloc()`
    - tcg 一開始會 allocate 32K mem
    - 執行 `tcg_malloc` 來移動 ptr 作記憶體分配
  - ops, free_ops (struct `TCGOp`) - 存 TCG-IR
    - host binary --> TCG-IR
    - `ops` 存 `TCGOp` linked list
  - code_gen_buffer - 存產生的 host binary
  - `tb_find()` -> `tb_lookup()`
    - TB 存在 hash table
    - 先找 `cpu_rb_jmp_cache` (較小)
    - 在找 hash table
  - 找不到就 `gen_intermediate_code()` -> `translator_loop()`
    - `gen_tb_start()`: 建立 TB prologue
    - `ops->translate_insn()`: decode target instruction 成對應的 TCGIR
      - `decode_insn16()` / `decode_insn32()`
      - 把產生的 `TCGOP` 放到 `ops`
        - `DISAS_NORETURN`: 代表在 `TCGIR` 的最後一個
    - `gen_tb_end()`: 建立 TB epilogue
  - `tcg_gen_code()`
    - `tb.tc_ptr`: 指向 code gen buffer 的某個地方，儲存目前寫入的 `TCGIR`
    - `tcg_out()`: 產生對應的 host instruction
    - `CPURISCVState` 存 register 的狀況
  - TB (target instruction code bb) ---> TCG-IR ---> 優化的 TCG-IR ---> ops 轉換成 host instruction code
  - TB 前後會有 prologue / epilogue 作檢測
  - `cpu_loop_exec_rb()` ---> `cpu_tb_exec()`
    - `jmp rsi` 直接到 host instruction code，host instruction code 的 epilogue 會再回去
  - Block chaining
    - 增加 performance
    - 將相連的 TB 連在一起，下次就可以直接跑 (固定的執行流程)
      - 把上一個跟當前的，透過 patch 上個 TB epilogue 的 `jmp` 成 當前的 TB
  - helper function: 為 `hook`，提供 user 自定義模擬的行為
    - 可以用在 `syscall` - `helper_raise_exception()`



### tiamat

`./qemooo ./liccheck.bin`

- `qemooo` 為 customized qemu
- `SPARC` 會有特別的 handle 方式
- `syscall number` 會對不同的 arch 加上的 offset
- 用 capstone 來 disasm
- `r15`: 存 4 byte random number
- `r29`: ptr to input license
- option:
  - j: login
    - rewrite `j`
  - e: input license
  - l: show content 1.mz ~ f.mz
  - n: 更新 `r15`，使用 0x18 次
    - fd 存 `r[0]`
    - wrong syscall number (根本就不會 `close`)
  - p: print license (`r29`)
    - bug1. leak xor libc
  - r: 回 menu
  - v: flag xor license
    - open 後沒 close
- 條件
  - `r15` 4 bytes
  - `xor /lic` known
  - md5sum 為 `0~f`



### TCG and the Unicorn

- `find_fast`
  - id: pc、cs_base、flags
- `find_slow`
  - id: pc、 phys_page1、cs_base、flags、phys_page2
- `not_found`
  - `tb_gen_code`
    - `gen_opc_buf`
    - `gen_opparam_buf`
  - enforce `UC_PROT_EXEC` flag
- `mov dptr [rdi], rax` (`\x89\x07`)
  - 抓 op code，parse size
  - parse op
  - 從原本的 op gen IR (`gen_ldst_modrm`)
  - `gen_lea_modrm`: parse address
  - `gewn_op_mov_v_reg`: mov registers
  - `tcg_gen_qemu_st_i64`: store regsister reg、IR
    - `check_exit_request`
  - switch 前沒有檢查 `UC_PROT_EXEC`
    - 只在不同的 inst 個別檢查
    - `cpu_ldq_code()`
      - 比較 page permission
- `TCG` - IR gen code
  - tmp slot
    - 前五個跟環境有關
    - 後面是 register
  - `TCG_optimize`
    - constant folding to IR
    - reorder argument
    - simplify expression
  - `tcp_liveness`
    - 把 opcode 標記成 dead (找不到 output operation)
    - 不會更新 opcode
- target host - r14 存 env、rsp 存 stack
- `tcg_reg_alloc_op`
  - assign input/output arg
  - parse & emit inst (轉成 asm)
  - sync output arg (output 順序/位置)
  - `env` 代表 state
- branch
  - 有 TAG 就填 TAG
  - 沒有就放 placeholder，之後在 resolve
- `st_i64`
  - 1: load iargs
  - 2: emit inst
    - env 的 local buffer
  - `st_direct`
- `set label`
  - TB 一次會處理一個 BB
  - label 永遠在 BB 的最下面
  - `tcg_out_label` patch
- miss cache ?
  - gen help function
- flush instruction cache
  - `icache`
- `gen_intermediate`: 會把太長的 BB 拆開
  - 但是在 qemu 中透過 prefix 可以讓 instruction 是無限長
  - hidden code from tcg (執行到應該被蓋掉的 code)
    - `uc_goood` 0CTF



#### CVE-2020-8871

- Parallel Desktop
- fixed in 15.1.3
- 載 End-of-Life version
- 買 SSD 灌 Catalina
  - avoid big sur



Entitlement

- SIP (System Integrity Protection)
- get-task-allow



Debugging

- get-task-allow
  - `ptrace()`
  - A 可以 control B
- disable SIP
  - DEFCON CTF 2018 IPwnKit
  - 可以做 `DYLD_*` (dll hijacking, LD_PRELOAD)

PD

- Client: `prl_client_app`
- VM: `prl_vm_app`
- Library: libMonitor.dylib (ring 3?)
  - monitor64

VGA

- Video Memory 4 planes of 64k
- sequencer - 將 video 轉成 color index
- DAC
- case 95-99 為 VGA 本身的 operation
  - 0-1X 為 PD 自己的
- 64MB 可以由 PD 設定
  - memory layout
  - double fetch
- 可以參考有 VGA 的相關 source code (qemu)
- `struct VGAContext` 儲存 VGA status
  - `struct VGAState`
    - a shared memory
- 可以先研究 VirtualBox



0CTF - `uc_masteeer`

bindiff


