## Browser



#### Reference

- [JS pipeline](https://mathiasbynens.be/notes/shapes-ics)
- [JS optimization](https://mathiasbynens.be/notes/prototypes#tradeoffs)



---



Browser - interpreter + optimizing compiler:

- V8 - the JavaScript engine used in Chrome and Node.js
- Ignition - interpreter of V8, responsible for generating and executing bytecode
- TurboFan - optimizing compiler of V8
- SpiderMonkey -Mozilla’s JavaScript engine as used in Firefox and in SpiderNode
- Chakra - Microsoft’s JavaScript engine as used in Edge and Node-ChakraCore
  - SimpleJIT - Just-In-Time compiler
  - FullJIT - produce **more-heavily-optimized** code
- JavaScriptCore (JSC) - Apple’s JavaScript engine as used in Safari and React Native
  - LLInt - the Low-Level Interpreter
  - DFG (Data Flow Graph)
  - FTL (Faster Than Light)
- optimizer 的個數為 trade-off
  - quickly getting code to run (interpreter) (直接跑 bytecode)
  - taking some more time, but eventually running the code with optimal performance (optimizing compiler) (等待優化完在執行)
- Sparkplug  -  V8's additional compiler added in Chrome 91 (released in 2021), between the **Ignition interpreter** and the **TurboFan optimizing** compiler.



JS object

- Dict
- 4 base properties
  - `[[value]]`
  - `[[writable]]` - 是否可以 reassigned
  - `[[enumeratble]]` - 是否可以用 `for-in` loop traverse
  - `[[configurable]]` - propterty 是否可以 delete
- array 可以想成是比較特別的 object，first element 是 array length
  - **array index** (size) (`2**32-2 ~ 0`)
    - writable - true
    - enumerable - false
    - configurable - false

JS `{Shapes,HiddenClasses,Maps,Types,Structures}`

- JS 節省 memory 的機制
- `Shape` 包含 property + attribute，不過沒有 `[[value]]`，反而多了 `[[offset]]` 代表在 object 中的位置
- 由多個 `Shape` 會組成 transition chains
  - 但在沒辦法建立 transition chains 時 (object 不重複)，會變成 transition tree
- 每個 `Shape` 會指向前一個 `Shape`，而在 `Shape` 在新增 property 時只需要看過去有沒有已經存在的 `Shape`，如果有的話直接用就好
- 不同的 properties order 代表不同的 Shape
- 最後由於 transition chains 耗 O(n) 去找特定的 element，因此有 `ShapeTable`，也是以 Dict 的形式存在

Inline Caches (ICs)

- **memorize information** on **where to find properties on objects**, to reduce the number of expensive lookups

JSArray

- 會有 elements backing store 來儲存 array-indexed property



當 code 常常被執行 (hot)，各個 JS engine 的 optimizer 就會優化 interpreter 產生出來的 bytecode，產生優化過的 machine code

- 即使 bytecode 的 instruction 個數比 machine code 來的少，但是執行時間差很多 (machine code 快於 bytecode)
- 不過 optimized machine code 與需要的 memory 成正比

JS engine optimize

- instead of storing the **prototype link** on the instance itself, engines store it on the **Shape**
- ValidityCell
  - prototype shapes 的一個 property
  - invalidated whenever someone **changes the associated prototype** or any prototype above it. Let’s take a look at how this works exactly
- IC 有四個屬性，用來記錄某個 property
  - ValidityCell
  - Prototype
  - Shape
  - Offset
- when Inline Cache is hit, the engine has to **check the shape of the instance** and the **ValidityCell**
  - valid - 直接用 offset + Prototype 存取
  - invalid - 代表 `Shape` 更新，需要重新尋找正確地 `Shape`，所以此次執行會變慢



### Environment

[V8 google git](https://chromium.googlesource.com/v8/v8.git/+/HEAD/)

- `depot_tools` - Chromium and Chromium OS use a package of scripts called **depot_tools** to **manage checkouts and code reviews**

  - [man](http://commondatastorage.googleapis.com/chrome-infra-docs/flat/depot_tools/docs/html/depot_tools_tutorial.html)

- `ninja

- `gclient` - Meta-checkout tool managing both subversion and git checkouts. It is similar to repo tool except that it works on Linux, OS X, and Windows and supports both svn and git. On the other hand, gclient doesn't integrate any code review functionality.

  ```bash
  git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
  echo "export PATH=/home/u1f383/depot_tools:$PATH" >> ~/.zshrc
  ```

- 抓 v8 (參考[文件](https://chromium.googlesource.com/external/github.com/v8/v8.wiki/+/8c0be5e888bda68437f15e2ea9e317fd6229a5e3/Building-with-GN.md))

  ```bash
  fetch v8
  
  #### output ####
  Running: gclient root
  Running: gclient config --spec 'solutions = [
    {
      "name": "v8",
      "url": "https://chromium.googlesource.com/v8/v8.git",
      "deps_file": "DEPS",
      "managed": False,
      "custom_deps": {},
    },
  ]
  Running: gclient sync --with_branch_heads
  # 以上如果沒有自動跑，就手動執行
  
  #### done ####
  # 執行完後，應該會有 .gclient 以及 v8/
  cd v8 && git pull && gclient sync && ./build/install-build-deps.sh
  tools/dev/gm.py x64.release
  # tools/dev/v8gen.py x64.optdebug (for debug version)
  ```

  在第一次執行 `fetch` 時會花超久的時間

- `d8` - V8’s own **developer shell**

- `gm` - all-in-one script

  - `gm x64.release`
  - `./tools/dev/gm.py x64.release d8`
  - `./out/x64.release/d8`

- 編譯 d8

  - 使用 `v8gen.py` (convenience script to generate your build files)
    - `ninja` 是用來編譯的工具
    - `v8gen.py` 與 `gm.py` 都是用來產生 build files 的工具
    - `tools/dev/v8gen.py x64.debug` + `ninja -C out.gn/x64.debug`
    - `tools/dev/v8gen.py x64.optdebug` + `ninja -C out.gn/x64.optdebug`
    - `tools/dev/v8gen.py x64.release` +  `ninja -C out.gn/x64.release` or `ninja -C out.gn/x64.release d8` (specific target)
  - 生成路徑: `out.gn/x64.optdebug`
    - `export PATH=/home/u1f383/v8/v8/out.gn/x64.optdebug:$PATH`
    - `d8` 本身只能在 `/home/u1f383/v8/v8/out.gn/x64.optdebug` 執行，或是使用絕對路徑，因此可以改成用 `alias d8="/home/u1f383/v8/v8/out.gn/x64.optdebug/d8"`



#### v8 使用文件

[參考](https://gist.github.com/kevincennis/0cd2138c78a07412ef21)

- `d8` == `v8` develop shell

- `d8 --trace-opt-verbose test.js`: trace optimized compilation

- `d8 --trace-opt --trace-deopt test.js`

  - `--trace-opt`: trace optimized compilation
  - `--trace-deopt`: trace deoptimization

- `time d8 --prof test.js`: Log statistical profiling information (implies --log-code)

  - 產生 `v8.log`

- `d8 --trace-turbo-inlining test.js`: trace TurboFan inlining

- `d8 --trace-gc test.js`: trace garbage collection

  - 當某個儲存 object 的記憶體空間滿了，之後在新增 object 時，就會觸發 gc (scavenge)

- `d8 --help` - help logs all available d8 flags

- In shell (直接執行 `d8 [opts]`，不接檔案)

  - `%DebugPrint()`
    - `runtime functions` that you can call from JavaScript using the `%` prefix
    - 如果沒有加上 `--allow-natives-syntax` 就不能使用 `%`
  - `src/runtime` 中，有 `RUNTIME_FUNCTION` 的就是 runtime function

- `Turbolizer`:  a tool that we are going to use to debug TurboFan's sea of nodes graph

  ```bash
  cd tools/turbolizer
  npm i
  npm run-script build
  python -m SimpleHTTPServer
  ```

  之後執行 `d8 --trace-turbo <FILE>` 會產生 `.cfg` 以及 `.json`，可以餵 `.json` 給 `turbolizer` 來顯示 control graph

  - `--trace-turbo`: trace generated TurboFan IR

- `%DisassembleFunction`: disasm 指定的 function



### introduction-to-turbofan

[RT 參考文章](https://doar-e.github.io/blog/2019/01/28/introduction-to-turbofan/)

- `deoptimization` (或被稱作 `bailout`): 由於程式流程跟優化過的程式碼不一樣，所以必須 destroy 掉舊的 bytecode (or machine code)
  - 用 `--trace-opt` + `--trace-deopt` 來觀察
- `TurboFan` works on a program representation called a **sea of nodes**
  - node 代表 arithmetic op、load、store、call、constant 等等
  - edge 有三種:
    - control edge: find in CFG, branches and loops
    - value edge: find in DFG, value dependencies
    - effect edge: order operations such as reading or writing states
- `V8 Torque` - language that allows developers contributing to the V8 project to express changes in the VM by **focusing on the intent of their changes to the VM**, rather than preoccupying themselves with unrelated implementation details
  - **TypeScript** - like syntax that eases both writing and understanding V8 code with syntax and types that reflects concepts that are already common in the **CodeStubAssembler**
  - 在 `src/builtins` 有許多 `.tq` 為副檔名的檔案
  - `torque` compiler 在 `src/torque`



#### Modern attacks on the Chrome browser : optimizations and deoptimizations

[RT 參考文章](https://doar-e.github.io/blog/2020/11/17/modern-attacks-on-the-chrome-browser-optimizations-and-deoptimizations/)

- Ignition - interpreter
  - uses TurboFan's macro-assembler
  - architecture-independent
  - register machine - opcode's inputs and output are using only registers
- TurboFan  - need to compile those instruction to target architecture

#### V8

- `isolate` - 4GB 空間
- 透過 `Handle` 來幫你改變 pointer，存取 object
  - [GC](https://v8.dev/blog/trash-talk)
- `Context` - 建立一個新的執行環境
  - 不同 JS script 有不同的執行環境



TurboFan IR

- Graph based
- operation
  - JSAdd (JavaScript level)
  - NumberAdd (Intermediate level (Simplified))
  - Int32Add (Machine level)
- high level ---- lowering ----> low level
- SimplifiedLoweringPhrase



memory allocation

- small integer (smi, int31) or pointer
- 若是 pointer，則最後 bit 1
- `Map` 描述 object 結構



CVE 2020-16040

- code review 的彭台
- VisitSpeculativeIntegerAdditiveOp
  - 將 `Signed32()` 改成 `restriction`
- Regression test == POC
- bitwise or `|` 會將兩側當作 int

Lowering

- `propagate`: 從後面 (end) 往前傳遞 tuncation，透過標記新的 type 來截斷不必要的 range
  - `set_restriction_type`
- `retype`: 往前 (start) 傳遞更新 type
  - `RetypeNode()`
  - `UpdateFeedbackType`
    - 限制 type (`Signed32()`)
- `lower`: 將 node lowering 成 machine code
- CFG 要怎麼 merge 不同的 type
  - phi --> 代表原本的 type 的其中一個
- `NaN` 要 bypass 第一階段的 if
- `y = -1` 要讓我們進去 `DCHECK`



exploit flow

- oob r/w

- 想辦法建立出長度 -1 的 array:
  - `array.shift()`
    - 前幾個月被 patch 了
    - `new Array(i)`
    - `arr.shift()`
    - `TFInlining` -> `TFLoadElimination`
      - `checksedLen` == `[0,0]`
      - `range(0,0)`，但實際為 1
- primitives
  - addrof / fakeobj
  - 透過 array + object pointer 來 leak
  - 為什麼可以改成 pointer ?
- more power primitives
  - array 自己控
  - 任意讀任意寫
- allocate rwx page
  - wasm load module，得到 rwx page
  - how to leak address
- copy sc
- jmp sc



目標為 optimizer 跟 static 分析不一樣

CheckBound elimination



`isolate` 只會存 offset，只有 32 bit (pointer)

- `ArrayBuffer` 在 V8 中是用 `klloc`，拿到的是 `Isolate` 外的
- `backing_store`



`DebugPrint` + `SystemBreak`

array size == -1    ===>    任意寫

gdb `job`



render - 由於要執行 untrusted code，因此是 sandboxing

- handle HTML, execute javascript, decode image,...
- renderers use the `Blink` open-source layout engine for interpreting and laying out HTML

plugin - 由於是 third-party code，因此也要 sandboxing

browser - **trusted**，基本上只有 browser 是 unsandboxed

- UI, networking

Mojo - new IPC mechanism

- IDL-based (Interactive Data Language)
- browser <---> renderer
- 所以在 browser 以及 renderer 都有 Mojo API

Turbofan - the JIT compiler inside v8

Future

- microservice architecture - well-defined API, reusable

```
[0] --> map pointer
[1] --> out-of-line properties
[2] --> the pointer to its elements
[3,4] --> inline properties
```



`d8 --allow-natives-syntax`:

```javascript
%DebugPrint
```

- [chromium source code](https://source.chromium.org/chromium/chromium/src)

`math.cosh(1)` as breakpoint

- `b v8::base::ieee754::cosh`
- `i b` (`info breakpoint`)
- 如果 gdb 中沒有印出東西，可以用 `> file` 解決
- 可以設 magic number，並用 `find` 找

mem structure of object in V8.js

- object type

  - smi (small integer (32 bits))

    - 直接存在 memory
    - 32 bits + 32 bits (0)

  - heap object (pointer (64 bits))

    - heap number / string

    - 不是 `malloc()` 的 heap

    - 63 bits address + 1 bit tag

    - heap number

      - 指向:

        ```
        [0] --> map offset (8 bytes)
        [1] --> value of heap number
        ```

    - string

      - 指向:

        ```
        [0] --> kmap offset (8 bytes)
        [1] --> khash offset (8 bytes)
        [2] --> string
        ```

        



```
[0] --> shape pointer (map offset)
[1] --> length of object
```



GC judges pointers and non-pointers

- accurate GC - pointer tagging

  - tag bits

    - signal either strong/weak pointers to objects located in V8 heap, or a small integer

    - the value of an integer can be stored directly in the tagged value, without having to allocate additional storage for it

    - ```
                  |----- 32 bits -----|----- 32 bits -----|
      Pointer:    |________base_______|______offset_____w1|
      Smi:        |sssssssssssssssssss|____int31_value___0|
      
                          |----- 32 bits -----|----- 32 bits -----|
      Compressed pointer:                     |______offset_____w1|
      Compressed Smi:                         |____int31_value___0|
      ```

      - `w` is a bit used for distinguishing strong pointers from the weak ones
      - `s` is the sign value of the Smi payload
      - V8 always allocates objects in the heap at `word-aligned` (4 bytes, `address % 4 == 0`) addresses

    - Decompress

      - v1 (base 0)

        ```c
        uint32_t compressed_tagged;
        
        uint64_t uncompressed_tagged;
        if (compressed_tagged & 1) {
          // pointer case
          uncompressed_tagged = base + uint64_t(compressed_tagged);
        } else {
          // Smi case
          uncompressed_tagged = int64_t(compressed_tagged);
        }
        ```

        - need to distinguish between **sign-extending the Smi** and **zero-extending the pointer**

      - v2 (put the base in the middle (2GB))

        ```c
        int32_t compressed_tagged;
        
        // Same code for both pointer and Smi cases
        int64_t sign_extended_tagged = int64_t(compressed_tagged);
        int64_t selector_mask = -(sign_extended_tagged & 1);
        // Mask is 0 in case of Smi or all 1s in case of pointer
        int64_t uncompressed_tagged =
            sign_extended_tagged + (base & selector_mask);
        ```

        

```c
d8> %DebugPrint(a)
DebugPrint: 0x206308109475: [JS_OBJECT_TYPE]
 - map: 0x2063082c78c1 <Map(HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x2063082841f5 <Object map = 0x2063082c21b9>
 - elements: 0x20630800222d <FixedArray[0]> [HOLEY_ELEMENTS]
 - properties: 0x20630800222d <FixedArray[0]>
 - All own properties (excluding elements): {
    0x206308292f21: [String] in OldSpace: #bbbb: 0x2063081094a5 <HeapNumber 3735928559.0> (const data field 0), location: in-object
 }
0x2063082c78c1: [Map]
 - type: JS_OBJECT_TYPE
 - instance size: 16
 - inobject properties: 1
 - elements kind: HOLEY_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - stable_map
 - back pointer: 0x2063082c7899 <Map(HOLEY_ELEMENTS)>
 - prototype_validity cell: 0x206308202405 <Cell value= 1>
 - instance descriptors (own) #1: 0x206308109485 <DescriptorArray[1]>
 - prototype: 0x2063082841f5 <Object map = 0x2063082c21b9>
 - constructor: 0x206308283e2d <JSFunction Object (sfi = 0x206308209071)>
 - dependent code: 0x2063080021b9 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0
```



### Multi-process Architecture

render

- https://www.chromium.org/developers/design-documents/multi-process-architecture
- `RenderProcess` object that manages communication with the parent browser process and maintains global state
  - browser maintains a corresponding `RenderProcessHost` for each render process
    - manages browser state and communication for the renderer
    - browser and the renderers communicate using Chromium's IPC system (Mojo)
- Each **render process** has one or more `RenderView` objects, managed by the `RenderProcess`, which correspond to tabs of content
  - (browser) `RenderProcessHost` maintains a `RenderViewHost` corresponding to each view in the renderer
- Each view is given a **view ID** that is used to differentiate **multiple views in the same renderer**
- IDs are unique inside one renderer but not **within the browser**, so identifying a view requires a `RenderProcessHost` and a **view ID**
  - 對 renderer 是 unique，但對 browser 來說不是，因此 browser 要辨識時需要 render + ID 兩項資訊
- Communication from the browser to a specific tab of content is done through these `RenderViewHost` objects, which know how to send messages through their `RenderProcessHost` to the `RenderProcess` and on to the `RenderView`
  - (Host suffix 是 browser 所擁有的)
  - (browser) `RenderViewHost` (a web page) ---> `RenderProcessHost` ---> (IPC) --->
  - (renderer) `RenderProcess` ---> `RenderView`
    - `RenderProcess` (renderer) <---> `RenderProcessHost` (browser) 雙方藉由 IPC 做溝通
    - 每個 renderer 只會有一個 `RenderProcess` (對到一個 browser)
    - 每個 browser 會有多個 `RenderProcessHost` (有很多 tab == 很多 render)
- renderer is sandboxed

### How Chromium Displays Web Pages

- **WebKit:** **Rendering engine** shared between **Safari, Chromium, and all other WebKit-based browsers**
  - The **Port** is a part of WebKit that integrates with platform dependent system services such as resource loading and graphics
  - Blink - new open source rendering engine based on WebKit
- **Glue:** Converts **WebKit types to Chromium types**. This is our "**WebKit embedding layer**." It is the basis of two browsers, **Chromium**, and **test_shell** (which allows us to test WebKit).
- **Renderer / Render host:** This is Chromium's "**multi-process embedding layer**." It proxies notifications and commands across the process boundary.
- **WebContents:** A reusable component that is the main class of the Content module. It's easily embeddable to allow multiprocess rendering of HTML into a view. See the [content module pages](https://www.chromium.org/developers/content-module) for more information.
- **Browser:** Represents the **browser window**, it contains **multiple WebContentses**.
- **Tab Helpers**: **Individual objects that can be attached to a WebContents** (via the WebContentsUserData mixin). The Browser attaches an assortment of them to the WebContentses that it holds (one for favicons, one for infobars, etc).

### Multi-process Resource Loading

Blink

- has a **ResourceLoader** object which is responsible for fetching data
- Each loader has a **WebURLLoader** for performing the actual requests
  - The header file for this interface is inside the Blink repo.
- **ResourceLoader**
  - implements the interface **WebURLLoaderClient**
  - This is the callback interface used by the renderer to **dispatch data and other events to Blink**

Renderer

- renderer's implementation of WebURLLoader, called **WebURLLoaderImpl**
- It uses the global **ResourceDispatcher** singleton object (**one for each renderer process**) to create a **unique request ID** and forward the request to the **browser via IPC**
- Responses from the browser will reference this request ID, which can then be converted back to the **RequestPeer** object (**WebURLRequestImpl**) by the resource dispatcher

Browser

- **RenderProcessHost** objects inside the browser **receive the IPC requests from each renderer**
- It forwards these requests to the global **ResourceDispatcherHost**, using a pointer to the render process host (specifically, an implementation of **ResourceDispatcherHost::Receiver**) and the request ID generated by the renderer to uniquely **identify the request**
- Each request is then converted into a **URLRequest** object, which in turn forwards it to its internal **URLRequestJob** that implements the **specific protocol** desired
- When the **URLRequest** generates notifications, its **ResourceDispatcherHost::Receiver** and request ID are used to send the notification to the correct **RenderProcessHost** for sending back to the renderer
- Since the ID generated by the renderer is preserved, it is able to correlate all responses with a specific request first generated by Blink

### Sandbox

https://chromium.googlesource.com/chromium/src/+/refs/heads/main/docs/linux/sandboxing.md

Focus on Linux:

- **Do not re-invent the wheel:** Let the **operating system** apply its security to the objects it controls. On the other hand, it is OK to create **application-level objects** (abstractions) that have a custom security model.
- **Principle of least privilege:** This should be applied both to the sandboxed code and to the code that controls the sandbox. In other words, the sandbox **should work** even if the user **cannot elevate to super-user**.
- **Assume sandboxed code is malicious code:** For threat-modeling purposes, we consider the sandbox compromised (that is, running malicious code) once the execution path reaches past a few early calls in the `main()` function. In practice, it could happen as soon as the first external input is accepted, or right before the main loop is entered.
- **Be nimble:** Non-malicious code does not try to access resources it cannot obtain. In this case the sandbox should impose **near-zero performance impact**. It's ok to have performance penalties for exceptional cases when a **sensitive resource needs to be touched once in a controlled manner**. This is usually the case if the OS security is used properly.
- **Emulation is not security:** Emulation and virtual machine solutions do not by themselves provide security. The sandbox should not rely on code emulation, code translation, or patching to provide security.

two level:

1. (also called the “semantics” layer) - prevents access to most resources from a process where it's engaged. The **setuid sandbox** is used for this
   - disable by `--disable-setuid-sandbox`
2. (also called “attack surface reduction” layer) - restricts access from a process to the attack surface of the **kernel**. **Seccomp-BPF** is used for this.
   -  disable by `--disable-seccomp-filter-sandbox`
   -  Difficulty - if a process A runs under seccomp-bpf, we need to guarantee that it cannot affect the integrity of process B running under a different seccomp-bpf policy
3. disable all sandbox by `--no-sandbox`

```c
d8> var a = [1,2,3,4,"1234567890"]
undefined
d8> %DebugPrint(a);
DebugPrint: 0xaf30810b951: [JSArray]
 - map: 0x0af3082c3b31 <Map(PACKED_ELEMENTS)> [FastProperties]
 - prototype: 0x0af30828c0e9 <JSArray[0]>
 - elements: 0x0af30829528d <FixedArray[5]> [PACKED_ELEMENTS (COW)]
 - length: 5
 - properties: 0x0af30800222d <FixedArray[0]>
 - All own properties (excluding elements): {
    0xaf3080048f1: [String] in ReadOnlySpace: #length: 0x0af30820215d <AccessorInfo> (const accessor descriptor), location: descriptor
 }
 - elements: 0x0af30829528d <FixedArray[5]> {
           0: 1
           1: 2
           2: 3
           3: 4
           4: 0x0af308295215 <String[10]: #1234567890>
 }
0xaf3082c3b31: [Map]
 - type: JS_ARRAY_TYPE
 - instance size: 16
 - inobject properties: 0
 - elements kind: PACKED_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - back pointer: 0x0af3082c3b09 <Map(HOLEY_DOUBLE_ELEMENTS)>
 - prototype_validity cell: 0x0af308202405 <Cell value= 1>
 - instance descriptors #1: 0x0af30828c59d <DescriptorArray[1]>
 - transitions #1: 0x0af30828c619 <TransitionArray[4]>Transition array #1:
     0x0af30800524d <Symbol: (elements_transition_symbol)>: (transition to HOLEY_ELEMENTS) -> 0x0af3082c3b59 <Map(HOLEY_ELEMENTS)>

 - prototype: 0x0af30828c0e9 <JSArray[0]>
 - constructor: 0x0af30828be85 <JSFunction Array (sfi = 0xaf30820fe71)>
 - dependent code: 0x0af3080021b9 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0

[1, 2, 3, 4, "1234567890"]
```



```c
RDI  0x55cee0a41da0 —▸ 0xaf308295395 ◂— 0x2d0800222d082c22
RSI  0x55cee0a41d70 —▸ 0xaf308283649 ◂— 0xd9000001f8082c21
 
2050 MaybeLocal<Value> Script::Run(Local<Context> context) {
2051   auto isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
2052   TRACE_EVENT_CALL_STATS_SCOPED(isolate, "v8", "V8.Execute");
2053   ENTER_V8(isolate, context, Script, Run, MaybeLocal<Value>(),
2054            InternalEscapableScope);
2055   i::TimerEventScope<i::TimerEventExecute> timer_scope(isolate);
```



### PartitionAlloc

https://www.youtube.com/watch?v=QfY-WMFjjKA&ab_channel=BlinkOn

- slot - indivisible allocation unit
- slot span - groups slots of the same size into well-packed, multi-page regions
- bucket - chains slot spans containing slots of the same size (3 lists, by availability)
- super page - pre-reserved 2MiB address space slab, home for **slot spans** & **metadata** describing them
- partition - groups super pages
- NOTE: once an address region belongs to a partition/slot span, it'll always belong to those (true for <= 960KiB allocation)

因為 slot 需要 per-partition lock，因此會需要 per-thread cache TLS 來增加速度

central Allocator lock per partition

- common solution: multiple partitions / arenas -> More memory
- approach: simplest, smallest solution with decent performance
  - small, lock-free, **per-thread cache of free slots (ready to allocate by thread)**
  - thread cache
- per-thread cache
  - performanace critical
  - 不用 lock --> 沒有 contention
  - 當用完的時候在從 lock 的地方要一個大的記憶體區塊繼續切



**PartitionAlloc** is Chromium’s memory allocator, designed for lower fragmentation, higher speed, and stronger security and has been used extensively within Blink (Chromium’s rendering engine). In **Chrome 89** the entire Chromium codebase transitioned to using **PartitionAlloc everywhere** (by **intercepting and replacing malloc() and new**) on Windows 64-bit and Android

- 這裡 everywhere 應該是指 cross-platform

**Slab allocation**

- a memory management mechanism intended for the efficient memory allocation of objects
- reduces **fragmentation** caused by allocations and deallocations
- Cache
  - cache represents a **small amount of very fast memory**
  - A cache is a storage for a **specific type of object**, such as **semaphores**, **process descriptors**, **file objects**, etc.
- Slab
  - slab represents a **contiguous piece of memory**, usually made of **several physically contiguous pages**
  - The slab is the actual **container of data** associated with objects of the **specific kind of the containing cache**
- When a program sets up a cache, it allocates a **number of objects to the slabs** associated with that **cache**
- This number depends on **the size of the associated slabs** Slabs may exist in one of the following states :
  - empty – all objects on a slab marked as **free**
  - partial – slab consists of **both used and free objects**
  - full – all objects on a slab marked as **used**

https://blog.chromium.org/2021/04/efficient-and-safe-allocations-everywhere.html

**PartitionAlloc**

- pre-reserves slabs of virtual address space
- **Small** and **medium**-sized allocations are grouped in geometrically-spaced, **size-segregated buckets**, e.g. [241; 256], [257; 288]
- Each slab is split into regions (called “**slot spans**”) that satisfy allocations (“**slots**”) from only one particular bucket, thereby increasing **cache locality** while **lowering fragmentation**
- Conversely, larger allocations don’t go through the bucket logic and are fulfilled **using the operating system’s primitives directly**
- **central allocator** is protected by a single **per-partition lock**
- To mitigate the scalability problem arising from contention, we add a small, **per-thread cache** of **small slots** in front, yielding a three-tiered architecture
  - **first layer (Per-thread cache)** - holds **a small amount of slots** belonging to smaller and more commonly used **buckets**
    - Because these slots are stored **per-thread**, they can be allocated **without a lock** and only requiring a faster **thread-local storage** (TLS) lookup, improving **cache locality** in the process. The per-thread cache has been tailored to satisfy the majority of requests by allocating from and releasing memory to the second layer in **batches**, amortizing lock acquisition, and further improving locality while not trapping excess memory
  - **second layer (Slot span free-lists)** - is invoked upon a **per-thread cache miss**. For each bucket size, PartitionAlloc knows a **slot span** with **free slots** associated with that **size**, and captures a slot from the **free-list of that span**. This is still a **fast path**, but slower than per-thread cache as it requires taking a lock
    - However, this section is only hit for larger allocations not supported by per-thread cache, or as **a batch to fill the per-thread cache.**
  - Finally, if there are **no free slots in the bucket**, the third layer (Slot span management) either carves out space from a slab for a new slot span, or allocates an **entirely new slab from the operating system**, which is a slow but very infrequent operation



https://chromium.googlesource.com/chromium/src/+/refs/heads/main/base/allocator/partition_allocator/PartitionAlloc.md

A **partition** is a heap that is **separated and protected from any other partitions**

- to isolate certain object types
  - isolate objects of **certain sizes** or objects of a **certain lifetime**
- Each partition holds multiple **buckets**

A **bucket** is a series of regions in a partition that contains **similar-sized objects**, e.g. one bucket holds sizes (240, 256], another (256, 288], and so on

- `kMaxBucketed=960KiB` (so called normal buckets)
- 8 buckets between each power of two
- Larger allocations (`>kMaxBucketed`) are realized by direct memory mapping (**direct map**).

**PartitionAlloc** is designed to be extremely fast in its **fast paths**. The fast paths of allocation and deallocation require **very few (reasonably predictable) branches**. The number of operations in the fast paths is **minimal**, leading to the possibility of **inlining**.

- even the fast path **isn't the fastest**, because it requires taking a **per-partition lock**
- Therefore we introduced the **thread cache**, which holds **a small amount of not-too-large memory chunks**, **ready to be allocated**
- Because these chunks are stored **per-thread**, they can be allocated **without a lock**, only requiring a faster **thread-local storage (TLS)** lookup, improving **cache locality** in the process
- The thread cache has been tailored to satisfy a vast majority of requests by allocating from and releasing memory to the main allocator in batches, amortizing lock acquisition and further improving locality while not trapping excess memory

PartitionAlloc guarantees that **different partitions exist in different regions** of the process's address space. When the caller has freed **all objects contained in a page in a partition**, PartitionAlloc returns the physical memory to the operating system, but continues to **reserve the region of address space**. PartitionAlloc will only **reuse an address space region for the same partition**.

Similarly, one page can contain only objects from the **same bucket**. When freed, PartitionAlloc returns the physical memory, but continues to reserve the region for **this very bucket**.

The above techniques help **avoid type confusion attacks**. Note, however, these apply **only to normal buckets** and not to direct map, as it'd waste too much address space.

PartitionAlloc also guarantees that:

- **Linear overflows/underflows** cannot corrupt into, out of, or **between partitions**. There are **guard pages** at the beginning and the end of each memory region owned by a partition.
- Linear overflows/underflows **cannot corrupt the allocation metadata**. PartitionAlloc records **metadata** in a dedicated, **out-of-line region** (not adjacent to objects), **surrounded by guard pages**. (**Freelist pointers are an exception**.)
- **Partial pointer overwrite of freelist pointer should fault**.
- Direct map allocations have **guard pages** at **the beginning and the end**.

PartitionAlloc guarantees that returned pointers are aligned on `base::kAlignment` boundary (typically **16B** on 64-bit systems, and **8B** on 32-bit).

PartitionAlloc also supports higher levels of alignment, that can be requested via `PartitionAlloc::AlignedAllocFlags()` or platform-specific APIs (such as `posix_memalign()`)

The requested alignment has to **be a power of two**. PartitionAlloc reserves the right to **round up the requested size** to the **nearest power of two**, greater than or equal to the requested alignment. This may be wasteful, but allows taking advantage of natural PartitionAlloc alignment guarantees. Allocations with an alignment requirement greater than `base::kAlignment` are expected to be very rare.



**PartitionAlloc-Everywhere**

- Originally, PartitionAlloc was used only in **Blink** (Chromium’s rendering engine). It was invoked explicitly, by calling **PartitionAlloc APIs directly**.
- PartitionAlloc-Everywhere is the name of the project that brought PartitionAlloc to the **entire-ish codebase** (exclusions apply). This was done by **intercepting malloc(), free(), realloc(), aforementioned posix_memalign(),** etc. and **routing them into PartitionAlloc**
- The shim located in `base/allocator/allocator_shim_default_dispatch_to_partition_alloc.h` is responsible for intercepting. For more details, see base/allocator/README.md.
- A special, **catch-it-all Malloc partition** has been created for the **intercepted malloc()** et al. This is to **isolate from already existing Blink partitions**. The only exception from that is Blink‘s FastMalloc partition, which was also catch-it-all in nature, so it’s perfectly fine to merge these together, to **minimize fragmentation**
- launched in
  - M89 for Windows 64-bit and Android
  - Windows 32-bit and Linux followed it shortly after, in M90.





In PartitionAlloc, by system page we mean a memory page as defined by **CPU/OS (often referred to as “virtual page” out there)**. It is most commonly **4KiB** in size, but depending on CPU it can be larger (PartitionAlloc supports up to **64KiB**).

The reason why we use the term “system page” is to disambiguate from partition page, which is the most common granularity used by PartitionAlloc. Each partition page consists of exactly **4 system pages.**

A **super page** is a **2MiB** region, aligned on a 2MiB boundary. Don't confuse it with CPU/OS terms like “**large page**” or “**huge page**”, which are also **commonly 2MiB in size**. These have to be fully committed/uncommitted in memory, whereas super pages can be partially committed, with system page granularity.

A slot is an **indivisible allocation unit**. **Slot sizes are tied to buckets**. For example each allocation that falls into the bucket (240; 256] would be satisfied with a slot of size 256. This applies only to **normal buckets**, not to **direct map**.

A **slot span** is just a grouping of slots of the **same size** next to each other in memory. Slot span size is a multiple of a partition page.

A **bucket is a collection of slot spans** containing slots of the same size, organized as linked-lists.

Allocations up to 4 partition pages are referred to as small buckets

- In these cases, **slot spans** are always between **1 and 4 partition pages in size.**
- The size is chosen based on the **slot size**, such that the rounding waste is minimized
- For example, if the **slot size was 96B** and slot span was 1 partition page of 16KiB, 64B would be wasted at the end, but nothing is wasted if 3 partition pages totalling 48KiB are used
- Furthermore, PartitionAlloc may **avoid waste by lowering the number of committed system pages** compared to the number of reserved pages
- For example, for the slot size of 80B we'd use a slot span of 4 partition pages of 16KiB, i.e. 16 system pages of 4KiB, but commit only up to 15, thus resulting in perfect packing.

Allocations above 4 partition pages (but `≤kMaxBucketed`) are referred to as **single slot spans**. That‘s because each slot span is guaranteed to hold exactly **one slot**

Fun fact: there are sizes `≤4 partition pages` that result in a **slot span having exactly 1 slot**, but nonetheless they’re still classified as **small buckets**. The reason is that single slot spans are often handled by a different code path, and that distinction is made purely based on slot size, for simplicity and efficiency.



PartitionAlloc handles **normal buckets** by **reserving (not committing)** 2MiB super pages. Each super page is split into **partition pages**. The first and the last partition page are permanently **inaccessible and serve as guard pages**, with the exception of **one system page** in the middle of the first partition page that holds **metadata** (**32B** struct per partition page).

As allocation requests arrive, there is eventually a need to allocate a **new slot span**. Address space for such a slot span is carved out from the last super page.

If not enough space, a **new super page is allocated**. Due to varying sizes of slot span, this may lead to leaving space unused (we **never go back to fill previous super pages**), which is fine because this memory is **merely reserved**, which is far less precious than committed memory. Note also that address space **reserved for a slot span is never released**, even if the slot span isn't used for a long time.

All slots in a newly allocated slot span are free, i.e. **available for allocation**.



All free slots within a slot span are chained into a **singly-linked free-list**, by writing the *next* pointer **at the beginning of each slot**, and **the head of the list is written in the metadata struct**.

However, writing a pointer in each free slot of a newly allocated span would require **committing and faulting in physical pages upfront**, which would be unacceptable. (還沒被使用就要 page fault) Therefore, PartitionAlloc has a concept of **provisioning slots**. Only **provisioned slots are chained into the freelist**. Once provisioned slots in a span are depleted (耗盡), then another page worth of slots is provisioned (note, a slot that crosses a page boundary only gets provisioned with slots of the **next page**). See `PartitionBucket::ProvisionMoreSlotsAndAllocOne()` for more details.

Freelist pointers are stored at **the beginning of each free slot**. As such, they are the only **metadata** that is inline, i.e. stored among the objects



Slot Span States - A slot span can be in any of 4 states:

- **Full**. A full span has no free slots.
- **Empty**. An empty span has no allocated slots, only free slots.
- **Active**. An active span is anything in between the above two.
- **Decommitted**. A **decommitted span** is a special case of an **empty span**, where **all pages are decommitted from memory**



PartitionAlloc prioritizes getting an available slot from an **active span**, over an empty one, in hope that the latter can be soon transitioned into a **decommitted state**, thus **releasing memory**. There is no mechanism, however, to prioritize selection of a slot span based on **the number of already allocated slots**. (看 slot span 內有多少已經分配的 slot 決定要給哪個 slot span)

An empty span becomes **decommitted** either when there are **too many empty spans (FIFO)**, or when `PartitionRoot::PurgeMemory()` gets invoked **periodically** (or in **low memory pressure conditions**)

An allocation can be satisfied from a decommitted span if there are **no active or empty spans** available. The slot provisioning mechanism kicks back in, committing the pages gradually as needed, and the span becomes active. (There is currently no other way to **unprovision slots than decommitting the entire span**).

As mentioned above, a bucket is **a collection of slot spans containing slots of the same size**. In fact, each bucket has 3 linked-lists, chaining **active**, **empty** and **decommitted** spans (see `PartitionBucket::*_slot_spans_head`). There is no need for a full span list. The lists are updated **lazily**. An empty, decommitted or full span may stay on the **active list** for some time, until `PartitionBucket::SetNewActiveSlotSpan()` encounters it. A decommitted span may stay on the **empty list** for some time, until `PartitionBucket<thread_safe>::SlowPathAlloc()` encounters it. However, the inaccuracy can't happen in the other direction, i.e. an active span can only be on the active list, and an empty span can only be on the active or empty list.



architecture

- super page - 2 MiB
  - super page is split into partition pages
  - 一次跟 system 要的大小
- partition page consists of exactly **4 system pages** - 16 KiB
  - 而在 ParitionAlloc 都是用 partition page 作為單位
  - Each partition holds multiple **buckets**
- A **bucket** is a series of regions in a partition that contains **similar-sized objects**, e.g. one bucket holds sizes (240, 256], another (256, 288], and so on
  - **8 buckets** between each power of two
  - slot size 跟 bucket 綁在一起，像是每個 allocation 落在 bucket (240; 256] 會滿足被分配 a slot of size 256
- **slot span** 存放相同大小的 slot，並且 slot span 的大小是 multiple of a partition page
- A slot is an **indivisible** allocation unit
- 大於 4 partition pages 的請求會被分配一個 single slot span，因為每個 slot span 都恰好包含一個 slot
- 小於 4 partition pages 的請求也有可能會產生包含一個 slot 的 slot span，但是仍被分配為 small bucket
  - 最多 4 partition pages 的分配被稱作 **small buckets**
  - **slot spans** are always between **1 and 4 partition pages in size**

所以是每次請求時會先看請求大小會是幾個 partition page，並且會檢查是否有存放對應大小 slot 的 slot span，如果有並且還有 freed slot 就直接回傳，其他情況就分配新的 slot span，而這個新的 slot span 會被 bucket maintain，之後從中拿 slot 回傳。



https://chromium.googlesource.com/chromium/src/+/refs/heads/main/base/allocator/README.md

Bare in mind that the chromium codebase does not always just use `malloc()`. Some examples:

- Large parts of the **renderer (Blink)** use two **home-brewed allocators**, **PartitionAlloc** and BlinkGC (Oilpan).
- Some subsystems, such as the **V8 JavaScript engine**, handle memory management autonomously (自主地).
- Various parts of the codebase use abstractions such as `SharedMemory` or `DiscardableMemory` which, similarly to the above, have their own page-level memory management.



The allocator target defines at **compile-time** the **platform-specific** choice of the allocator and **extra-hooks** which services calls to **malloc/new**. The relevant build-time flags involved are **use_allocator and use_allocator_shim**.

Linux Desktop / CrOS use_allocator: `tcmalloc`, a forked copy of tcmalloc which resides in third_party/tcmalloc/chromium

- Setting use_allocator: none causes the build to fall back to the system (Glibc) symbols.

**Overview of the unified allocator shim** The allocator shim consists of three stages:

```
+-------------------------+    +-----------------------+    +----------------+
|     malloc & friends    | -> |       shim layer      | -> |   Routing to   |
|    symbols definition   |    |     implementation    |    |    allocator   |
+-------------------------+    +-----------------------+    +----------------+
| - libc symbols (malloc, |    | - Security checks     |    | - tcmalloc     |
|   calloc, free, ...)    |    | - Chain of dispatchers|    | - glibc        |
| - C++ symbols (operator |    |   that can intercept  |    | - Android      |
|   new, delete, ...)     |    |   and override        |    |   bionic       |
| - glibc weak symbols    |    |   allocations         |    | - WinHeap      |
|   (__libc_malloc, ...)  |    +-----------------------+    +----------------+
+-------------------------+
```



https://chromium.googlesource.com/chromium/src/+/0e94f26e8/third_party/WebKit/Source/wtf/Allocator.md#Memory-allocators
`PartitionAlloc` is **Blink‘s default memory allocator**. PartitionAlloc is highly optimized for performance and security requirements in Blink. All Blink objects that don’t need a GC or discardable memory should be allocated by PartitionAlloc (instead of malloc). The following objects are allocated by PartitionAlloc:

- Objects that have a `USING_FAST_MALLOC` macro.
- Nodes (which will be moved to Oilpan in the near future)
- LayoutObjects
- Strings, Vectors, HashTables, ArrayBuffers and other primitive containers.

The implementation is in `wtf/Partition*`

renderer (Blink) 大部分都是用 chromium 單獨設計的 PartitionAlloc 和 BlinkGC (Oilpan)，像 V8 這樣比較獨立的子系統使用自己的內存管理機制，還有部分模塊會使用抽象化的內存管理模塊如 ShareMemory 或者 DiscardMemory，和上面的內存管理器類似，他們也有自己的頁面級內存管理器

tcmalloc vs. PartitionAlloc ([src](https://source.chromium.org/chromium/chromium/src/+/master:base/allocator/allocator.gni;bpv=0;bpt=0)):

```cpp
# Copyright 2019 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import("//build/config/chromecast_build.gni")
import("//build/config/sanitizers/sanitizers.gni")

# Sanitizers replace the allocator, don't use our own.
_is_using_sanitizers = is_asan || is_hwasan || is_lsan || is_tsan || is_msan

# - Component build support is disabled on all platforms. It is known to cause
#   issues on some (e.g. Windows with shims, Android with non-universal symbol
#   wrapping), and has not been validated on others.
# - Windows: debug CRT is not compatible, see below.
# - Chromecast on Android: causes issues with crash reporting, see b/178423326.
_disable_partition_alloc =
    is_component_build || (is_win && is_debug) || (is_android && is_chromecast)
_is_partition_alloc_platform = is_android || is_win || is_linux || is_chromeos

# The debug CRT on Windows has some debug features that are incompatible with
# the shim. NaCl in particular does seem to link some binaries statically
# against the debug CRT with "is_nacl=false".
if ((is_linux || is_chromeos || is_android || is_apple ||
     (is_win && !is_component_build && !is_debug)) && !_is_using_sanitizers) {
  _default_use_allocator_shim = true
} else {
  _default_use_allocator_shim = false
}

if (_default_use_allocator_shim && _is_partition_alloc_platform &&
    !_disable_partition_alloc) {
  _default_allocator = "partition"
} else if (is_android || is_apple || _is_using_sanitizers || is_win ||
           is_fuchsia || ((is_linux || is_chromeos) && target_cpu == "arm64") ||
           (is_cast_audio_only && target_cpu == "arm")) {
  # Temporarily disable tcmalloc on arm64 linux to get rid of compilation
  # errors.
  _default_allocator = "none"
} else {
  _default_allocator = "tcmalloc"
}

```

blink (renderer) - 用 PartitionAlloc

Linux 當中 `malloc()` 以及 `free()` 會被替換成 tcmalloc，或者當 `use_allocator: none` 會使用原本的 `malloc()`

On Linux/CrOS: the **allocator symbols** are defined as **exported global symbols** in `allocator_shim_override_libc_symbols.h` ([src](https://chromium.googlesource.com/chromium/src/base/+/refs/heads/main/allocator/allocator_shim_override_libc_symbols.h)) (for malloc, free and friends) and in `allocator_shim_override_cpp_symbols.h` (for operator new, operator delete and friends).

This enables proper **interposition of malloc symbols** referenced by the main executable and any third party libraries. Symbol resolution on Linux is a **breadth first search** (BFS) that starts from the **root link unit**, that is the executable (see EXECUTABLE AND LINKABLE FORMAT (ELF) - Portable Formats Specification). Additionally, when `tcmalloc` is the default allocator, some extra glibc symbols are also defined in `allocator_shim_override_glibc_weak_symbols.h`, for subtle reasons explained in that file.



https://docs.google.com/document/d/1aitSOucL0VHZa9Z2vbRJSyAIsAz24kX8LFByQ5xQnUg/edit#

Blink is a rendering engine of the web platform. Roughly speaking, Blink implements everything that renders content inside a browser tab:

- Implement the specs of the web platform (e.g., HTML standard), including **DOM, CSS and Web IDL**
- Embed **V8** and run JavaScript
- Request resources from the underlying network stack
- Build **DOM trees**
- Calculate style and layout
- Embed Chrome Compositor and draw graphics



How many renderer processes are created? For security reasons, it is important to **isolate memory address regions between cross-site documents** (this is called **Site Isolation**). Conceptually each renderer process should be dedicated to at most one site. Realistically, however, it's sometimes **too heavy** to limit each renderer process to a single site when users **open too many tabs** or the **device does not have enough RAM**. Then a renderer process may be shared by multiple iframes or tabs loaded from different sites. This means that **iframes** in one tab may be hosted by different renderer processes and that iframes in **different tabs** may be hosted by the same renderer process. There is no 1:1 mapping between renderer processes, iframes and tabs.

Given that a renderer process **runs in a sandbox**, Blink needs to ask the **browser** process to dispatch system calls (e.g., file access, play audio) and access user profile data (e.g., cookie, passwords). This browser-renderer process communication is realized by **Mojo**. (Note: In the past we were using **Chromium IPC** and a bunch of places are still using it. However, it's deprecated and uses **Mojo** under the hood.) On the Chromium side, **Servicification** is ongoing and abstracting the browser process as a set of "**service**"s. From the Blink perspective, Blink can just **use Mojo to interact with the services and the browser process**.

How many threads are created in a renderer process?

- Blink has **one main thread**, **N worker threads** and **a couple of internal threads.**
- Almost all important things happen on the main thread. All JavaScript (except workers), **DOM, CSS, style and layout calculations** run on the main thread. Blink is highly optimized to maximize the performance of the main thread, assuming the mostly single-threaded architecture.
- multiple worker threads to run **Web Workers, ServiceWorker and Worklets**
- **Blink and V8** may create a couple of internal threads to handle **webaudio, database, GC** etc.
- PostTask APIs instead of Shared memory programming to communicate with other thread

`WTF` is a "**Blink-specific base**" library and located at `platform/wtf/`. We are trying to unify **coding primitives** between **Chromium** and **Blink** as much as possible, so WTF should **be small**. This library is needed because there are a number of types, containers and macros that really need to be optimized for Blink's workload and **Oilpan (Blink GC)**. If types are defined in WTF, Blink has to **use the WTF types** instead of types defined in //base or std libraries. The most popular ones are **vectors, hashsets, hashmaps and strings**. Blink should use `WTF::Vector`, `WTF::HashSet`, `WTF::HashMap`, `WTF::String` and `WTF::AtomicString` instead of `std::vector`, `std::*set`, `std::*map` and `std::string`.

allocate an object on PartitionAlloc's heap by using `USING_FAST_MALLOC()`:

```cpp
class SomeObject {
  USING_FAST_MALLOC(SomeObject);
  static std::unique_ptr<SomeObject> Create() {
    return std::make_unique<SomeObject>();  // Allocated on PartitionAlloc's heap.
  }
};
```

- The lifetime of objects allocated by `PartitionAlloc` should be managed by `scoped_refptr<>` or `std::unique_ptr<>`. It is strongly discouraged to manage the lifetime manually. Manual delete is **banned** in Blink

You can allocate an object on Oilpan's heap by using `GarbageCollected`:

```cpp
class SomeObject : public GarbageCollected<SomeObject> {
  static SomeObject* Create() {
    return new SomeObject;  // Allocated on Oilpan's heap.
  }
};
```

### StarScan: Heap scanning use-after-free prevention

C++ and other languages that rely on explicit memory management using `malloc()` and `free()` are prone to memory corruptions and the resulting **security issues**. The fundamental idea behind these **heap scanning algorithms** is to intercept an underlying allocator and delay releasing of memory until the corresponding memory block is provably unreachable from application code.

The basic ingredients for such algorithms are:

1. *Quarantine*: When an object is deemed unused with a `free()` call, it is put into **quarantine** instead of being returned to the allocator. The object is not actually freed by the underlying allocator and cannot be used for future allocation requests until **it is found that no pointers are pointing to the given memory block**.
2. *Scan*: When the quarantine reaches a certain **quarantine limit** (e.g. based on memory size of quarantine list entries), the quarantine scan is triggered. The scan iterates over the **application memory** and **checks if references are pointing to quarantined memory**. If objects in the quarantine are still referenced then they are kept in quarantine, if **not they are flagged to be released**.
3. *Sweep*: All objects that **are flagged to be released** are actually **returned to the underlying memory allocator**.

[Heap scanning algorithms](http://bit.ly/conservative-heap-scan) come in different flavors that offer **different performance** and **security characteristics**.

***Probabilistic conservative scan (PCScan)*** (`pcscan.{h,cc}`) is one particular kind of heap scanning algorithm implemented on top of [PartitionAlloc](https://source.chromium.org/chromium/chromium/src/+/master:base/allocator/partition_allocator/PartitionAlloc.md#) with the following properties:

- Memory blocks are scanned conservatively for pointers.
- Scanning and sweeping are generally performed on a **separate thread** to maximize application performance.
- **Lazy safe points** prohibit certain operations from modifying the memory graph and provide convenient entry points for scanning the stack.

PCScan is currently considered **experimental** - please do not use it in production code just yet. It can be enabled in the following configurations via `--enable-features` on builds that use PartitionAlloc as the [main allocator](https://source.chromium.org/chromium/chromium/src/+/master:base/allocator/README.md#):

- `PartitionAllocPCScan`: All processes and all supporting partitions enable PCScan.
- `PartitionAllocPCScanBrowserOnly`: Enables PCScan in the browser process for the default malloc partition.



proxy in javascript

- Used to re-define basic operation

magic number

- 代表 hole / missing number



https://docs.google.com/document/d/1aitSOucL0VHZa9Z2vbRJSyAIsAz24kX8LFByQ5xQnUg/edit#

## V8

Isolate, Context and World - `v8::Isolate`, `v8::Context` and `DOMWrapperWorld`

When you call V8 APIs, you have to make sure that you're in the correct context. Otherwise, `v8::Isolate::GetCurrentContext()` will return a **wrong** context and in the worst case it will end up **leaking objects** and **causing security issues**

- World - a concept to support **content scripts** of Chrome extensions
  - Worlds do not correspond to anything in web standards.
  - Content scripts want to **share DOM with the web page**, but for security reasons JavaScript objects of content scripts must be **isolated from the JavaScript heap** of the web page. (Also a JavaScript heap of one content script must be isolated **from a JavaScript heap of another content script.)**
  - To realize the isolation, the main thread creates **one main world** for the **web page** and **one isolated world for each content script**. The main world and the isolated worlds can access the **same C++ DOM objects** but their JavaScript objects are isolated. This isolation is realized by creating multiple **V8 wrappers for one C++ DOM object**; i.e., **one V8 wrapper per world**.

What's a relationship between **Context, World and Frame**?

Imagine that there are N Worlds on the main thread (one main world + (N - 1) isolated worlds). Then one Frame should have N window objects, each of which is used for one world. **Context** is a concept that corresponds to a **window object**. This means that when we have **M Frames** and **N Worlds**, we have **M * N Contexts** (but the Contexts are created **lazily**).

In case of **a worker**, there is only **one World** and **one global object**. Thus there is only **one Context**.

Again, when you use V8 APIs, you should be really careful about using the **correct context**. Otherwise you'll end up leaking **JavaScript objects** between **isolated worlds** and **causing security disasters** (e.g., an extension from A.com can manipulate an extension from B.com)

### V8 APIs

There are a lot of **V8 APIs** defined in `//v8/include/v8.h`. Since V8 APIs are **low-level** and hard to use correctly, platform/bindings/ provides a bunch of **helper classes** that **wrap V8 APIs**. You should consider using the helper classes as much as possible. If your code has to use V8 APIs heavily, the files should be put in bindings/{core,modules}.

V8 uses **handles** to point to V8 objects. The most common handle is `v8::Local<>`, which is used to **point to V8 objects** from a machine stack. `v8::Local<>` must be used after allocating `v8::HandleScope` on the machine stack. `v8::Local<>` should not be used outside the machine stack:

```cpp
void function() {
  v8::HandleScope scope;
  v8::Local<v8::Object> object = ...;  // This is correct.
}

class SomeObject : public GarbageCollected<SomeObject> {
  v8::Local<v8::Object> object_;  // This is wrong.
};
```

If you want to point to V8 objects from outside the machine stack, you need to use wrapper tracing. However, you have to be really careful not to create a reference cycle with it. In general V8 APIs are hard to use.



**V8 wrappers**
Each **C++ DOM object** (e.g., **Node**) has its corresponding **V8 wrapper**. Precisely speaking, each **C++ DOM object** has its corresponding V8 wrapper per world.

V8 wrappers have **strong references** to their corresponding **C++ DOM objects**. However, the C++ DOM objects have only **weak references** to the V8 wrappers. So if you want to keep V8 wrappers alive for a certain period of time, you have to do that **explicitly**. Otherwise, V8 wrappers will be **prematurely collected** and **JS properties on the V8 wrappers will be lost**...

```cpp
div = document.getElementbyId("div");
child = div.firstChild;
child.foo = "bar";
child = null;
gc();  // If we don't do anything, the V8 wrapper of |firstChild| is collected by the GC.
assert(div.firstChild.foo === "bar");  //...and this will fail.
```

[Objects in v8](https://segmentfault.com/a/1190000039908658/en)



An isolate is an **independent copy of the V8 runtime**, including a **heap manager**, **a garbage collector**, etc. Only **one thread** may access **a given isolate at a time**, but **different threads** may access **different isolates simultaneously**.

- An isolate is **not sufficient** for running scripts, however. You also need a **global (root) object**

A context defines a **complete script execution environment** by designating an object in an **isolate's heap** as a global object.

- Therefore, not only can **many contexts "exist" in a given isolate**, but they can also **share any or all of their objects easily and safely**. That's because their objects actually **belong to the isolate** and are **protected by the isolate's exclusive lock**.



https://blog.dingkewz.com/post/tech/google_v8_core_concepts_01/

Handle，簡單的說，是對一個特定 JS 對象的 index。它指向此 JS 對象在 V8 所管理的 Heap 中的位置。需要注意的是，Handle 不存於 Heap 中，而是**存在於 stack 中**。只有一個 Handle 被釋放後，此 Handle 才會從 stack 中 pop 出。這就帶來一個問題，在執行特定操作時，我們可能需要**聲明很多 Handle**。如果要一個個手動釋放，未免太麻煩。為此，我們使用 **Handle Scope** 來集中釋放這些 Handle。

Handle Scope，形象的說是一個可以**包含很多 Handle 的工作區**。當這個工作區 Handle Scope 被移出 stack 時，其所包含的所有 Handle 都會被移出堆棧，並且被 GC 標註，從而在後續的垃圾回收過程快速的定位到這些可能需要被銷毀的Handle。

Handle Type：

- Local Handle
- Persistent Handle
- UniquePersistent Handle
- Eternal Handle



compressed pointer 從 V8 8.0 才有 (Chrome 80) - https://v8.dev/blog/v8-release-80

https://blog.infosectcbr.com.au/2020/02/pointer-compression-in-v8.html，內容還有講解 exploit 的部分

isolate memory region - upper 32 bits 不變只有 lower 32 bits 變

-  **isolate root** 為 upper 32 bits
- compress / decompress pointer 的部分在 https://source.chromium.org/chromium/chromium/src/+/master:v8/src/common/ptr-compr-inl.h;drc=7fc1bf7f07dacab1be87c6fde304750df5b7d4cd;bpv=0;bpt=1;l=58

有 `addrof()` 跟 `fakeobj()` 後

- fake a `JSArray` and control the elements pointer to gain **arbitrary r/w** primitives (within the V8 heap)，因為只能控制 lower 32bits
- allocating an `ArrayBuffer` on the V8 heap and overwriting its `backing store` to an arbitrary 64-bit memory address
  - performing reads and writes with it using either a TypedArray or a DataView object will grant you an arbitrary r/w primitive within the entire 64-bit address space
  - 因為 `backing stores` of array buffers are allocated using **PartitionAlloc**
    - All **PartitionAlloc** allocations go on a **separate memory region that is not within the V8 heap**. This means that the backing store pointer needs to be stored as an **uncompressed 64-bit pointer**, since its upper 32 bits are not the same as the **isolate root** and thus *have* to be stored with the pointer.



https://chromium.googlesource.com/chromium/src/+/refs/heads/main/docs/security/mojo.md

**Mojo** structs, interfaces, and methods should all have comments. Make sure the comments cover **the “how” and the “why”** of using an interface and its methods, and not just the **“what”**. Document preconditions, postconditions, and trust: if an interface is implemented **in the browser process** and **handles requests from the renderer process**, this should be mentioned in the comments.

Complex features should also have an external `README.md` that covers the **high-level flow** of information through interfaces and how they interact to implement the feature.

Policy should be controlled solely by the browser process. “Policy” can mean any number of things, such as sizes, addresses, permissions, URLs, origins, etc. In an ideal world:

1. **Unprivileged process** asks for a capability from the **privileged process** that owns the resource.
2. **Privileged process** applies policy to find **an implementation for the capability**.
3. **Unprivileged process** performs **operations on the capability**, constrained in scope.

The privileged process must own the capability lifecycle



繞過 sandbox 的方法

- 打 OS sandbox feature
- 打 IPC layer
- Logic bug



## Resource

- [V8 engine JSObject structure analysis and memory optimization ideas](https://medium.com/@bpmxmqd/v8-engine-jsobject-structure-analysis-and-memory-optimization-ideas-be30cfcdcd16)
- [Objects in v8](https://segmentfault.com/a/1190000039908658)
- [官方 documentation](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/docs/)

