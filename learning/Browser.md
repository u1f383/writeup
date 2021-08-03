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

- `gclient` - Meta-checkout tool managing both subversion and git checkouts. It is similar to repo tool except that it works on Linux, OS X, and Windows and supports both svn and git. On the other hand, ㄎgclient doesn't integrate any code review functionality.

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
  '
  Running: gclient sync --with_branch_heads
  # 以上如果沒有自動跑，就手動執行
  
  #### done ####
  # 執行完後，應該會有 .gclient 以及 v8/
  cd v8 && gclient sync && ./build/install-build-deps.sh
  tools/dev/gm.py x64.release
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

