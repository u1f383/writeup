## Browser

Browser - interpreter(直譯器) + optimizing compiler(編譯器)：

- V8 -  Chrome 和 Node.js 的 JavaScript engine
  - Ignition - V8 的 interpreter，負責產生可執行的 bytecode
  - TurboFan - V8 的 optimizing compiler
  - Sparkplug  - V8 在 Chrome 91 加的 compiler，功能介於 **Ignition interpreter** 和 **TurboFan optimizing** compiler 之間
- SpiderMonkey -Mozilla 的 JavaScript engine，用於 Firefox 和 SpiderNode
- Chakra - Microsoft 的 JavaScript engine，用於 Edge 與 Node-ChakraCore
  - Chakra 的 optimizing compiler (JIT, Just-In-Time compiler)
    - SimpleJIT
    - FullJIT - **more-heavily-optimized** code
- JavaScriptCore (JSC) - Apple 的 JavaScript engine，用於 Safari 和 React Native
  - JSC 的 opt compiler
    - LLInt - the Low-Level Interpreter
    - DFG (Data Flow Graph)
    - FTL (Faster Than Light)


Optimizing compiler 的個數為 trade-off：
- 少一點的話，可以花更多資源在 interpreter，直接跑 bytecode 的效能會上升
- 多一點的話，雖然 bytecode 會比較慢，但是等 code 優化完在執行的效能會提升許多



**JS object**

- Dict
- 4 base properties
  - `[[value]]`
  - `[[writable]]` - 是否可以 reassigned
  - `[[enumeratble]]` - 是否可以用 `for-in` loop traverse
  - `[[configurable]]` - propterty 是否可以 delete
- array 可以想成是比較特別的 object
  - **array index**
    - writable
    - enumerable
    - configurable
- JSArray 會有 elements **backing store** 來儲存 array-indexed property



JS 的  `{Shapes,HiddenClasses,Maps,Types,Structures}` (在每個 JS engine 名稱不同)

- JS 節省 memory 的機制
- `Shape` 包含 property + attribute，用 offset 表示對應的 property 在 object 中的位置
- 多個 `Shape` 會組成 transition chains，透過一層層去往上找當前 object 的 member，因為這樣做能讓有重複 member 的 object 共享相同的 `Shape`，以達到節省記憶體，但在沒辦法建立 transition chains 時 (object 不重複) 會變成 transition tree
- 每個 `Shape` 會指向前一個 `Shape`，而在 `Shape` 在新增 property 時只需要看過去有沒有已經存在的 `Shape`，如果有的話直接用就好
- 不同的 properties order 代表不同的 Shape
- 最後由於 transition chains 耗 O(n) 去找特定的 element，因此有 `ShapeTable`，而 `ShapeTable` 也是以 Dict 的形式存在



**Inline Caches (ICs)** - function 在呼叫時會紀錄在何處找到對應 object 的 property，之後在傳入參數時只需檢查是否為相同的 object，即可透過 cache 存放的位置直接存取，減少不必要的 lookup

- IC 有四個屬性，用來記錄某個 property
  - ValidityCell
    - prototype shapes 的一個 property
    - 當改變對應的 prototype 或是相關連的 prototype 時會變成 invalid
  - Prototype
  - Shape
  - Offset

當 IC hit，JS engine 會檢查該 instance 對應 shape 的 **ValidityCell** 屬性

- Valid - 直接用 offset + prototype 存取
- Invalid - 代表 `Shape` 更新，需要重新尋找正確地 `Shape`，所以此次執行會變慢



**JS engine optimize** - 當 code 常常被執行 (hot)，各個 JS engine 的 optimizer 就會優化 interpreter 產生出來的 bytecode，產生優化過的 machine code

- 即使 bytecode 的 instruction 個數比 machine code 來的少，但是執行時間差很多 (machine code 快於 bytecode)
- optimized machine code 與需要的 memory 成正比



**Exploit flow**

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
- copy shellcode
- jmp shellcode
