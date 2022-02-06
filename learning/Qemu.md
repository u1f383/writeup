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



`MAP_HUGETLB` - 分配連續記憶體空間





---

## Qemu device 使用到的結構 & function

device 可以分成以下幾種階段:

- device 對應到的 struct 為 `TypeInfo`
- `type_new()` 會產生一個 `TypeImpl`，資料跟 `TypeInfo` 很像
- 註冊 device type (`module_call_init()`)
- 初始化 device type (`type_initialize()`)
- 實例 device

### TypeImpl - TypeInfo 的實例

```c
struct TypeImpl
{
    const char *name;

    size_t class_size;

    size_t instance_size;
    size_t instance_align;

    void (*class_init)(ObjectClass *klass, void *data);
    void (*class_base_init)(ObjectClass *klass, void *data);

    void *class_data;

    void (*instance_init)(Object *obj);
    void (*instance_post_init)(Object *obj);
    void (*instance_finalize)(Object *obj);

    bool abstract;

    const char *parent;
    TypeImpl *parent_type;

    ObjectClass *class; // 需要被初始化

    int num_interfaces;
    InterfaceImpl interfaces[MAX_INTERFACES];
};
```

- qemu 根據 user define 的 `TypeInfo` 來產生

### TypeInfo - 描述某個 device

```c
struct TypeInfo
{
    const char *name;
    const char *parent;

    size_t instance_size;
    size_t instance_align;
    void (*instance_init)(Object *obj);
    void (*instance_post_init)(Object *obj);
    void (*instance_finalize)(Object *obj);

    bool abstract;
    size_t class_size;

    void (*class_init)(ObjectClass *klass, void *data);
    void (*class_base_init)(ObjectClass *klass, void *data);
    void *class_data;

    InterfaceInfo *interfaces;
};
```

- user define
- `*class_init` 指向 initialization function，而若需要 override method 的話在此 function 當中處理
  - method 皆是 virtual (指的是用 function pointer maintain 吧)

### Object - 所有物件都會從此 struct 做擴展，為 base object

```c
/**
 * struct Object:
 *
 * The base for all objects.  The first member of this object is a pointer to
 * a #ObjectClass.  Since C guarantees that the first member of a structure
 * always begins at byte 0 of that structure, as long as any sub-object places
 * its parent as the first member, we can cast directly to a #Object.
 *
 * As a result, #Object contains a reference to the objects type as its
 * first member.  This allows identification of the real type of the object at
 * run time.
 */
struct Object
{
    /* private: */
    ObjectClass *class;
    ObjectFree *free;
    GHashTable *properties;
    uint32_t ref;
    Object *parent;
};
```

- 第一個  member 一定為指向 ObjectClass 的 pointer
- `ObjectClass` --> class，透過 `class_init()` 初始化
- `Object` --> instance of class，透過 `instance_init()` 初始化
- Initialization overview:
  - TypeInfo => ModuleEntry => TypeImpl => ObjectClass => Object
  - 用 `TypeInfo` 註冊 `TypeImpl`
  - `class_init()` --> ObjectClass
  - `instance_init()` --> Object
  - 但是真正初始化是 `realize()` 才做，做完一個 device 才能被使用
    - 建立 memory region
    - 掛載 bus
- 編譯時 device 透過 `type_init()` 將註冊 device 的 function 加到 init array
- runtime 透過 c runtime 的 `__libc_csu_init()` 來跑這些 init function
- `qemu_init()` --> `qemu_init_subsystems()` --> `module_call_init(MODULE_INIT_QOM)`
  - 取出 type 為 `MODULE_INIT_QOM` 的 `ModuleEntry`，呼叫 `init()`
- `qemu_init()` --> `qemu_create_machine()` --> `select_machine()` --> `object_class_get_list()` --> `object_class_foreach()` --> `g_hash_table_foreach()` --> `object_class_foreach_tramp()` --> `type_initialize()`
  1. 檢查 `ti->class`，若有值代表已初始化就回傳
  2. `ti->class = g_malloc0(ti->class_size)` 分配空間給 class
  3. `parent = type_get_parent(ti)` 取得 parent 的 `TypeImpl`
  4. `memcpy(ti->class, parent->class, parent->class_size)` 複製 parent 的資料給自己
  5. `type_initialize_interface()` 初始化 interfaces
  6. `ti->class->properties = g_hash_table_new_full(...)` 建立存放 property 的 hash table
  7. `ti->class->type = ti` 將自己的 class 的 type 設為自己 (`ObjectClass` 所對應的 `TypeImpl`)
  8. `parent->class_base_init(...)` 若 parent 有 define `class_base_init` 就呼叫來初始化 base class
  9. `ti->class_init(...)` 最後呼叫到 `TypeImpl` 對應到的 ObjectClass 的初始化 function
- `qemu_init()` --> `qemu_create_machine()` --> `object_new_with_class()` --> `object_new_with_type()` --> `object_initialize_with_type()` --> `object_init_with_type()` --> `ti->instance_init()`
  1. `object_new_with_class()` 內呼叫 `object_new_with_type(klass->type)` 而已
  2. `object_new_with_type()` 內部先呼叫 `type_initialize()` 來確保 class 已經初始化 (執行了 `class_init()`)，而後執行 `object_initialize_with_type()`
  3. `object_initialize_with_type()` 又初始化執行了一次 `type_initialize()`，不過因為 `type_initialize()` 有先檢查 class 是否已經初始化，如果是的話就不做任何事。而在 assign `object->class` 與 `object->properties` 後執行 `object_init_with_type()`
  4. `object_init_with_type()` 會判斷 `TypeImpl ti` 有沒有 parent，有的話會先確保 parent 的 type 初始化，最後會呼叫 `ti->instance_init()`

### register_module_init() - 將要註冊的 device 加進特定 type 的 linked list 當中

```c
void register_module_init(void (*fn)(void), module_init_type type)
{
    ModuleEntry *e;
    ModuleTypeList *l;

    e = g_malloc0(sizeof(*e));
    e->init = fn;
    e->type = type;

    l = find_type(type);

    QTAILQ_INSERT_TAIL(l, e, node); // 加到 linked list 的尾巴
}
```

- `MODULE_INIT_QOM` 為其中一種 type，用來註冊 device

- 而這些 device 的 register function 會在 `main()` 的一開始被呼叫:

  ```c
  int main(int argc, char **argv, char **envp)
  {
      ...
      error_init(argv[0]);
      module_call_init(MODULE_INIT_TRACE);
      qemu_init_cpu_list();
      module_call_init(MODULE_INIT_QOM);
      ...
  }
  ```

### ObjectClass - base class for all classes

```c
/**
 * struct ObjectClass:
 *
 * The base for all classes.  The only thing that #ObjectClass contains is an
 * integer type handle.
 */
struct ObjectClass
{
    /* private: */
    Type type;
    GSList *interfaces;

    const char *object_cast_cache[OBJECT_CLASS_CAST_CACHE];
    const char *class_cast_cache[OBJECT_CLASS_CAST_CACHE];

    ObjectUnparent *unparent;

    GHashTable *properties;
};
```


### type_initialize() - 用於初始化註冊的 TypeImpl

```c
static void type_initialize(TypeImpl *ti)
{
    TypeImpl *parent;

    if (ti->class) {
        return;
    }
    // 設定大小
    ti->class_size = type_class_get_size(ti);
    ti->instance_size = type_object_get_size(ti);
    /* Any type with zero instance_size is implicitly abstract.
     * This means interface types are all abstract.
     */
    if (ti->instance_size == 0) {
        ti->abstract = true;
    }
    // highest type ?
    if (type_is_ancestor(ti, type_interface)) {
        assert(ti->instance_size == 0);
        assert(ti->abstract);
        assert(!ti->instance_init);
        assert(!ti->instance_post_init);
        assert(!ti->instance_finalize);
        assert(!ti->num_interfaces);
    }
    // 先分配存放 class 的空間
    ti->class = g_malloc0(ti->class_size);

    parent = type_get_parent(ti);
    if (parent) { // 先初始化 parent
        type_initialize(parent); // recursively call
        GSList *e;
        int i;

        g_assert(parent->class_size <= ti->class_size);
        g_assert(parent->instance_size <= ti->instance_size);
        // 將 parent class 的內容複製過去
        memcpy(ti->class, parent->class, parent->class_size);
        ti->class->interfaces = NULL;

        // 取得 parent 的 interface entry，自己也跟著初始化的感覺 ?
        for (e = parent->class->interfaces; e; e = e->next) {
            InterfaceClass *iface = e->data;
            ObjectClass *klass = OBJECT_CLASS(iface);

            type_initialize_interface(ti, iface->interface_type, klass->type);
        }

        for (i = 0; i < ti->num_interfaces; i++) {
            TypeImpl *t = type_get_by_name(ti->interfaces[i].typename);
            if (!t) {
                error_report("missing interface '%s' for object '%s'",
                             ti->interfaces[i].typename, parent->name);
                abort();
            }
            // 找 TypeImpl of interface 的上層並做初始化
            for (e = ti->class->interfaces; e; e = e->next) {
                TypeImpl *target_type = OBJECT_CLASS(e->data)->type;

                if (type_is_ancestor(target_type, t)) {
                    break;
                }
            }

            if (e) {
                continue;
            }

            type_initialize_interface(ti, t, t);
        }
    }

    ti->class->properties = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
                                                  object_property_free);

    ti->class->type = ti;

    // 初始化所有的 parent class
    while (parent) {
        if (parent->class_base_init) {
            parent->class_base_init(ti->class, ti->class_data);
        }
        parent = type_get_parent(parent);
    }

    // 執行 user define 的 init function ?
    if (ti->class_init) {
        ti->class_init(ti->class, ti->class_data);
    }
}
```

- interface 如 `INTERFACE_CONVENTIONAL_PCI_DEVICE`

  ```c
  #define INTERFACE_CONVENTIONAL_PCI_DEVICE "conventional-pci-device"
  ```

### type_initialize_interface() - 初始化 device 內的 interface

```c
static void type_initialize_interface(TypeImpl *ti, TypeImpl *interface_type,
                                      TypeImpl *parent_type)
{
    InterfaceClass *new_iface;
    TypeInfo info = { };
    TypeImpl *iface_impl;

    info.parent = parent_type->name;
    info.name = g_strdup_printf("%s::%s", ti->name, interface_type->name);
    info.abstract = true;

    iface_impl = type_new(&info);
    iface_impl->parent_type = parent_type;
    type_initialize(iface_impl); // 又對 device 的 class 做初始化 @_@
    g_free((char *)info.name);

    new_iface = (InterfaceClass *)iface_impl->class;
    new_iface->concrete_class = ti->class;
    new_iface->interface_type = interface_type;

    ti->class->interfaces = g_slist_append(ti->class->interfaces, new_iface);
}
```

- 不是很懂這邊的行為

### object_initialize() - 建立 device 實例

```c
void object_initialize(void *data, size_t size, const char *typename)
{
    TypeImpl *type = type_get_by_name(typename);

#ifdef CONFIG_MODULES
    if (!type) {
        module_load_qom_one(typename);
        type = type_get_by_name(typename);
    }
#endif
    if (!type) {
        error_report("missing object type '%s'", typename);
        abort();
    }

    object_initialize_with_type(data, size, type);
}
```

- 這個 wrapper 會先取得 `typename` 對應到的 type，並呼叫 `object_initialize_with_type()` 做初始化

```c
static void object_initialize_with_type(Object *obj, size_t size, TypeImpl *type)
{
    type_initialize(type);

    g_assert(type->instance_size >= sizeof(Object));
    g_assert(type->abstract == false);
    g_assert(size >= type->instance_size);

    memset(obj, 0, type->instance_size);
    obj->class = type->class;
    object_ref(obj);
    object_class_property_init_all(obj);
    obj->properties = g_hash_table_new_full(g_str_hash, g_str_equal,
                                            NULL, object_property_free);
    object_init_with_type(obj, type);
    object_post_init_with_type(obj, type);
}
```

### DeviceClass - 許多 device 的 parent class

```c
/**
 * DeviceClass:
 * @props: Properties accessing state fields.
 * @realize: Callback function invoked when the #DeviceState:realized
 * property is changed to %true.
 * @unrealize: Callback function invoked when the #DeviceState:realized
 * property is changed to %false.
 * @hotpluggable: indicates if #DeviceClass is hotpluggable, available
 * as readonly "hotpluggable" property of #DeviceState instance
 *
 * # Realization #
 * Devices are constructed in two stages,
 * 1) object instantiation (實例化) via object_initialize() and
 * 2) device realization (實現) via #DeviceState:realized property.
 * The former may not fail (and must not abort or exit, since it is called
 * during device introspection already), and the latter may return error
 * information to the caller and must be re-entrant.
 * Trivial field initializations should go into #TypeInfo.instance_init.
 * Operations depending on @props static properties should go into @realize.
 * After successful realization, setting static properties will fail.
 *
 * As an interim step, the #DeviceState:realized property can also be
 * set with qdev_realize().
 * In the future, devices will propagate this state change to their children
 * and along busses they expose.
 * The point in time will be deferred to machine creation, so that values
 * set in @realize will not be introspectable beforehand. Therefore devices
 * must not create children during @realize; they should initialize them via
 * object_initialize() in their own #TypeInfo.instance_init and forward the
 * realization events appropriately.
 *
 * Any type may override the @realize and/or @unrealize callbacks but needs
 * to call the parent type's implementation if keeping their functionality
 * is desired. Refer to QOM documentation for further discussion and examples.
 *
 * <note>
 *   <para>
 * Since TYPE_DEVICE doesn't implement @realize and @unrealize, types
 * derived directly from it need not call their parent's @realize and
 * @unrealize.
 * For other types consult the documentation and implementation of the
 * respective parent types.
 *   </para>
 * </note>
 *
 * # Hiding a device #
 * To hide a device, a DeviceListener function hide_device() needs to
 * be registered.
 * It can be used to defer adding a device and therefore hide it from
 * the guest. The handler registering to this DeviceListener can save
 * the QOpts passed to it for re-using it later. It must return if it
 * wants the device to be hidden or visible. When the handler function
 * decides the device shall be visible it will be added with
 * qdev_device_add() and realized as any other device. Otherwise
 * qdev_device_add() will return early without adding the device. The
 * guest will not see a "hidden" device until it was marked visible
 * and qdev_device_add called again.
 *
 */
struct DeviceClass {
    /*< private >*/
    ObjectClass parent_class;
    /*< public >*/

    DECLARE_BITMAP(categories, DEVICE_CATEGORY_MAX);
    const char *fw_name;
    const char *desc;

    /*
     * The underscore at the end ensures a compile-time error if someone
     * assigns to dc->props instead of using device_class_set_props.
     */
    Property *props_;

    /*
     * Can this device be instantiated with -device / device_add?
     * All devices should support instantiation with device_add, and
     * this flag should not exist.  But we're not there, yet.  Some
     * devices fail to instantiate with cryptic error messages.
     * Others instantiate, but don't work.  Exposing users to such
     * behavior would be cruel; clearing this flag will protect them.
     * It should never be cleared without a comment explaining why it
     * is cleared.
     * TODO remove once we're there
     */
    bool user_creatable;
    /*
	傳統的 PCI, ISA 都需要在電腦處於冷機的時候，才能插上裝置
	而 hotplug 不必讓電腦關機、切斷電源後就能插上裝置
	e.g. 隨身碟
    */
    bool hotpluggable;

    /* callbacks */
    /*
     * Reset method here is deprecated and replaced by methods in the
     * resettable class interface to implement a multi-phase reset.
     * TODO: remove once every reset callback is unused
     */
    DeviceReset reset;
    DeviceRealize realize;
    DeviceUnrealize unrealize;

    /* device state */
    const VMStateDescription *vmsd;

    /* Private to qdev / bus.  */
    const char *bus_type;
};
```

### device_initfn

```c
static void device_initfn(Object *obj)
{
    DeviceState *dev = DEVICE(obj);

    if (phase_check(PHASE_MACHINE_READY)) {
        dev->hotplugged = 1;
        qdev_hot_added = true;
    }

    dev->instance_id_alias = -1;
    dev->realized = false;
    dev->allow_unplug_during_migration = false;

    QLIST_INIT(&dev->gpios);
    QLIST_INIT(&dev->clocks);
}
```

- 做一些簡單的初始化，然後放到 `QLIST_INIT` 內

```c
static void device_class_init(ObjectClass *class, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    VMStateIfClass *vc = VMSTATE_IF_CLASS(class);
    ResettableClass *rc = RESETTABLE_CLASS(class);

    class->unparent = device_unparent;

    /* by default all devices were considered as hotpluggable,
     * so with intent to check it in generic qdev_unplug() /
     * device_set_realized() functions make every device
     * hotpluggable. Devices that shouldn't be hotpluggable,
     * should override it in their class_init()
     */
    dc->hotpluggable = true;
    dc->user_creatable = true;
    vc->get_id = device_vmstate_if_get_id;
    rc->get_state = device_get_reset_state;
    rc->child_foreach = device_reset_child_foreach;

    /*
     * @device_phases_reset is put as the default reset method below, allowing
     * to do the multi-phase transition from base classes to leaf classes. It
     * allows a legacy-reset Device class to extend a multi-phases-reset
     * Device class for the following reason:
     * + If a base class B has been moved to multi-phase, then it does not
     *   override this default reset method and may have defined phase methods.
     * + A child class C (extending class B) which uses
     *   device_class_set_parent_reset() (or similar means) to override the
     *   reset method will still work as expected. @device_phases_reset function
     *   will be registered as the parent reset method and effectively call
     *   parent reset phases.
     */
    dc->reset = device_phases_reset;
    rc->get_transitional_function = device_get_transitional_reset;

    object_class_property_add_bool(class, "realized",
                                   device_get_realized, device_set_realized);
    object_class_property_add_bool(class, "hotpluggable",
                                   device_get_hotpluggable, NULL);
    object_class_property_add_bool(class, "hotplugged",
                                   device_get_hotplugged, NULL);
    object_class_property_add_link(class, "parent_bus", TYPE_BUS,
                                   offsetof(DeviceState, parent_bus), NULL, 0);
}
```

- property 設置通常可以在執行 qemu 時透過給參數來賦予，不過在此先初始化了 `realized`, `hotpluggable`, `hotplugged` 這三個屬性

```c
static const TypeInfo device_type_info = {
    .name = TYPE_DEVICE,
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(DeviceState),
    .instance_init = device_initfn, // 負責初始化 instance
    .instance_post_init = device_post_init,
    .instance_finalize = device_finalize,
    .class_base_init = device_class_base_init,
    .class_init = device_class_init, // 負責初始化 class
    .abstract = true,
    .class_size = sizeof(DeviceClass),
    .interfaces = (InterfaceInfo[]) {
        { TYPE_VMSTATE_IF },
        { TYPE_RESETTABLE_INTERFACE },
        { }
    }
};
```

### MemoryRegion - 關於 VM 當中的記憶體結構

```c
/** MemoryRegion:
 *
 * A struct representing a memory region.
 */
struct MemoryRegion {
    Object parent_obj;

    /* private: */

    /* The following fields should fit in a cache line */
    bool romd_mode;
    bool ram;
    bool subpage;
    bool readonly; /* For RAM regions */
    bool nonvolatile;
    bool rom_device;
    bool flush_coalesced_mmio;
    uint8_t dirty_log_mask;
    bool is_iommu;
    RAMBlock *ram_block;
    Object *owner;

    const MemoryRegionOps *ops;
    void *opaque; // 不透明 (?
    MemoryRegion *container;
    Int128 size;
    hwaddr addr;
    void (*destructor)(MemoryRegion *mr);
    uint64_t align;
    bool terminates;
    bool ram_device;
    bool enabled;
    bool warning_printed; /* For reservations */
    uint8_t vga_logging_count;
    MemoryRegion *alias;
    hwaddr alias_offset;
    int32_t priority;
    // memory region 實際上是用 tree 資料結構來儲存
    QTAILQ_HEAD(, MemoryRegion) subregions;
    QTAILQ_ENTRY(MemoryRegion) subregions_link;
    QTAILQ_HEAD(, CoalescedMemoryRange) coalesced;
    const char *name;
    unsigned ioeventfd_nb;
    MemoryRegionIoeventfd *ioeventfds;
    RamDiscardManager *rdm; /* Only for RAM */
};
```

- `main()` --> `qemu_init()`
  - `qemu_create_machine()`
    - `cpu_exec_init_all()`
      - `io_mem_init()`
      - `memory_map_init()`

與 memory 相關的結構還有 `AddressSpace`:

```c
/**
 * struct AddressSpace: describes a mapping of addresses to #MemoryRegion objects
 */
struct AddressSpace {
    /* private: */
    struct rcu_head rcu;
    char *name;
    MemoryRegion *root; // root of MemoryRegion tree

    /* Accessed via RCU.  */
    struct FlatView *current_map;

    int ioeventfd_nb;
    struct MemoryRegionIoeventfd *ioeventfds;
    QTAILQ_HEAD(, MemoryListener) listeners;
    QTAILQ_ENTRY(AddressSpace) address_spaces_link;
};
```

- `struct FlatView` 儲存被攤平的 `MemoryRegion`

- `generate_memory_topology()` - render a memory topology into a list of disjoint absolute ranges

  - `render_memory_region()` - render a memory region into the global view.  Ranges in @view obscure

  - `flatview_add_to_dispatch()`:

    ```c
    /*
     * The range in *section* may look like this:
     *
     *      |s|PPPPPPP|s|
     *
     * where s stands for subpage and P for page.
     */
    ```

- `address_space_set_flatview()` - 構建結構 `AddressSpaceDispatch`

  ```c
  struct AddressSpaceDispatch {
      // MemoryRegionSection
      // @describes a fragment of a #MemoryRegion
      MemoryRegionSection *mru_section;
      /* This is a multi-level map on the physical address space.
       * The bottom level has pointers to MemoryRegionSections.
       */
      PhysPageEntry phys_map;
      PhysPageMap map;
  };
  
  struct PhysPageEntry {
      /* How many bits skip to next level (in units of L2_SIZE). 0 for a leaf. */
      uint32_t skip : 6;
       /* index into phys_sections (!skip) or phys_map_nodes (skip) */
      uint32_t ptr : 26;
  };
  ```

  - `phys_map` - contains the physical address of the base address of the page directory table
    - 像是 CR3 

### memory_region_init() - 初始化 memory region

```c
void memory_region_init(MemoryRegion *mr,
                        Object *owner,
                        const char *name,
                        uint64_t size)
{
    object_initialize(mr, sizeof(*mr), TYPE_MEMORY_REGION);
    memory_region_do_init(mr, owner, name, size);
}
```

- 是一個 wrapper，內部用了 `object_initialize()` 先初始化 object，再透過 `memory_region_do_init()` 初始化 `MemoryRegion`

### RAMBlock - 與 VM mapping 的記憶體有關

```c
struct RAMBlock {
    struct rcu_head rcu;
    struct MemoryRegion *mr;
    uint8_t *host;
    uint8_t *colo_cache; /* For colo, VM's ram cache */
    ram_addr_t offset;
    ram_addr_t used_length;
    ram_addr_t max_length;
    void (*resized)(const char*, uint64_t length, void *host);
    uint32_t flags;
    /* Protected by iothread lock.  */
    char idstr[256];
    /* RCU-enabled, writes protected by the ramlist lock */
    QLIST_ENTRY(RAMBlock) next;
    QLIST_HEAD(, RAMBlockNotifier) ramblock_notifiers;
    int fd;
    size_t page_size;
    /* dirty bitmap used during migration */
    unsigned long *bmap;
    /* bitmap of already received pages in postcopy */
    unsigned long *receivedmap;

    /*
     * bitmap to track already cleared dirty bitmap.  When the bit is
     * set, it means the corresponding memory chunk needs a log-clear.
     * Set this up to non-NULL to enable the capability to postpone
     * and split clearing of dirty bitmap on the remote node (e.g.,
     * KVM).  The bitmap will be set only when doing global sync.
     *
     * NOTE: this bitmap is different comparing to the other bitmaps
     * in that one bit can represent multiple guest pages (which is
     * decided by the `clear_bmap_shift' variable below).  On
     * destination side, this should always be NULL, and the variable
     * `clear_bmap_shift' is meaningless.
     */
    unsigned long *clear_bmap;
    uint8_t clear_bmap_shift;

    /*
     * RAM block length that corresponds to the used_length on the migration
     * source (after RAM block sizes were synchronized). Especially, after
     * starting to run the guest, used_length and postcopy_length can differ.
     * Used to register/unregister uffd handlers and as the size of the received
     * bitmap. Receiving any page beyond this length will bail out, as it
     * could not have been valid on the source.
     */
    ram_addr_t postcopy_length;
};
```

- qemu 在記憶體映射的處理:
  - `pc_memory_init()`
  - `memory_region_init_ram()`
    - `memory_region_init_ram_nomigrate()`
      - `memory_region_init_ram_flags_nomigrate()`
        - `memory_region_init()` - Initialize a memory region. The region typically acts as a container for other memory regions. Use `memory_region_add_subregion()` to add subregions
        - `qemu_ram_alloc()`
          - `qemu_ram_alloc_internal()`
    - `vmstate_register_ram()`
- `RAMBlock->host` 就是 HVA
- `MemoryRegion->addr` 就是 GPA

### x86_cpu_realizefn - 實例化 CPU，而 CPU 與 APIC 通常是綁在一起

- `x86_cpu_realizefn()`
  - `x86_cpu_apic_create()` - 建立 APIC
    - 設置 cpu prop 與 apic 相關的 `"id"`, `"lapic"`
  - `x86_cpu_apic_realize()`
    - `qdev_realize()`



### APICCommonState - 描述 APIC 的結構

```c
struct APICCommonState {
    /*< private >*/
    DeviceState parent_obj;
    /*< public >*/

    MemoryRegion io_memory; // 初始化時註冊的 memory region
    X86CPU *cpu;
    uint32_t apicbase; // default APIC 存取的位址 (?)
    uint8_t id; /* legacy APIC ID */
    uint32_t initial_apic_id;
    uint8_t version;
    uint8_t arb_id;
    uint8_t tpr;
    uint32_t spurious_vec;
    uint8_t log_dest;
    uint8_t dest_mode;
    uint32_t isr[8];  /* in service register */
    uint32_t tmr[8];  /* trigger mode register */
    uint32_t irr[8]; /* interrupt request register */
    uint32_t lvt[APIC_LVT_NB];
    uint32_t esr; /* error register */
    uint32_t icr[2];

    uint32_t divide_conf;
    int count_shift;
    uint32_t initial_count;
    int64_t initial_count_load_time;
    int64_t next_time;
    QEMUTimer *timer;
    int64_t timer_expiry;
    int sipi_vector;
    int wait_for_sipi;

    uint32_t vapic_control;
    DeviceState *vapic;
    hwaddr vapic_paddr; /* note: persistence via kvmvapic */
    bool legacy_instance_id;
};
```

### MemoryRegionOps apic_io_ops - 定義 apic 作為 device 會使用到的 function

```c
static const MemoryRegionOps apic_io_ops = {
    .read = apic_mem_read,
    .write = apic_mem_write,
    .impl.min_access_size = 1,
    .impl.max_access_size = 4,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .endianness = DEVICE_NATIVE_ENDIAN,
};
```

### apic_mem_write - 寫入 APIC address 會執行的 function

```c
...
    case 0x30:
        s->icr[0] = val;
        apic_deliver(dev, (s->icr[1] >> 24) & 0xff, (s->icr[0] >> 11) & 1,
                     (s->icr[0] >> 8) & 7, (s->icr[0] & 0xff),
                     (s->icr[0] >> 15) & 1);
        break;
...
```





關於 instance_init() vs. realize() 可以參考[這篇文章](http://people.redhat.com/~thuth/blog/qemu/2018/09/10/instance-init-realize.html)

- 有三種常見的 initialization function - class_init, instance_init, realize
  - `instance_init()` 會被先叫到，之後才會叫到 `realize()`
    - 前者不會失敗，後者會
  - instance 對應到的是 `TypeInfo`
  - realize 作用於 `DeviceClass`
  - instance 可以不需要 realized 就被 instantiated 與 finalized



加上 property:

- 靜態 - `DEFINE_PROP_*` 相關的 macro
- 動態 - `object_property_add()`
  - `object_property_add_child()`
- 調整
  - `object_property_set_<type>()`
  - `object_property_get_<type>()`
  - setter / getter 的感覺 (?)



device 之間的關係:

- child
  - 代表一個 device (parent) 建立另一個 device，並且由 parent 掌握 child 的生命週期與發送相關事件
  - 一個 device 只有一個 parent，但能有多個 child
- link
  - backlink 表示一個 device 引用另一個 device



KVM 當中的 Guest mode 對應到的是 CPU 的 VMX non-root mode

virtio 省去了純模擬模式下 catch trap 的部分，Guest OS 可以和 QEMU 的 I/O 模組直接溝通

QEMU-KVM - KVM 負責存取 CPU 與記憶體，而 QEMU 則用以模擬其它硬體資源 (如硬碟、網路、顯示、USB)

Posted Interrupt - Posted-interrupt processing is a feature by which a processor processes the virtual interrupts by **recording them as pending** on the **virtual-APIC page**





Others:

- APIC - Advanced Programmable Interrupt Controller
- SRAT - System Resource Affinity Table
- SLIT - System Locality Information Table
- GPA - Guest Physical Address
- HVP - Host Virtual Address
- MSI - Message Signaled Interrupts
- IPI - Inter-Processor Interrupt
- SDM - Sofeware Developer Manual
- TPR - Task-Priority Register
- RVI / SVI
  - RVI - Requesting virtual interrupt (low byte)
  - SVI - Servicing virtual interrupt (high byte)

- EOI - end of interrupt 
- PIR - Posted Interrupt Requests
- VIRR - Virtual interrupt-request register
- RDMA- remote direct memory access

