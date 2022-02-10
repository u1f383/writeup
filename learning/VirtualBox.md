## README

### binary overview

virtual box 的檔案以及其對應功能：

![image-20220206173254017](/Users/u1f383/Library/Application Support/typora-user-images/image-20220206173254017.png)



virtual box 內部與 guest 溝通的流程：

<img src="/Users/u1f383/Library/Application Support/typora-user-images/image-20220206173344182.png" alt="image-20220206173344182" style="zoom:50%;" />



照下方區分：

- CPU 有支援硬體虛擬化技術，guest 的執行狀態 - AMD-V / VT-x
- Host 環境
- CPU 沒支援時，guest 的執行狀態 - Raw-Mode

![image-20220206173609555](/Users/u1f383/Library/Application Support/typora-user-images/image-20220206173609555.png)



## virtualbox源码分析筆記

### 1

- Virtualbox.exe - VM management interface
- VirtualboxVM.exe - 有 UI 的 VM instance
- VBoxSVC.exe - SVC == service，提供一些 **com** interface 與 virtualboxVM.exe 互動，管理**所有的 VM 以及其 config**



### 2

目錄結構：

```
VBox
├── Additions
├── Artwork // 圖標之類的
├── Debugger
├── Devices // 設備模擬的 source (audio, pc, storage)
├── Disassembler
├── ExtPacks
├── Frontends
├── GuestHost // 跟 clipboard 相關
├── HostDrivers // 裝到 host 內的 driver
├── HostServices // 一些服務如 shared folder
├── ImageMounter
├── Installer
├── Main
├── Makefile.kmk
├── NetworkServices // NAT / DHCP 網路相關
├── RDP
├── Runtime // 類似 util 的存在
├── Storage
├── VMM // VM manager，虛擬化的核心 (VT / device / CPU / memory ... 的虛擬化)
└── ValidationKit
```



### 3

名詞解釋

- VT - Virtualization Technology
- GVA --> HPA
  - Shadow Page Table - 用軟體實現
  - EPT - Extended Page Table，專屬於 VM 的 page table



### 4

VMX 使用到的指令以及狀態的切換：

![image-20220206185900177](/Users/u1f383/Library/Application Support/typora-user-images/image-20220206185900177.png)

- VMXON - 進入 VMX root mode
- VMXOFF - 離開 VMX root mode
- VMExit - non-root 切到 root
- VMEntry - root 切到 non-root

VMCS (Virtual Machine Control Structure)

- 三種狀態：  launched, clear, active，每個實體 CPU 只能有一個 active / launched

  <img src="/Users/u1f383/Library/Application Support/typora-user-images/image-20220206190249065.png" alt="image-20220206190249065" style="zoom:50%;" />

  - VMCLEAR - 把目前的 CPU 設置成 clear 狀態
  - VMPTRLD - 將 CPU 的 VMCS 的 pointer 更新成傳入的物理位址

- 透過 VMEntry 進入 guest os 執行，在需要 host os 的幫助時執行 VMExit 回到 host 做處理

  - 呼叫 VMExit 的時間點透過 **VMCS** 來設定，如 `VMX_EXIT_CPUID` 就是控制 guest os 在執行 `cpuid` 的 instruction 時會觸發 VMExit，回到 host os 內，而且 VB 提供隨時更新 VMCS，動態控制要回來的時機
  - VMExit 的成本很高，而 VB 也提供了比較細粒度的控制，指定 MSR 內的哪些 register 被存取時才會 VMExit



### 5

> 分析 VB 內 R0 的部分，Virtualbox 版本為 6.1.32，過程中刪除一些錯誤處理以及相對不重要的部分

---

`HMR0Init(void)` - Does global Ring-0 HM initialization (at module init)，會提供一些 API 給 r3 呼叫

- HM - **Hardware Acceleration Manager** or **Hardware Assisted Virtualization Manager**，負責處理 VT-X 或 AMD-V 的相關資源

```c
g_HmR0.fEnabled = false; // 如果 CPU 都 init，則會是 true
static RTONCE s_OnceInit = RTONCE_INITIALIZER; // 只需要 init 一次即可 (once)
g_HmR0.EnableAllCpusOnce = s_OnceInit; // 在 HMR0EnableAllCpus() 用來設置 cpu
for (unsigned i = 0; i < RT_ELEMENTS(g_HmR0.aCpuInfo); i++)
{
    g_HmR0.aCpuInfo[i].idCpu        = NIL_RTCPUID; // CPU 的 ID
    g_HmR0.aCpuInfo[i].hMemObj      = NIL_RTR0MEMOBJ; // memory object
    g_HmR0.aCpuInfo[i].HCPhysMemObj = NIL_RTHCPHYS; // HC 我猜是 host context，因此代表 host 內的 memory object
    g_HmR0.aCpuInfo[i].pvMemObj     = NULL; // pv short for ?
#ifdef VBOX_WITH_NESTED_HWVIRT_SVM
...
#endif
}

// 將 callback function 初始化成一些 dummy function
g_HmR0.pfnEnterSession      = hmR0DummyEnter;
...
g_HmR0.pfnSetupVM           = hmR0DummySetupVM;

// 預設會初始化 VT-x/AMD-V ?
g_HmR0.fGlobalInit         = true;
```

- `g_HmR0` 為 global variable，負責儲存 R0 中 VT 的相關資料
- `RTONCE` 用來描述只執行一次的行為的結構

```c
// aCpuInfo 結構需要夠大，預設為 256 大小的 array
if (RTMpGetArraySize() > RT_ELEMENTS(g_HmR0.aCpuInfo))
{
	... // 實際的 cpu / core / thread 太多了
}

uint32_t fCaps = 0;
int rc = SUPR0GetVTSupport(&fCaps); // 看是否 support VT，如果 support 的話是 VT-X 還是 AMD-V
if (RT_SUCCESS(rc))
{
    if (fCaps & SUPVTCAPS_VT_X)
    	rc = hmR0InitIntel(); // 初始化 VT-X
    else
        rc = hmR0InitAmd(); // 初始化 AMD-V
}
else
    g_HmR0.rcInit = VERR_UNSUPPORTED_CPU; // 什麼都沒支援
```

```c
// 註冊用於通知的 callback function，當 suspend/resume 時可以用來關閉/開啟 CPU
if (!g_HmR0.hwvirt.u.vmx.fUsingSUPR0EnableVTx)
{
    rc = RTMpNotificationRegister(hmR0MpEventCallback, NULL);
    rc = RTPowerNotificationRegister(hmR0PowerCallback, NULL);
}

return VINF_SUCCESS;
```

而在 `hmR0InitIntel()` 與 `hmR0InitAmd()` 當中，會分別初始化 **VMX** 以及 **SVM**，其中除了 CPU 的設置 (一些 MSR 的存取)，還初始化了 callback function：

```c
static int hmR0InitIntel(void)
{
    ...
    g_HmR0.pfnEnterSession      = VMXR0Enter;
    g_HmR0.pfnThreadCtxCallback = VMXR0ThreadCtxCallback;
    g_HmR0.pfnCallRing3Callback = VMXR0CallRing3Callback;
    g_HmR0.pfnExportHostState   = VMXR0ExportHostState;
    g_HmR0.pfnRunGuestCode      = VMXR0RunGuestCode;
    g_HmR0.pfnEnableCpu         = VMXR0EnableCpu;
    g_HmR0.pfnDisableCpu        = VMXR0DisableCpu;
    g_HmR0.pfnInitVM            = VMXR0InitVM;
    g_HmR0.pfnTermVM            = VMXR0TermVM;
    g_HmR0.pfnSetupVM           = VMXR0SetupVM;
    ...
}
```

```c
static int hmR0InitAmd(void)
{
	...
    g_HmR0.pfnEnterSession      = SVMR0Enter;
    g_HmR0.pfnThreadCtxCallback = SVMR0ThreadCtxCallback;
    g_HmR0.pfnCallRing3Callback = SVMR0CallRing3Callback;
    g_HmR0.pfnExportHostState   = SVMR0ExportHostState;
    g_HmR0.pfnRunGuestCode      = SVMR0RunGuestCode;
    g_HmR0.pfnEnableCpu         = SVMR0EnableCpu;
    g_HmR0.pfnDisableCpu        = SVMR0DisableCpu;
    g_HmR0.pfnInitVM            = SVMR0InitVM;
    g_HmR0.pfnTermVM            = SVMR0TermVM;
    g_HmR0.pfnSetupVM           = SVMR0SetupVM;
	...
}
```

而本次分析主要 focus 在 Intel 的 VMX。

---

`hmR0InitIntel()` - Intel specific initialization code



---

`VMXR0SetupVM()` - Sets up the VM for execution using hardware-assisted VMX，此 function 只會在每個 VM 初始化時被呼叫**一次**

- 此 function 會在 VMX ROOT mode 被執行
- `PVMCC` 等同於 `PVM`，而 `PVM` 為 `VM` pointer，`struct VM` 用來保存 VM data

```c
// 檢查當前是否存在於 VMX mode，cr4 的 13-th bit 用來標記是否 enable VMX
RTCCUINTREG const uHostCr4 = ASMGetCR4();
if (RT_LIKELY(uHostCr4 & X86_CR4_VMXE))
{ /* likely */ }
else
    return VERR_VMX_NOT_IN_VMX_ROOT_MODE;

// 在沒有開啟 unrestricted guest 的情況下，EPT 跟 real mode TSS 需要初始化才行
if (!pVM->hm.s.vmx.fUnrestrictedGuest
    && (!pVM->hm.s.vmx.pNonPagingModeEPTPageTable || !pVM->hm.s.vmx.pRealModeTSS))
{ return VERR_INTERNAL_ERROR; }

pVM->hm.s.vmx.enmTlbFlushEpt  = VMXTLBFLUSHEPT_NONE; // 預設不 handle 'INVEPT' insn
pVM->hm.s.vmx.enmTlbFlushVpid = VMXTLBFLUSHVPID_NONE; // 同上 for 'INVVPID' insn 

// 設置 tagged-TLB flush handler，在 VMEntry 前會被呼叫
int rc = hmR0VmxSetupTaggedTlb(pVM);
```

```c
// 如果 LBR 開啟就初始化
if (pVM->hm.s.vmx.fLbr) { rc = hmR0VmxSetupLbrMsrRange(pVM); }

#ifdef VBOX_WITH_NESTED_HWVIRT_VMX
...
#endif

// 為每個 CPU 都設置對應的 VMCS
for (VMCPUID idCpu = 0; idCpu < pVM->cCpus; idCpu++)
{
    PVMCPUCC pVCpu = VMCC_GET_CPU(pVM, idCpu);
    rc = hmR0VmxSetupVmcs(pVCpu, &pVCpu->hm.s.vmx.VmcsInfo, false);
    if (RT_SUCCESS(rc))
    {
#ifdef VBOX_WITH_NESTED_HWVIRT_VMX
...
#endif
    }
}
```

- LBR - last branch record

---

`hmR0VmxSetupVmcs()` - 為每個**使用 VMX** 的 VM 都設置對應的 VMCS

```c
PVMCC pVM = pVCpu->CTX_SUFF(pVM); // 展開後為 pVMR3
// 在 VMCS 的開頭寫入一個 CPU specified revision id
*(uint32_t *)pVmcsInfo->pvVmcs = RT_BF_GET(pVM->hm.s.vmx.Msrs.u64Basic, VMX_BF_BASIC_VMCS_ID);
const char * const pszVmcs     = fIsNstGstVmcs ? "nested-guest VMCS" : "guest VMCS";

LogFlowFunc(("\n"));

int rc = hmR0VmxClearVmcs(pVmcsInfo); // 用 VMCLEAR 來初始化 VMCS 結構
rc = hmR0VmxLoadVmcs(pVmcsInfo); // 以 pVmcsInfo->HCPhysVmcs 作為 VMCS pointer
pVmcsInfo->pfnStartVM = VMXR0StartVM64; // 初始化 execution handler
// 設置 pin-based VM-execution controls
rc = hmR0VmxSetupVmcsPinCtls(pVCpu, pVmcsInfo);
// 設置 processor-based VM-execution controls
rc = hmR0VmxSetupVmcsProcCtls(pVCpu, pVmcsInfo);
// 設置 miscellaneous control fields
rc = hmR0VmxSetupVmcsMiscCtls(pVCpu, pVmcsInfo);
// 設置 exception bitmap
hmR0VmxSetupVmcsXcptBitmap(pVCpu, pVmcsInfo);
#ifdef VBOX_WITH_NESTED_HWVIRT_VMX
	...
#endif
```

- pVMR3 為 Ring-3 Host Context VM Pointer
- `hmR0VmxLoadVmcs()` --> `VMXLoadVmcs()`，為 `VMPTRLD` handler
- `pv` prefix 似乎是指 `void *` (pointer of void)
- `pfn` 為 function pointer type
- `VMXR0StartVM64()` - 在執行 guest code 時會呼叫到 `hmR0VmxRunGuest()`，而內部會呼叫此 function 來執行 VM，並且 vbox 只支援 64-bit 的 host (function suffix **64**)

```c
if (RT_SUCCESS(rc))
{
    // 間接呼叫到 VMXClearVmcs() 來同步 pVmcsInfo->HCPhysVmcs 與 CPU 內的 VMCS 資料
    rc = hmR0VmxClearVmcs(pVmcsInfo);
    ...
}
```

- `VMXClearVmcs()` 為 `VMCLEAR` 的 handler
- `VMCLEAR` 不僅可以初始化 VMCS，也可以將 CPU processor 內的 VMCS 資料複製到 memory 當中的 VMCS

---

`VMXR0Enter()` - Enters the VT-x session，載入對應的 VMCS，使其狀態變成 active / current

```c
#ifdef VBOX_STRICT
...
#endif

// 首先檢查所屬的 mode，在取得 CPU VMCS 結構
PVMXVMCSINFO pVmcsInfo;
bool const fInNestedGuestMode = CPUMIsGuestInVmxNonRootMode(&pVCpu->cpum.GstCtx);
if (!fInNestedGuestMode)
    pVmcsInfo = &pVCpu->hm.s.vmx.VmcsInfo;
else
    pVmcsInfo = &pVCpu->hm.s.vmx.VmcsInfoNstGst;

int rc = hmR0VmxLoadVmcs(pVmcsInfo); // VMPTRLD
if (RT_SUCCESS(rc))
{
    pVCpu->hm.s.fLeaveDone = false; // 是否完成 HM leave function

    // fL1dFlushOnSched: L1 data cache 要在 scheduling 時被 flush
    if (pVCpu->CTX_SUFF(pVM)->hm.s.fL1dFlushOnSched)
        ASMWrMsr(MSR_IA32_FLUSH_CMD, MSR_IA32_FLUSH_CMD_F_L1D);
    // fMdsClearOnSched: MDS buffers 要在 scheduling 時被 clear
    else if (pVCpu->CTX_SUFF(pVM)->hm.s.fMdsClearOnSched)
        hmR0MdsClear();
}
return rc;
```

- `CPUMIsGuestInVmxNonRootMode()` - 檢查 guest 是否存在於 non-root
- `CTX_SUFF(pVM)` 展開就是 `pVMR3`
- MDS - Metadata Service

---

`VMXR0EnableCpu()` - Sets up and activates VT-x on the current CPU

```c
// 如果還沒開啟 VT-X 就開啟
if (!fEnabledByHost)
	hmR0VmxEnterRootMode(pHostCpu, pVM, HCPhysCpuPage, pvCpuPage);

// flush 所有 EPT 內的 tagged-TLB entries，因為 entry 在 VPID 相同時不會 flush 掉，但是 entry 當中可能會有舊的 mapping
if (pHwvirtMsrs->u.vmx.u64EptVpidCaps & MSR_IA32_VMX_EPT_VPID_CAP_INVEPT_ALL_CONTEXTS)
{
    hmR0VmxFlushEpt(NULL, NULL, VMXTLBFLUSHEPT_ALL_CONTEXTS);
    // 是否要對新的 ASID/VPID flush 其 TLB entry (?
    // false (不需要) 的原因應該是在這邊已經 flush 完了
    pHostCpu->fFlushAsidBeforeUse = false;
}
else
    pHostCpu->fFlushAsidBeforeUse = true;

// 官方註解表示，這個操作能確保每個在當前 physical CPU 上的 VCPU 在恢復 (resume) 時都有新的 VPID (?)
++pHostCpu->cTlbFlushes; // 增加 tlb flush count

return VINF_SUCCESS;
```

- VPID - Virtual-Processor Identifier，每個 VCPU 都會有一個唯一的 VPID，並且每個 TLB entry 對應到一個 VPID
  - 當進行 GVA 到 HPA 轉換時，當 TLB entry 對應的 VPID 與正在運行的 VM 的 VCPU 的 VPID 相同時，才可以使用該 TLB entry，減少了 TLB flush 的次數

---

`hmR0VmxEnterRootMode()` - Enters VMX root mode operation on the current CPU

```c
if (pVM)
    // 在 VMXON region 中寫入 VMCS revision id
    *(uint32_t *)pvCpuPage = RT_BF_GET(pVM->hm.s.vmx.Msrs.u64Basic, VMX_BF_BASIC_VMCS_ID);

// interrupt 可能會用壞 cr4，因此先 disable 掉 (cli)
RTCCUINTREG const fEFlags = ASMIntDisableFlags();

// set VMX bit in cr4
RTCCUINTREG const uOldCr4 = SUPR0ChangeCR4(X86_CR4_VMXE, RTCCUINTREG_MAX);
// fVmxeAlreadyEnabled: 紀錄 VMXE 是否已經被 set (透過上面的 code)
pHostCpu->fVmxeAlreadyEnabled = RT_BOOL(uOldCr4 & X86_CR4_VMXE);

/* Enter VMX root mode. */
// Executes VMXON
int rc = VMXEnable(HCPhysCpuPage); // 執行 VMXON
// 重新 enable interrupt (sti)
ASMSetFlags(fEFlags);
return rc;
```

- 變數 `pvCpuPage` - pointer to the VMXON region
- 變數 `HCPhysCpuPage` - physical address of VMXON structure

---

`VMXR0DisableCpu()` - Deactivates VT-x on the current CPU，實際為呼叫 `hmR0VmxLeaveRootMode()` 的 wrapper function

```c
...
return hmR0VmxLeaveRootMode(pHostCpu);
```

---

`hmR0VmxLeaveRootMode()` - Exits VMX root mode operation on the current CPU

```c
// 相同於 VMXR0EnableCpu()
RTCCUINTREG const fEFlags = ASMIntDisableFlags();

// 先檢查是不是在 VMX root mode，如果不在也不需要離開
RTCCUINTREG const uHostCr4 = ASMGetCR4();

int rc;
if (uHostCr4 & X86_CR4_VMXE)
{
    VMXDisable(); // 單純執行 VMXOFF insn

	// 若 pHostCpu (HM physical-CPU structure) 紀錄 VMXE 沒被設置，就更新到 host 的 cr4
    if (!pHostCpu->fVmxeAlreadyEnabled)
        SUPR0ChangeCR4(0, ~(uint64_t)X86_CR4_VMXE);
    rc = VINF_SUCCESS;
}
ASMSetFlags(fEFlags); // 恢復 interrupt
return rc;
```

- 執行時會需要確保 memory 所記錄的 (`pHostCpu`) 與實際 host CPU 內的是否同步

---

`VMXR0InitVM()` - Does per-VM VT-x initialization

```c
hmR0VmxStructsInit(pVM);
int rc = hmR0VmxStructsAlloc(pVM);
return VINF_SUCCESS;
```

- `hmR0VmxStructsInit()` - Pre-initializes non-zero fields in VMX structures that will be allocated

  ```c
  // 初始化一些欄位的值成 NIL (null)
  pVM->hm.s.vmx.HCPhysApicAccess    = NIL_RTHCPHYS;
  ...
  for (VMCPUID idCpu = 0; idCpu < pVM->cCpus; idCpu++)
  {
      PVMCPUCC pVCpu = VMCC_GET_CPU(pVM, idCpu); // 取得當前 VM 對應使用到的 VCPU
      hmR0VmxVmcsInfoInit(&pVCpu->hm.s.vmx.VmcsInfo); // 初始化 VMCS info
  }
  ```

- `hmR0VmxVmcsInfoInit()` - Initializes a VMCS info. object，初始化 `VMCSinfo`，`VMCSinfo` 像是 VMCS 的 metadata

  ```c
  memset(pVmcsInfo, 0, sizeof(*pVmcsInfo));
  pVmcsInfo->HCPhysVmcs          = NIL_RTHCPHYS;
  ...
  pVmcsInfo->idHostCpuExec       = NIL_RTCPUID;
  ```

---

`hmR0VmxStructsAlloc()` - Allocate all VT-x structures for the VM，除了為 VMX pages 分配 pages，同時也初始化了 VCPU 的 VMCSInfo

```c
// VMCS size 不能超過 4KB (4096 bytes)
uint32_t const cbVmcs = RT_BF_GET(pVM->hm.s.vmx.Msrs.u64Basic, VMX_BF_BASIC_VMCS_SIZE);
if (cbVmcs <= X86_PAGE_4K_SIZE) { /* likely */ }
else
{ ...; return VERR_HM_UNSUPPORTED_CPU_FEATURE_COMBO; }

// VMX_PROC_CTLS2_VIRT_APIC_ACCESS: virtualize APIC accesses
bool const fVirtApicAccess   = RT_BOOL(pVM->hm.s.vmx.Msrs.ProcCtls2.n.allowed1 & VMX_PROC_CTLS2_VIRT_APIC_ACCESS);
// fUseVmcsShadowing: 是否使用 VMCS shadowing
bool const fUseVmcsShadowing = pVM->hm.s.vmx.fUseVmcsShadowing;
// 此變數會使用到 fUseVmcsShadowing & fVirtApicAccess，作為分配 page 時的參考
VMXPAGEALLOCINFO aAllocInfo[] =
{ ... /* APIC-access page, VMREAD bitmap, VMWRITE bitmap */ };

// 根據 aAllocInfo[] 所記錄的分配資訊來配置 VMX pages
int rc = hmR0VmxPagesAllocZ(&pVM->hm.s.vmx.hMemObj, &aAllocInfo[0], RT_ELEMENTS(aAllocInfo));

// 對每個 VCPU 都分配 VT-X 結構 (per-VCPU)
for (VMCPUID idCpu = 0; idCpu < pVM->cCpus && RT_SUCCESS(rc); idCpu++)
{
    // 取得 VCPU
    PVMCPUCC pVCpu = VMCC_GET_CPU(pVM, idCpu);
    // 為 VCPU 內的 VMCSInfo 初始化
    rc = hmR0VmxAllocVmcsInfo(pVCpu, &pVCpu->hm.s.vmx.VmcsInfo, false /* fIsNstGstVmcs */);
}
return VINF_SUCCESS;
```

- `VMXPAGEALLOCINFO` - VMX page allocation information
- `hmR0VmxPagesAllocZ()` - 根據傳入的 allocate info 來分配 VMX page，function 中的 **Z** 代表配置完的 pages 內容都會是 0 (Zero)

---

`hmR0VmxPagesAllocZ()` - Allocates pages specified as specified by an array of VMX page allocation info objects

---

`hmR0VmxAllocVmcsInfo()` - Allocates the VT-x structures for a VMCS info. object

---

`VMXR0TermVM()` - Does per-VM VT-x termination

```c
...
hmR0VmxStructsFree(pVM); // 釋放整個 VT-X 結構
return VINF_SUCCESS;
```

---

`hmR0VmxStructsFree()` - Free all VT-x structures for the VM，釋放在 `hmR0VmxStructsAlloc()` 中分配的記憶體

```c
// 釋放先前用 hmR0VmxPagesAllocZ() 所分配的記憶體
hmR0VmxPagesFree(pVM->hm.s.vmx.hMemObj);
for (VMCPUID idCpu = 0; idCpu < pVM->cCpus; idCpu++)
{
    PVMCPUCC pVCpu = VMCC_GET_CPU(pVM, idCpu);
    // 釋放掉每個 VCPU 內的 VMCSInfo
    hmR0VmxVmcsInfoFree(&pVCpu->hm.s.vmx.VmcsInfo);
}
```

---

`VMXR0RunGuestCode()` - Runs the guest using hardware-assisted VMX

```c
PCPUMCTX pCtx = &pVCpu->cpum.GstCtx;
VBOXSTRICTRC rcStrict;

uint32_t     cLoops = 0;
... // 省略了 nested 的部分
if (... /* 確定沒有任何 debug 的操作 */)
    rcStrict = hmR0VmxRunGuestCodeNormal(pVCpu, &cLoops); // 直接用 VT-X 執行 guest code
else
    rcStrict = hmR0VmxRunGuestCodeDebug(pVCpu, &cLoops); // debug (single steps guest code)
```

- GstCtx - guest context，type 為 `PCPUMCTX` (pointer of CPU context)，而此欄位 guest context 會直接被 execution engine 使用
- 在 `hmR0VmxRunGuestCodeNormal()` 中已經會處理 VMExit，不過有些狀況沒辦法做 handle，會回傳給 `rcSrtrict` 並在後續處理

```c
int const rcLoop = VBOXSTRICTRC_VAL(rcStrict);
switch (rcLoop)
{
    // interpreter 不能 handle 此對應到的 insn
    case VERR_EM_INTERPRETER:   rcStrict = VINF_EM_RAW_EMULATE_INSTR;   break;
    // VM 已經被 reset，回到 startup 執行
    case VINF_EM_RESET:         rcStrict = VINF_EM_TRIPLE_FAULT;        break;
}

int rc2 = hmR0VmxExitToRing3(pVCpu, rcStrict); // 回到 ring-3 前需要做一些準備
return rcStrict;
```

---

`hmR0VmxRunGuestCodeNormal()` - Runs the guest code using hardware-assisted VMX the normal way，透過 VMX 執行 guest code

```c
uint32_t const cMaxResumeLoops = pVCpu->CTX_SUFF(pVM)->hm.s.cMaxResumeLoops;

VMXTRANSIENT VmxTransient;
RT_ZERO(VmxTransient); // 清零

// 在取得當前 active 的 VMCSInfo 後，會比對是否為參數傳入的 VMCSInfo，確定目前正在執行
VmxTransient.pVmcsInfo = hmGetVmxActiveVmcsInfo(pVCpu);
Assert(VmxTransient.pVmcsInfo == &pVCpu->hm.s.vmx.VmcsInfo);

VBOXSTRICTRC rcStrict = VERR_INTERNAL_ERROR_5; // return value
for (;;)
{
	... // 一些 assertion
    // 做 run code 的前處理
    rcStrict = hmR0VmxPreRunGuest(pVCpu, &VmxTransient, false /* fStepping */);

    /* 至此 interrupt 已經被 disable */
    
    hmR0VmxPreRunGuestCommitted(pVCpu, &VmxTransient); // 最後的準備
    int rcRun = hmR0VmxRunGuest(pVCpu, &VmxTransient); // 實際執行
    hmR0VmxPostRunGuest(pVCpu, &VmxTransient, rcRun);
    
    /* 至此 interrupt 已經被 enable */

    if (RT_SUCCESS(rcRun))
    { /* very likely */ }
    else
    { ... /* 一些 error 的處理 */ }
    ...
}
```

- `VMXTRANSIENT` - VMX per-VCPU transient state，紀錄關於 VCPU 的一些暫時狀態
- 有 **STAM** prefix 與 **PROF** suffix 的 function 應該是作為測量效能用的，可以省略

```c
for (;;)
{
    ...
    VBOXVMM_R0_HMVMX_VMEXIT_NOCTX(pVCpu, &pVCpu->cpum.GstCtx, VmxTransient.uExitReason);
    
    // 執行對應 ExitReason 的 exit handler
    rcStrict = g_apfnVMExitHandlers[VmxTransient.uExitReason](pVCpu, &VmxTransient);
    
    if (++(*pcLoops) <= cMaxResumeLoops) // 有一定的執行次數
        continue;
    rcStrict = VINF_EM_RAW_INTERRUPT;
    break;
    ...
}
```

- `g_apfnVMExitHandlers[]` - 為一個 function table，根據 guest OS 執行 VMExit 回到 host OS 的原因 (`ExitReason`) 來執行對應的 handler (VMX_EXIT dispatch table)
- `VINF_EM_RAW_INTERRUPT` - interrupt needed to be handled by the host OS，也就會跳出 guest OS
- `cMaxResumeLoops` 預設為 1024，避免 guest os 佔滿 CPU 的使用時間

---

`hmR0VmxPreRunGuest()` - Does the preparations before executing guest code in VT-x

```c
// 檢查是否有需要回 ring-3 做 "force flag actions" (?
VBOXSTRICTRC rcStrict = hmR0VmxCheckForceFlags(pVCpu, pVmxTransient, fStepping);
/*
    * Virtualize memory-mapped accesses to the physical APIC (may take locks).
    */
PVMCC pVM = pVCpu->CTX_SUFF(pVM);
if (!pVCpu->hm.s.vmx.u64GstMsrApicBase /* APIC 還沒有 mapping */
    && ... /* 是否開啟 APIC */)
{
    // 建立 mapping for the APIC-access page 來虛擬化 APIC 的存取
    // 更新 'u64GstMsrApicBase' member
    int rc = hmR0VmxMapHCApicAccessPage(pVCpu);
}

/**************** 以下三個部分沒有很理解 ****************/
if (TRPMHasTrap(pVCpu)) // 檢查是否有 active trap
    hmR0VmxTrpmTrapToPendingEvent(pVCpu); // 有的話就轉成 pending HM event 送給 VM
// 檢查是否有 pending 當中的 event，如果有的話就更新 VMCS 內的一些相關資料
uint32_t fIntrState;
rcStrict = hmR0VmxEvaluatePendingEvent(pVCpu, pVmxTransient, &fIntrState);
// 將 event 轉為對應的 interrupt 送給 guest OS
rcStrict = hmR0VmxInjectPendingEvent(pVCpu, pVmxTransient, fIntrState, fStepping);
```

- `hmR0VmxMapHCApicAccessPage()` - Map the APIC-access page for virtualizing APIC accesses
- TRPM - Trap Manager
- `hmR0VmxTrpmTrapToPendingEvent()` --> `HMTrpmEventTypeToVmxEventType()` - Converts a TRPM event type into an appropriate VMX event type，這邊可以理解成如果 host 有 trap 要送往 VM，則在這個 function 中會轉成 VMX event 的形式傳給 VM

```c
// 檢查是否要求強制更新 cr3 的內容
if (VMCPU_FF_IS_SET(pVCpu, VMCPU_FF_HM_UPDATE_CR3))
    int rc2 = PGMUpdateCR3(pVCpu, CPUMGetGuestCR3(pVCpu));

// PAE: Physical Address Extension
// PDPE: page directory pointer entry
// 重新更新 PAE 的 PDPE
if (VMCPU_FF_IS_SET(pVCpu, VMCPU_FF_HM_UPDATE_PAE_PDPES))
    PGMGstUpdatePaePdpes(pVCpu, &pVCpu->hm.s.aPdpes[0]);

// disable r3 的呼叫 (host call)
VMMRZCallRing3Disable(pVCpu);

/* 至此不會在 longjmp 到 ring3 */

// 執行前輸出 guest 的 state bits 到 VMCS 的 guest-state area (GstCtx)
rcStrict = hmR0VmxExportGuestStateOptimal(pVCpu, pVmxTransient);

// disable interrupts
pVmxTransient->fEFlags = ASMIntDisableFlags();

if (   (   !VM_FF_IS_ANY_SET(pVM, VM_FF_EMT_RENDEZVOUS | VM_FF_TM_VIRTUAL_SYNC)
        && !VMCPU_FF_IS_ANY_SET(pVCpu, VMCPU_FF_HM_TO_R3_MASK))
    || (   fStepping /* Optimized for the non-stepping case, so a bit of unnecessary work when stepping. */
        && !VMCPU_FF_IS_ANY_SET(pVCpu, VMCPU_FF_HM_TO_R3_MASK & ~(VMCPU_FF_TIMER | VMCPU_FF_PDM_CRITSECT))) )
{
    if (!RTThreadPreemptIsPending(NIL_RTTHREAD))
    {
        // 所有 pending event 在 hmR0VmxInjectPendingEvent() 已經處理完畢
        pVCpu->hm.s.Event.fPending = false;
        return VINF_SUCCESS;
    }
    rcStrict = VINF_EM_RAW_INTERRUPT;
}
else
    rcStrict = VINF_EM_RAW_TO_R3; // Ring-3 operation pending

/* 至此，可能在後續處理還需要回 R3，所以需要恢復到先前的狀態 */
ASMSetFlags(pVmxTransient->fEFlags); // 恢復 RFlag
VMMRZCallRing3Enable(pVCpu); // re-enables host calls
```

- FF 指的是 force flags，不太確定實際定義，不過猜測是能強制做出 flag 指定的行為，如 `VMCPU_FF_HM_UPDATE_CR3`
- PAE - Physical Address Extension
- PDPE - page directory pointer entry
- `hmR0VmxExportGuestStateOptimal()` - 大部分 VMExit 的處理只需要更新 guest rip (`hmR0VmxExportGuestRip()`)，若有其他狀態更新就呼叫 `hmR0VmxExportGuestState()`
  - `hmR0VmxExportGuestState()` - Exports the guest state into the VMCS guest-state area (VCPU --> VMCS)

---

觀念釐清

- `pVCpu` 內有一個 member 為 `GstCtx`，直接對應到 VM 執行時的環境，在程式註解中被稱作 **guest context**
  - 而 VM 執行時存放 guest context 的環境在註解中被稱作 **VMCS guest-state area**
- host 中有些狀態也必須存放於 VMCS，註解中稱作 **host-state area in the VMCS**
- ExportGuestState 指的是 `GstCtx` ---> VMCS 的 guest context，所以 import 就是 guest context --> `GstCtx`



(From manual) The VMCS data are organized into six logical groups：

- Guest-state area - Processor state is saved into the guest-state area on **VM exits** and **loaded from there on VM entries**
- Host-state area - Processor state is **loaded from the host-state** area on VM exits
  - 從 VM exit 回來時會載入，藉此恢復 host 的執行狀態
- VM-execution control fields - These fields control processor behavior in VMX non-root operation. They determine in part the causes of VM exits
- VM-exit control fields - These fields control VM exits
- VM-entry control fields - These fields control VM entries
- VM-exit information fields - These fields receive information on VM exits and describe the cause and the nature of VM exits. On some processors, these fields are read-only.

---

`hmR0VmxPreRunGuestCommitted()` - Final preparations before executing guest code using hardware-assisted VMX

```c
// 更新 VCPU 的狀態
VMCPU_SET_STATE(pVCpu, VMCPUSTATE_STARTED_EXEC);

PVMCC         pVM          = pVCpu->CTX_SUFF(pVM);
PVMXVMCSINFO  pVmcsInfo    = pVmxTransient->pVmcsInfo;
PHMPHYSCPU    pHostCpu     = hmR0GetCurrentCpu();
RTCPUID const idCurrentCpu = pHostCpu->idCpu;

// 檢查 guest OS 是否啟用 FPU/XMM，並載入 guest 的 FPU state 到 CPU 內
if (!CPUMIsGuestFPUStateActive(pVCpu))
{
    if (CPUMR0LoadGuestFPU(pVM, pVCpu) == VINF_CPUM_HOST_CR0_MODIFIED)
        // 如果有更改到 cr0，則在 VCPU 中做紀錄
        pVCpu->hm.s.fCtxChanged |= HM_CHANGED_HOST_CONTEXT;
}

// 若 cr0 有被更動到，則 re-export host state
if (pVCpu->hm.s.fCtxChanged & HM_CHANGED_HOST_CONTEXT)
    hmR0VmxExportHostState(pVCpu);

// export host 與 guest 共享的狀態，如 FPU, debug, lazy MSRs 等
if (pVCpu->hm.s.fCtxChanged & HM_CHANGED_VMX_HOST_GUEST_SHARED_STATE)
    hmR0VmxExportSharedState(pVCpu, pVmxTransient);

// 保存 debug state
pVmxTransient->fWasGuestDebugStateActive = CPUMIsGuestDebugStateActive(pVCpu);
pVmxTransient->fWasHyperDebugStateActive = CPUMIsHyperDebugStateActive(pVCpu);

// 如果有使用 virtual-APIC，則 cache TPR-shadow
// TPR: Task Priority Register
if (pVmcsInfo->pbVirtApic)
    pVmxTransient->u8GuestTpr = pVmcsInfo->pbVirtApic[XAPIC_OFF_TPR];

// 更新存在於 VM-exit MSR-load area 的 MSR
if (!pVCpu->hm.s.vmx.fUpdatedHostAutoMsrs)
{
    if (pVmcsInfo->cExitMsrLoad > 0)
        hmR0VmxUpdateAutoLoadHostMsrs(pVCpu, pVmcsInfo);
    pVCpu->hm.s.vmx.fUpdatedHostAutoMsrs = true;
}

// 評估是否需要去模擬 RDTSC/P 的存取
if (!pVmxTransient->fUpdatedTscOffsettingAndPreemptTimer
  || idCurrentCpu != pVCpu->hm.s.idLastCpu)
{
    // 設置 TSC-offsetting 與更新 VMCS
    hmR0VmxUpdateTscOffsettingAndPreemptTimer(pVCpu, pVmxTransient);
    // 更新完畢
    pVmxTransient->fUpdatedTscOffsettingAndPreemptTimer = true;
}

```

- `CPUMR0LoadGuestFPU()` - Saves the host-FPU/XMM state (if necessary) and (always) loads the guest-FPU state into the CPU，視情況保存 host 本身的 FPU/XMM 的狀態，而一定會載入 guest-FPU 的狀態到 CPU 當中
- RDTSC - Read Time-Stamp Counter
- RDTSCP - Read Time-Stamp Counter and Processor ID
- TSC-offsetting - Timestamp-counter offsetting，讓 VMM 可以傳入一個 value (the TSC offset)，使 guest os 在存取時被加到 TSC，去模擬 TSC 的變化

```c
bool const fIsRdtscIntercepted = RT_BOOL(pVmcsInfo->u32ProcCtls & VMX_PROC_CTLS_RDTSC_EXIT);

ASMAtomicWriteBool(&pVCpu->hm.s.fCheckedTLBFlush, true); // 先標記 TLB 已經 flush
hmR0VmxFlushTaggedTlb(pHostCpu, pVCpu, pVmcsInfo); // 但此時才確實 flush

// 更新 (紀錄) 前一次相關資料對應到的 CPU
pVCpu->hm.s.vmx.LastError.idCurrentCpu = idCurrentCpu;
pVmcsInfo->idHostCpuState = idCurrentCpu;
pVmcsInfo->idHostCpuExec  = idCurrentCpu;

TMNotifyStartOfExecution(pVM, pVCpu); // resume TM (timer) 因為即將執行 guest

// 如果不需要 intercept RDTSCP，則載入 guest 的 TSC_AUX MSR
if (   (pVmcsInfo->u32ProcCtls2 & VMX_PROC_CTLS2_RDTSCP)
    && !fIsRdtscIntercepted)
{
    hmR0VmxImportGuestState(pVCpu, pVmcsInfo, CPUMCTX_EXTRN_TSC_AUX);

    // 因為呼叫該 function 時傳入 fUpdateHostMsr 為 true，因此就算執行過 hmR0VmxUpdateAutoLoadHostMsrs() 也沒關係
    int rc = hmR0VmxAddAutoLoadStoreMsr(pVCpu, pVmxTransient, MSR_K8_TSC_AUX, CPUMGetGuestTscAux(pVCpu), true, true);
    // 要求 TSC_AUX MSR 在執行完 VMExit 後從 auto-load/store MSR 被移出
    pVmxTransient->fRemoveTscAuxMsr = true;
}
```

- 整個 function 基本上都是載入 guest os context 到 host 中，並且視情況保存 host 原先的執行狀態

---

`hmR0VmxRunGuest()` - Wrapper for running the guest code in VT-x

```c
PCPUMCTX pCtx = &pVCpu->cpum.GstCtx;
// 標記 HM 為 guest-CPU registers 的持有者 (keeper)，在一些特定情況才會用到
pCtx->fExtrn |= HMVMX_CPUMCTX_EXTRN_ALL | CPUMCTX_EXTRN_KEEPER_HM;

PCVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;
// 從 VMCS 取得 launch state 並看是否已經 launch
bool const fResumeVM = RT_BOOL(pVmcsInfo->fVmcsState & VMX_V_VMCS_LAUNCH_STATE_LAUNCHED);
PVMCC pVM = pVCpu->CTX_SUFF(pVM);
int rc = pVmcsInfo->pfnStartVM(fResumeVM, pCtx, NULL /*pvUnused*/, pVM, pVCpu);
return rc;
```

- `hmR0VmxSetupVmcs()` 時會初始化 `pfnStartVM` 成 `VMXR0StartVM64()`

---

`hmR0VmxPostRunGuest()` - First C routine invoked after running guest code using hardware-assisted VMX

```c
uint64_t const uHostTsc = ASMReadTSC();

// 在 HMInvalidatePageOnAllVCpus() 用來判斷是否要做 TLB flushing
ASMAtomicWriteBool(&pVCpu->hm.s.fCheckedTLBFlush, false);
// cWorldSwitchExits: World switch exit counter，用來做 EMT poking (?
ASMAtomicIncU32(&pVCpu->hm.s.cWorldSwitchExits);
// Exits/longjmps 到 r3 前會需要儲存 guest state
pVCpu->hm.s.fCtxChanged            = 0;
// 需要會從 VMCS 讀 transient 的資料
pVmxTransient->fVmcsFieldsRead     = 0;
// 在 NMI or interrupt 發生 page fault 而 VXExit
pVmxTransient->fVectoringPF        = false;
// 在 exception or page fault 時發生 page fault 而 VXExit
pVmxTransient->fVectoringDoublePF  = false;

PVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;
if (!(pVmcsInfo->u32ProcCtls & VMX_PROC_CTLS_RDTSC_EXIT))
{
    uint64_t uGstTsc;
    // host tsc + vmcs 內保存的 offset 等於目前 guest 內的 tsc
    uGstTsc = uHostTsc + pVmcsInfo->u64TscOffset;
    // 用 guest TSC 更新 TM
    TMCpuTickSetLastSeen(pVCpu, uGstTsc);
}

// 通知 TM guest 已經停止
TMNotifyEndOfExecution(pVCpu->CTX_SUFF(pVM), pVCpu);
// 設置 STARTED，猜測代表機器已經啟動
VMCPU_SET_STATE(pVCpu, VMCPUSTATE_STARTED_HM);

// 一些 host state 會被 VMX 影響，因此需要 restore
pVCpu->hm.s.vmx.fRestoreHostFlags |= VMX_RESTORE_HOST_REQUIRED;
// 已經 launch，因此下次執行時用 VMRESUME 恢復執行狀態即可
pVmcsInfo->fVmcsState |= VMX_V_VMCS_LAUNCH_STATE_LAUNCHED;
// enable interrupt，舊的 fEFlags 的 IF 應該是 unset
ASMSetFlags(pVmxTransient->fEFlags);
```

```c
// 取得 VMExit 的 reason
uint32_t uExitReason;
int rc = VMXReadVmcs32(VMX_VMCS32_RO_EXIT_REASON, &uExitReason);
// 32-bit value 中還有紀錄其他相關資訊
pVmxTransient->uExitReason    = VMX_EXIT_REASON_BASIC(uExitReason);
pVmxTransient->fVMEntryFailed = VMX_EXIT_REASON_HAS_ENTRY_FAILED(uExitReason);

// 不需要 intercept RDTSCP 的話就會是 true
if (pVmxTransient->fRemoveTscAuxMsr)
{
    hmR0VmxRemoveAutoLoadStoreMsr(pVCpu, pVmxTransient, MSR_K8_TSC_AUX);
    pVmxTransient->fRemoveTscAuxMsr = false;
}

// 檢查 VMLAUNCH/VMRESUME 是否成功
if (RT_LIKELY(rcVMRun == VINF_SUCCESS))
{
    // 更新 VM-exit history array 
    EMHistoryAddExit(pVCpu, EMEXIT_MAKE_FT(EMEXIT_F_KIND_VMX, pVmxTransient->uExitReason & EMEXIT_F_TYPE_MASK), UINT64_MAX, uHostTsc);

    if (RT_LIKELY(!pVmxTransient->fVMEntryFailed))
    {
        VMMRZCallRing3Enable(pVCpu); // re-enables host calls

        // 在 re-entry 中 injecting event 會需要知道 guest-interruptibility，所以要在此 import
        uint64_t const fImportMask = CPUMCTX_EXTRN_HM_VMX_INT_STATE;
        // 保存 VMX 的 interruptibility 資訊到 guest state
        rc = hmR0VmxImportGuestState(pVCpu, pVmcsInfo, fImportMask);

        // 同步 VMCS 與 pVmxTransient 所紀錄的 TPR
        if (   !pVmxTransient->fIsNestedGuest
            && (pVmcsInfo->u32ProcCtls & VMX_PROC_CTLS_USE_TPR_SHADOW))
        {
            if (pVmxTransient->u8GuestTpr != pVmcsInfo->pbVirtApic[XAPIC_OFF_TPR])
            {
                rc = APICSetTpr(pVCpu, pVmcsInfo->pbVirtApic[XAPIC_OFF_TPR]);
                ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_GUEST_APIC_TPR);
            }
        }
        return;
    }
}
... // error handling
```

- `hmR0VmxImportGuestState` -  從 VMX 讀取對應的值到 type 為 `PCPUMCTX` 的變數 `GstCtx` 當中 (cpum 應該是指 CPU in memory)
  - `fExtrn` 紀錄著需要被 import 的 flag，macro 如 `CPUMCTX_EXTRN_RIP` 代表 flag

---

`VMXR0StartVM64()` - Prepares for and executes VMLAUNCH/VMRESUME

```asm
push    xBP
mov     xBP, xSP

pushf
cli ; disable interrupt

MYPUSHAD ; 保存所有 general purpose host registers

; 在 vmlaunch64_done 寫入 return address 為 .vmlaunch64_done
lea     r10, [.vmlaunch64_done wrt rip]
mov     rax, VMX_VMCS_HOST_RIP
vmwrite rax, r10

; input 相關的 register
; fResume already in rdi
; pCtx    already in rsi
mov     rbx, rdx        ; pvUnused

; 如果需要的話 (fLoadSaveGuestXcr0 == 1) 保存 host 的 XCR0，並使用 guest 的
mov     rax, r8                     ; pVCpu
test    byte [xAX + VMCPU.hm + HMCPU.fLoadSaveGuestXcr0], 1
jz      .xcr0_before_skip

xor     ecx, ecx
; xgetbv: Get Value of Extended Control Register
xgetbv ; 把 host 的存到 stack
push    xDX
push    xAX

; 載入 guest 的
mov     eax, [xSI + CPUMCTX.aXcr]
mov     edx, [xSI + CPUMCTX.aXcr + 4]
xor     ecx, ecx
xsetbv

push    0 ; 需要 restore XCR0
jmp     .xcr0_before_done

.xcr0_before_skip:
push    3fh ; 不需要 restore XCR0
.xcr0_before_done:

; Save segment registers
MYPUSHSEGS xAX, ax

; Save the pCtx pointer.
push    xSI

; Save host LDTR
xor     eax, eax
sldt    ax ; Store Local Descriptor Table Register
push    xAX

; Save host TR - task register
str     eax ; Store Task Register
push    xAX

; Save host GDTR - Global Descriptor Table Register
sub     xSP, xCB * 2
sgdt    [xSP]

; Save host IDTR - Interrupt Descriptor Table Register
sub     xSP, xCB * 2
sidt    [xSP]

; Load CR2 if necessary
; 因為 write cr2 是個 sync insn，所以 overhead 相較高 (expensive)
mov     rbx, qword [xSI + CPUMCTX.cr2]
mov     rdx, cr2
cmp     rbx, rdx
je      .skip_cr2_write
mov     cr2, rbx

.skip_cr2_write:
mov     eax, VMX_VMCS_HOST_RSP
vmwrite xAX, xSP

; Fight intel spectre
INDIRECT_BRANCH_PREDICTION_AND_L1_CACHE_BARRIER xSI, CPUMCTX_WSF_IBPB_ENTRY, CPUMCTX_WSF_L1D_ENTRY, CPUMCTX_WSF_MDS_ENTRY

; 載入 guest general purpose registers
mov     rax, qword [xSI + CPUMCTX.eax]
...
mov     rbp, qword [xSI + CPUMCTX.ebp]
mov     r8,  qword [xSI + CPUMCTX.r8]
...
mov     r15, qword [xSI + CPUMCTX.r15]

; Resume or start VM?
cmp     xDI, 0 ; fResume == 0

; Load guest rdi & rsi
mov     rdi, qword [xSI + CPUMCTX.edi]
mov     rsi, qword [xSI + CPUMCTX.esi]

je      .vmlaunch64_launch ; 第一次載入

vmresume ; resume VM
jc      near .vmxstart64_invalid_vmcs_ptr
jz      near .vmxstart64_start_failed
jmp     .vmlaunch64_done;      ; here if vmresume detected a failure

.vmlaunch64_launch:
vmlaunch ; launch VM
jc      near .vmxstart64_invalid_vmcs_ptr
jz      near .vmxstart64_start_failed
jmp     .vmlaunch64_done;      ; here if vmlaunch detected a failure

ALIGNCODE(16)
.vmlaunch64_done:
RESTORE_STATE_VM64
mov     eax, VINF_SUCCESS

.vmstart64_end:
popf
pop     xBP
ret
; 發生 error 要回傳對應的 error status
.vmxstart64_invalid_vmcs_ptr:
RESTORE_STATE_VM64
mov     eax, VERR_VMX_INVALID_VMCS_PTR_TO_START_VM
jmp     .vmstart64_end

.vmxstart64_start_failed:
RESTORE_STATE_VM64
mov     eax, VERR_VMX_UNABLE_TO_START_VM
jmp     .vmstart64_end
ENDPROC VMXR0StartVM64
```

- 似乎區分成 `ASM_CALL64_MSC` 以及 `ASM_CALL64_GCC`
- 前面有 `x` prefix 的似乎是 extended register



### 6

> 大多 function 與狀態的保存相關，除此之外還有 VMExit handler 的分析

---

`hmR0VmxImportGuestState()` - Worker for VMXR0ImportStateOnDemand

```c
int      rc   = VINF_SUCCESS;
PVMCC    pVM  = pVCpu->CTX_SUFF(pVM);
PCPUMCTX pCtx = &pVCpu->cpum.GstCtx;
uint32_t u32Val;

// disable interrupt，使得 fExtrn modification 可以為 atomic 不被打斷
RTCCUINTREG const fEFlags = ASMIntDisableFlags();

fWhat &= pCtx->fExtrn; // what to import ?

if (fWhat)
{
    do
    {
        // 省略如 if (fWhat & CPUMCTX_EXTRN_XXX) hmR0VmxImportGuestXXX(pVCpu) 的操作
        ...
    } while (0);
    pCtx->fExtrn &= ~fWhat; // unset 那些 import 完的暫存器/資料
    // 如果所有資料都被 import，則 unset HM 的 keeper bit
    if (!(pCtx->fExtrn & HMVMX_CPUMCTX_EXTRN_ALL))
        pCtx->fExtrn &= ~CPUMCTX_EXTRN_KEEPER_HM;
}

ASMSetFlags(fEFlags); // 重新 enable interrupt

// maybe 執行到此的 scenario 參考下方補充 [1]
if (VMMRZCallRing3IsEnabled(pVCpu))
{
    if (VMCPU_FF_IS_SET(pVCpu, VMCPU_FF_HM_UPDATE_CR3)) // force update cr3
        PGMUpdateCR3(pVCpu, CPUMGetGuestCR3(pVCpu));

    if (VMCPU_FF_IS_SET(pVCpu, VMCPU_FF_HM_UPDATE_PAE_PDPES)) // force update pdpe
        PGMGstUpdatePaePdpes(pVCpu, &pVCpu->hm.s.aPdpes[0]);
}
```

- 從 VMCS import 到 guest-CPU context
- **[1]** - VM-exit -> `VMMRZCallRing3Enable()` -> do stuff that causes a longjmp -> `VMXR0CallRing3Callback()` -> `VMMRZCallRing3Disable()` -> `hmR0VmxImportGuestState()` -> Sets **VMCPU_FF_HM_UPDATE_CR3** pending -> return from the longjmp -> continue with VM-exit handling -> `hmR0VmxImportGuestState()`

---

`hmR0VmxExportGuestState()` - Exports the guest state into the VMCS guest-state area

```c
// 檢查是否在 real mode
PVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;
if (pVCpu->CTX_SUFF(pVM)->hm.s.vmx.fUnrestrictedGuest
    || !CPUMIsGuestInRealModeEx(&pVCpu->cpum.GstCtx))
    pVmcsInfo->RealMode.fRealOnV86Active = false;
else
    pVmcsInfo->RealMode.fRealOnV86Active = true;

// 下方 export 的順序有 dependency
int rc = hmR0VmxExportGuestEntryExitCtls(pVCpu, pVmxTransient);
rc = hmR0VmxExportGuestCR0(pVCpu, pVmxTransient);
VBOXSTRICTRC rcStrict = hmR0VmxExportGuestCR3AndCR4(pVCpu, pVmxTransient);
rc = hmR0VmxExportGuestSegRegsXdtr(pVCpu, pVmxTransient);
rc = hmR0VmxExportGuestMsrs(pVCpu, pVmxTransient);
hmR0VmxExportGuestApicTpr(pVCpu, pVmxTransient);
hmR0VmxExportGuestXcptIntercepts(pVCpu, pVmxTransient);
hmR0VmxExportGuestRip(pVCpu);
hmR0VmxExportGuestRsp(pVCpu);
hmR0VmxExportGuestRflags(pVCpu, pVmxTransient);
rc = hmR0VmxExportGuestHwvirtState(pVCpu, pVmxTransient);

// 清除 "沒用 / 保留 / 無條件 export" 的 bits
ASMAtomicUoAndU64(&pVCpu->hm.s.fCtxChanged, ~((HM_CHANGED_GUEST_GPRS_MASK & ~HM_CHANGED_GUEST_RSP) | ... | HM_CHANGED_GUEST_OTHER_MSRS | (HM_CHANGED_KEEPER_STATE_MASK & ~HM_CHANGED_VMX_MASK)));

return rc;
```

---

`hmR0VmxExportHostState()` - Exports the host state into the VMCS host-state area

```c
int rc = VINF_SUCCESS;
if (pVCpu->hm.s.fCtxChanged & HM_CHANGED_HOST_CONTEXT)
{
    hmR0VmxExportHostControlRegs(); // 保存 host 的 control register
    rc = hmR0VmxExportHostSegmentRegs(pVCpu); // 保存 host 的 segr
    hmR0VmxExportHostMsrs(pVCpu); // 保存 host 的 msr
    // 已經保存完畢，unset changed bit
    pVCpu->hm.s.fCtxChanged &= ~HM_CHANGED_HOST_CONTEXT;
}
return rc;
```

- 沒有 `hmR0VmxImportHostState()` 也不需要

---

下面介紹在設置 VMCS 時初始化的 VMExit handler，大概可以劃分成以下流程：

1. 當 CPU 執行到 VMExit 時，會將執行訊息保存在 VMCS 當中，之後再透過 `vmread` 讀 VMCS 並寫到 CPUMCTX 當中來儲存 guest OS 的狀態 (VMCS --> CPUMCTX)，同時取得 VMExit 的參數。其中 VMExit 回來的執行訊息可以分成以下 (參考 intel 手冊)：
   - Basisc info： Exit reason / Exit qualification / Guest IP
   - Event-specific info： interruption information / error code。當因為 exceptions / external interrupts / NMI 時發生所造成的 interrupt，就會紀錄相關資訊在此欄位
   - Additional information： IDT-vectoring info /  error code，在處理 event 的過程中 trigger VMExit
   - 執行特定 insn： VMExit instruction length / info，SMI (System Management Interrupt) 會額外有一些 IO 相關的資訊 (I/O RCX, I/O RSI, I/O RDI, I/O RIP)
   - VM-instruction error： 不會提供 VMExit 相關的資訊，而是提供發生 non-faulting execution 時的一些執行狀態
2. 執行對應的 VMExit handler
3. 第二步成功的話會調整 register 並繼續執行 guest OS；若失敗則有些需要 inject exception 到 guest 當中，甚至要退出 VMX 回 R3 處理



`hmR0VmxSetupVmcsPinCtls()` - Sets up pin-based VM-execution controls in the VMCS，跟 INTR / NMI 產生的 VMExit 較為相關 (async interrupt)

```c
PVMCC pVM = pVCpu->CTX_SUFF(pVM);
// 在這邊的 set bit 必須一直要被 set
uint32_t       fVal = pVM->hm.s.vmx.Msrs.PinCtls.n.allowed0;
// 在這邊的 cleared bit 必須一直要被 cleared
uint32_t const fZap = pVM->hm.s.vmx.Msrs.PinCtls.n.allowed1;

// External interrupts 以及 Non-maskable interrupts
fVal |= VMX_PIN_CTLS_EXT_INT_EXIT | VMX_PIN_CTLS_NMI_EXIT;

// 如果開啟 virtual NMI，則使用 virt-NMIs 以及 virtual-NMI blocking features
if (pVM->hm.s.vmx.Msrs.PinCtls.n.allowed1 & VMX_PIN_CTLS_VIRT_NMI)
    fVal |= VMX_PIN_CTLS_VIRT_NMI;

// 啟用 VMX-preemption timer
if (pVM->hm.s.vmx.fUsePreemptTimer)
    fVal |= VMX_PIN_CTLS_PREEMPT_TIMER;

if ((fVal & fZap) != fVal) { ... /* error handling */ }

/* Commit it to the VMCS and update our cache. */
// commit 到 VMCS 當中，並且 update memory 當中的 VMCS
int rc = VMXWriteVmcs32(VMX_VMCS32_CTRL_PIN_EXEC, fVal);
pVmcsInfo->u32PinCtls = fVal;

return VINF_SUCCESS;
```

- VMCS cache 應該是指存在於 memory 內的 `VMCSInfo` 結構

---

`hmR0VmxSetupVmcsProcCtls()` - Sets up processor-based VM-execution controls in the VMCS，例如執行到 instruction 時所觸發的 VMExit (sync interrupt)，不過還有另外分出 `hmR0VmxSetupVmcsProcCtls2()`

```c
PVMCC pVM = pVCpu->CTX_SUFF(pVM);
uint32_t       fVal = pVM->hm.s.vmx.Msrs.ProcCtls.n.allowed0;
uint32_t const fZap = pVM->hm.s.vmx.Msrs.ProcCtls.n.allowed1;

fVal |= VMX_PROC_CTLS_HLT_EXIT /* HLT */ | VMX_PROC_CTLS_USE_TSC_OFFSETTING /* 使用 TSC-offsetting */ | VMX_PROC_CTLS_MOV_DR_EXIT /* MOV DRx */ | VMX_PROC_CTLS_UNCOND_IO_EXIT /* IO insn */ | VMX_PROC_CTLS_RDPMC_EXIT /* RDPMC */ | VMX_PROC_CTLS_MONITOR_EXIT /* MONITOR */ | VMX_PROC_CTLS_MWAIT_EXIT; /* MWAIT */

// VMX_PROC_CTLS_MOV_DR_EXIT 需要被 toggle，不能 always set / cleared
if (   !(pVM->hm.s.vmx.Msrs.ProcCtls.n.allowed1 & VMX_PROC_CTLS_MOV_DR_EXIT)
    ||  (pVM->hm.s.vmx.Msrs.ProcCtls.n.allowed0 & VMX_PROC_CTLS_MOV_DR_EXIT))
{ ... /* error handling */ }

// mov cr3 / INVLPG (包含 INVPCID) 都會 trigger VMExit
fVal |= VMX_PROC_CTLS_INVLPG_EXIT | VMX_PROC_CTLS_CR3_LOAD_EXIT |  VMX_PROC_CTLS_CR3_STORE_EXIT;

// 如果 CPU support TPR shadowing 的話就用
if (PDMHasApic(pVM)
    && (pVM->hm.s.vmx.Msrs.ProcCtls.n.allowed1 & VMX_PROC_CTLS_USE_TPR_SHADOW))
{
    // CR8 reads from the Virtual-APIC page
    fVal |= VMX_PROC_CTLS_USE_TPR_SHADOW;
    // CR8 writes cause a VM-exit based on TPR threshold
    Assert(!(fVal & VMX_PROC_CTLS_CR8_STORE_EXIT));
    Assert(!(fVal & VMX_PROC_CTLS_CR8_LOAD_EXIT));
    // TPR shadowing 的使用需要初始化 Virt APIC
    hmR0VmxSetupVmcsVirtApicAddr(pVmcsInfo);
}
else
{
    // 有些 32-bit CPU 不支援 cr8 的存取，所以在 64-bit CPU 才去對 cr8 read/write 做處理
    if (pVM->hm.s.fAllow64BitGuests)
        fVal |= VMX_PROC_CTLS_CR8_STORE_EXIT | VMX_PROC_CTLS_CR8_LOAD_EXIT;
}
```

- INVLPG - Invalidate TLB Entries
- TPR shadow - 開啟後可以存取 CR8 會以 memory-mapped 的方式取得 APIC 的 TPR，如果沒開啟就只能用 MSR-based interfaces 存取 (?)

```c
// 如果 CPU 有用 MSR-bitmap 則 setup it
if (pVM->hm.s.vmx.Msrs.ProcCtls.n.allowed1 & VMX_PROC_CTLS_USE_MSR_BITMAPS)
{
    fVal |= VMX_PROC_CTLS_USE_MSR_BITMAPS;
    hmR0VmxSetupVmcsMsrBitmapAddr(pVmcsInfo);
}

// 如果 CPU 支援則 set secondary ProcCtls bit
if (pVM->hm.s.vmx.Msrs.ProcCtls.n.allowed1 & VMX_PROC_CTLS_USE_SECONDARY_CTLS)
    fVal |= VMX_PROC_CTLS_USE_SECONDARY_CTLS;

// commit 到 VMCS 並更新 cache
int rc = VMXWriteVmcs32(VMX_VMCS32_CTRL_PROC_EXEC, fVal);
pVmcsInfo->u32ProcCtls = fVal;

/* Set up MSR permissions that don't change through the lifetime of the VM. */
if (pVmcsInfo->u32ProcCtls & VMX_PROC_CTLS_USE_MSR_BITMAPS)
    hmR0VmxSetupVmcsMsrPermissions(pVCpu, pVmcsInfo);

// 如果 CPU 支援則設置 secondary ProcCtls 結構
if (pVmcsInfo->u32ProcCtls & VMX_PROC_CTLS_USE_SECONDARY_CTLS)
    return hmR0VmxSetupVmcsProcCtls2(pVCpu, pVmcsInfo);

// old cpu 不支援 secondary ProcCtls
return VINF_SUCCESS;
```

---

`hmR0VmxSetupVmcsProcCtls2()` - Sets up secondary processor-based VM-execution controls in the VMCS

```c
PVMCC pVM = pVCpu->CTX_SUFF(pVM);
uint32_t       fVal = pVM->hm.s.vmx.Msrs.ProcCtls2.n.allowed0;
uint32_t const fZap = pVM->hm.s.vmx.Msrs.ProcCtls2.n.allowed1;

// WBINVD causes a VM-exit
if (pVM->hm.s.vmx.Msrs.ProcCtls2.n.allowed1 & VMX_PROC_CTLS2_WBINVD_EXIT)
    fVal |= VMX_PROC_CTLS2_WBINVD_EXIT;

// 如果支援 INVPCID 就加到 VMExit handling 內，不支援的話執行就會處發 #UD
if (   pVM->cpum.ro.GuestFeatures.fInvpcid
    && (pVM->hm.s.vmx.Msrs.ProcCtls2.n.allowed1 & VMX_PROC_CTLS2_INVPCID))
    fVal |= VMX_PROC_CTLS2_INVPCID;

// Enable VPID
if (pVM->hm.s.vmx.fVpid)
    fVal |= VMX_PROC_CTLS2_VPID;

// Enable unrestricted guest execution
if (pVM->hm.s.vmx.fUnrestrictedGuest)
    fVal |= VMX_PROC_CTLS2_UNRESTRICTED_GUEST;

// 支援 Virtualize-APIC page 的存取，先前已經執行 hmR0VmxSetupVmcsVirtApicAddr() 來初始化 virt apic address
if (pVM->hm.s.vmx.Msrs.ProcCtls2.n.allowed1 & VMX_PROC_CTLS2_VIRT_APIC_ACCESS)
{
    fVal |= VMX_PROC_CTLS2_VIRT_APIC_ACCESS;
    hmR0VmxSetupVmcsApicAccessAddr(pVCpu);
}

// 如果支援 RDTSCP 就加到 VMExit handling 內，不支援的話執行就會處發 #UD
if (   pVM->cpum.ro.GuestFeatures.fRdTscP
    && (pVM->hm.s.vmx.Msrs.ProcCtls2.n.allowed1 & VMX_PROC_CTLS2_RDTSCP))
    fVal |= VMX_PROC_CTLS2_RDTSCP;

// 此時若 CPU 支援 ple (pause loop exiting)，會在發現 spinning 時做處理
if (   (pVM->hm.s.vmx.Msrs.ProcCtls2.n.allowed1 & VMX_PROC_CTLS2_PAUSE_LOOP_EXIT)
    && pVM->hm.s.vmx.cPleGapTicks
    && pVM->hm.s.vmx.cPleWindowTicks)
{
    fVal |= VMX_PROC_CTLS2_PAUSE_LOOP_EXIT;

    int rc = VMXWriteVmcs32(VMX_VMCS32_CTRL_PLE_GAP, pVM->hm.s.vmx.cPleGapTicks);
    rc = VMXWriteVmcs32(VMX_VMCS32_CTRL_PLE_WINDOW, pVM->hm.s.vmx.cPleWindowTicks);
}

// commit to VMCS and update cache
int rc = VMXWriteVmcs32(VMX_VMCS32_CTRL_PROC_EXEC2, fVal);
pVmcsInfo->u32ProcCtls2 = fVal;

return VINF_SUCCESS;
```

- INVPCID - Invalidate Process-Context Identifier
- ple - VCPU1 嘗試執行 `pause` insn 來等 VCPU2 的 lock，而 VCPU2 卻在處理其他的行為，此時持續執行 `pause` 則會造成 CPU 浪費，因此 CPU 有一個功能可以偵測白白 pause-loop 的情況，並做出對應的處理，而在此會觸發 VMExit 讓 host 可以 handle
- `fUnrestrictedGuest` 讓 guest 可以運行在沒有 paging 的 protection mode / real mode

---

`hmR0VmxSetupVmcsMiscCtls()` - Sets up misc control fields in the VMCS

```c
int rc = VMXWriteVmcs64(VMX_VMCS64_GUEST_VMCS_LINK_PTR_FULL, NIL_RTHCPHYS);
// 設置 GuestMsrLoad/GuestMsrStore/HostMsrLoad 對應的 address
// 其中 VMEntry 時會使用 GuestMsrLoad，VMExit 時會用 GuestMsrStore/HostMsrLoad
rc = hmR0VmxSetupVmcsAutoLoadStoreMsrAddrs(pVmcsInfo);

// 取出當前 VCPU 所紀錄的 cr0 mask 與 cr4 mask
uint64_t const u64Cr0Mask = hmR0VmxGetFixedCr0Mask(pVCpu);
uint64_t const u64Cr4Mask = hmR0VmxGetFixedCr4Mask(pVCpu);

// 更新到 VMCS
rc = VMXWriteVmcsNw(VMX_VMCS_CTRL_CR0_MASK, u64Cr0Mask);
rc = VMXWriteVmcsNw(VMX_VMCS_CTRL_CR4_MASK, u64Cr4Mask);

// 更新到 cache
pVmcsInfo->u64Cr0Mask = u64Cr0Mask;
pVmcsInfo->u64Cr4Mask = u64Cr4Mask;

// 若 CPU 支援 Last Branch Record (LBR) 就開啟
// 常在 Debug 時會用到，不過也不限於 debug
if (pVCpu->CTX_SUFF(pVM)->hm.s.vmx.fLbr)
    rc = VMXWriteVmcsNw(VMX_VMCS64_GUEST_DEBUGCTL_FULL, MSR_IA32_DEBUGCTL_LBR);
return VINF_SUCCESS;
```

- `hmR0VmxSetupVmcsAutoLoadStoreMsrAddrs()` - Sets up the VM-entry MSR load, VM-exit MSR-store and VM-exit MSR-load addresses in the VMCS

---

`hmR0VmxSetupVmcsXcptBitmap()` - Sets up the initial exception bitmap in the VMCS based on static conditions，當部分 exception 發生時會被 intercept，也就是透過 VMExit 給 host 處理

```c
// 一些 exception 一定會被 intercept
// #AC - Alignment Check，會有 side channel 以至於 leak host config
// #DB - Debug，recursive #DB 可能會造成 CPU hang 住
// #PF - Page Fault，需要跟 shadow page table 做同步
uint32_t const uXcptBitmap = RT_BIT(X86_XCPT_AC)
                            | RT_BIT(X86_XCPT_DB)
                            | RT_BIT(X86_XCPT_PF);

// commit to VMCS and update cache
int rc = VMXWriteVmcs32(VMX_VMCS32_CTRL_EXCEPTION_BITMAP, uXcptBitmap);
pVmcsInfo->u32XcptBitmap = uXcptBitmap;
```

- DR - Debug Register

---

`g_apfnVMExitHandlers[]` 為 VMExit handler table：

```c
/*  0  VMX_EXIT_XCPT_OR_NMI             */  hmR0VmxExitXcptOrNmi,
/*  1  VMX_EXIT_EXT_INT                 */  hmR0VmxExitExtInt,
/*  2  VMX_EXIT_TRIPLE_FAULT            */  hmR0VmxExitTripleFault,
/*  3  VMX_EXIT_INIT_SIGNAL             */  hmR0VmxExitErrUnexpected,
/*  4  VMX_EXIT_SIPI                    */  hmR0VmxExitErrUnexpected,
/*  5  VMX_EXIT_IO_SMI                  */  hmR0VmxExitErrUnexpected,
/*  6  VMX_EXIT_SMI                     */  hmR0VmxExitErrUnexpected,
/*  7  VMX_EXIT_INT_WINDOW              */  hmR0VmxExitIntWindow,
/*  8  VMX_EXIT_NMI_WINDOW              */  hmR0VmxExitNmiWindow,
/*  9  VMX_EXIT_TASK_SWITCH             */  hmR0VmxExitTaskSwitch,
/* 10  VMX_EXIT_CPUID                   */  hmR0VmxExitCpuid,
/* 11  VMX_EXIT_GETSEC                  */  hmR0VmxExitGetsec,
/* 12  VMX_EXIT_HLT                     */  hmR0VmxExitHlt,
/* 13  VMX_EXIT_INVD                    */  hmR0VmxExitInvd,
/* 14  VMX_EXIT_INVLPG                  */  hmR0VmxExitInvlpg,
/* 15  VMX_EXIT_RDPMC                   */  hmR0VmxExitRdpmc,
/* 16  VMX_EXIT_RDTSC                   */  hmR0VmxExitRdtsc,
/* 17  VMX_EXIT_RSM                     */  hmR0VmxExitErrUnexpected,
/* 18  VMX_EXIT_VMCALL                  */  hmR0VmxExitVmcall,
/* 19  VMX_EXIT_VMCLEAR                 */  hmR0VmxExitSetPendingXcptUD,
/* 20  VMX_EXIT_VMLAUNCH                */  hmR0VmxExitSetPendingXcptUD,
/* 21  VMX_EXIT_VMPTRLD                 */  hmR0VmxExitSetPendingXcptUD,
/* 22  VMX_EXIT_VMPTRST                 */  hmR0VmxExitSetPendingXcptUD,
/* 23  VMX_EXIT_VMREAD                  */  hmR0VmxExitSetPendingXcptUD,
/* 24  VMX_EXIT_VMRESUME                */  hmR0VmxExitSetPendingXcptUD,
/* 25  VMX_EXIT_VMWRITE                 */  hmR0VmxExitSetPendingXcptUD,
/* 26  VMX_EXIT_VMXOFF                  */  hmR0VmxExitSetPendingXcptUD,
/* 27  VMX_EXIT_VMXON                   */  hmR0VmxExitSetPendingXcptUD,
/* 28  VMX_EXIT_MOV_CRX                 */  hmR0VmxExitMovCRx,
/* 29  VMX_EXIT_MOV_DRX                 */  hmR0VmxExitMovDRx,
/* 30  VMX_EXIT_IO_INSTR                */  hmR0VmxExitIoInstr,
/* 31  VMX_EXIT_RDMSR                   */  hmR0VmxExitRdmsr,
/* 32  VMX_EXIT_WRMSR                   */  hmR0VmxExitWrmsr,
/* 33  VMX_EXIT_ERR_INVALID_GUEST_STATE */  hmR0VmxExitErrInvalidGuestState,
/* 34  VMX_EXIT_ERR_MSR_LOAD            */  hmR0VmxExitErrUnexpected,
/* 35  UNDEFINED                        */  hmR0VmxExitErrUnexpected,
/* 36  VMX_EXIT_MWAIT                   */  hmR0VmxExitMwait,
/* 37  VMX_EXIT_MTF                     */  hmR0VmxExitMtf,
/* 38  UNDEFINED                        */  hmR0VmxExitErrUnexpected,
/* 39  VMX_EXIT_MONITOR                 */  hmR0VmxExitMonitor,
/* 40  VMX_EXIT_PAUSE                   */  hmR0VmxExitPause,
/* 41  VMX_EXIT_ERR_MACHINE_CHECK       */  hmR0VmxExitErrUnexpected,
/* 42  UNDEFINED                        */  hmR0VmxExitErrUnexpected,
/* 43  VMX_EXIT_TPR_BELOW_THRESHOLD     */  hmR0VmxExitTprBelowThreshold,
/* 44  VMX_EXIT_APIC_ACCESS             */  hmR0VmxExitApicAccess,
/* 45  VMX_EXIT_VIRTUALIZED_EOI         */  hmR0VmxExitErrUnexpected,
/* 46  VMX_EXIT_GDTR_IDTR_ACCESS        */  hmR0VmxExitErrUnexpected,
/* 47  VMX_EXIT_LDTR_TR_ACCESS          */  hmR0VmxExitErrUnexpected,
/* 48  VMX_EXIT_EPT_VIOLATION           */  hmR0VmxExitEptViolation,
/* 49  VMX_EXIT_EPT_MISCONFIG           */  hmR0VmxExitEptMisconfig,
/* 50  VMX_EXIT_INVEPT                  */  hmR0VmxExitSetPendingXcptUD,
/* 51  VMX_EXIT_RDTSCP                  */  hmR0VmxExitRdtscp,
/* 52  VMX_EXIT_PREEMPT_TIMER           */  hmR0VmxExitPreemptTimer,
/* 53  VMX_EXIT_INVVPID                 */  hmR0VmxExitSetPendingXcptUD,
/* 54  VMX_EXIT_WBINVD                  */  hmR0VmxExitWbinvd,
/* 55  VMX_EXIT_XSETBV                  */  hmR0VmxExitXsetbv,
/* 56  VMX_EXIT_APIC_WRITE              */  hmR0VmxExitErrUnexpected,
/* 57  VMX_EXIT_RDRAND                  */  hmR0VmxExitErrUnexpected,
/* 58  VMX_EXIT_INVPCID                 */  hmR0VmxExitInvpcid,
/* 59  VMX_EXIT_VMFUNC                  */  hmR0VmxExitErrUnexpected,
/* 60  VMX_EXIT_ENCLS                   */  hmR0VmxExitErrUnexpected,
/* 61  VMX_EXIT_RDSEED                  */  hmR0VmxExitErrUnexpected,
/* 62  VMX_EXIT_PML_FULL                */  hmR0VmxExitErrUnexpected,
/* 63  VMX_EXIT_XSAVES                  */  hmR0VmxExitErrUnexpected,
/* 64  VMX_EXIT_XRSTORS                 */  hmR0VmxExitErrUnexpected,
/* 65  UNDEFINED                        */  hmR0VmxExitErrUnexpected,
/* 66  VMX_EXIT_SPP_EVENT               */  hmR0VmxExitErrUnexpected,
/* 67  VMX_EXIT_UMWAIT                  */  hmR0VmxExitErrUnexpected,
/* 68  VMX_EXIT_TPAUSE                  */  hmR0VmxExitErrUnexpected,
```

---

`hmR0VmxExitExtInt()` - VM-exit handler for external interrupts (**VMX_EXIT_EXT_INT**)

```c
... // 對於 windows 的處理
return VINF_EM_RAW_INTERRUPT;
```

---

`hmR0VmxExitXcptOrNmi()` - VM-exit handler for exceptions or NMIs (**VMX_EXIT_XCPT_OR_NMI**)

```c
// 從 VMX 讀 interruption-info 到 pVmxTransient
hmR0VmxReadExitIntInfoVmcs(pVmxTransient);

uint32_t const uExitIntType = VMX_EXIT_INT_INFO_TYPE(pVmxTransient->uExitIntInfo);
uint8_t const  uVector      = VMX_EXIT_INT_INFO_VECTOR(pVmxTransient->uExitIntInfo);

PCVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;
VBOXSTRICTRC rcStrict;
switch (uExitIntType)
{
    // guest 的 NMI 只能是 host 自己 inject，並且 host inject 到 guest 的 event 都不會觸發 VMExit
    case VMX_EXIT_INT_INFO_TYPE_NMI:
    {
        // 配送 NMI 給 host
        rcStrict = hmR0VmxExitHostNmi(pVCpu, pVmcsInfo);
        break;
    }

    // Privileged software exceptions, e.g. #DB
    case VMX_EXIT_INT_INFO_TYPE_PRIV_SW_XCPT:
        RT_FALL_THRU();
    // Software exceptions, e.g. #BP #OF
    case VMX_EXIT_INT_INFO_TYPE_SW_XCPT:
        RT_FALL_THRU();
    // Hardware exceptions，處理後恢復 guest 執行
    case VMX_EXIT_INT_INFO_TYPE_HW_XCPT:
    {
        hmR0VmxReadExitIntErrorCodeVmcs(pVmxTransient);
        hmR0VmxReadExitInstrLenVmcs(pVmxTransient);
        hmR0VmxReadIdtVectoringInfoVmcs(pVmxTransient);
        hmR0VmxReadIdtVectoringErrorCodeVmcs(pVmxTransient);

        rcStrict = hmR0VmxExitXcpt(pVCpu, pVmxTransient);
        break;
    }

    default: { ... /* error handle */ }
}

return rcStrict;
```

---

`hmR0VmxExitHostNmi()` - Dispatching an NMI on the host CPU that received it

```c
RTCPUID const idCpu = pVmcsInfo->idHostCpuExec;

bool fDispatched = false;
RTCCUINTREG const fEFlags = ASMIntDisableFlags(); // disable interrupt
if (idCpu == RTMpCpuId()) // VM 使用的 host CPU 跟目前一樣
{
    VMXDispatchHostNmi(); // 透過 int 2 來傳送 NMI
    fDispatched = true;
}
ASMSetFlags(fEFlags); // enable interrupt
if (fDispatched)
    return VINF_SUCCESS;

// RTMpOnSpecific() 會等到 worker function (hmR0DispatchHostNmi) 在 target CPU 上執行
return RTMpOnSpecific(idCpu, &hmR0DispatchHostNmi, NULL, NULL);
```

- IDT[2] 對到的是 NMI pin，傳送給 NMI handler 做執行
- 原始碼的註解中有提到：執行到這邊後就不在延後 NMI 的 dispatching

---

`hmR0VmxExitXcpt()` - VM-exit exception handler for all exceptions (except NMIs!)，內部並不是實際在處理每個種類的 exception，而是在判斷 exception 的種類後呼叫對應的 function 處理

```c
// VMExit 是在 delivering event 時發生
VBOXSTRICTRC rcStrict = hmR0VmxCheckExitDueToEventDelivery(pVCpu, pVmxTransient);
if (rcStrict == VINF_SUCCESS)
{
	// optional event 可能需要 reinject 到 guest 內
    // 不過 page fault 比較複雜，在 hmR0VmxExitXcptPF() 中有額外做其他處理
    uint8_t const uVector = VMX_EXIT_INT_INFO_VECTOR(pVmxTransient->uExitIntInfo);
    if (   !pVCpu->hm.s.Event.fPending
        || uVector == X86_XCPT_PF)
    {
        switch (uVector)
        {
            case X86_XCPT_PF: return hmR0VmxExitXcptPF(pVCpu, pVmxTransient);
            case X86_XCPT_GP: return hmR0VmxExitXcptGP(pVCpu, pVmxTransient);
            case X86_XCPT_MF: return hmR0VmxExitXcptMF(pVCpu, pVmxTransient);
            case X86_XCPT_DB: return hmR0VmxExitXcptDB(pVCpu, pVmxTransient);
            case X86_XCPT_BP: return hmR0VmxExitXcptBP(pVCpu, pVmxTransient);
            case X86_XCPT_AC: return hmR0VmxExitXcptAC(pVCpu, pVmxTransient);
            default:
                // 非以上的 interrupt 都會 reinject to guest
                return hmR0VmxExitXcptOthers(pVCpu, pVmxTransient);
        }
    }
}
else if (rcStrict == VINF_HM_DOUBLE_FAULT)
{
    // 先前處理後會重新 inject event 給 guest，確定有 event 正在 pending 即可
    Assert(pVCpu->hm.s.Event.fPending);
    rcStrict = VINF_SUCCESS;
}

return rcStrict;
```

---

`hmR0VmxExitXcptPF()` - VM-exit exception handler for \#PF (Page-fault exception)

```c
HMVMX_VALIDATE_EXIT_XCPT_HANDLER_PARAMS(pVCpu, pVmxTransient);
PVMCC pVM = pVCpu->CTX_SUFF(pVM);
hmR0VmxReadExitQualVmcs(pVmxTransient);

/* If it's a vectoring #PF, emulate injecting the original event injection as PGMTrap0eHandler() is incapable
    of differentiating between instruction emulation and event injection that caused a #PF. See @bugref{6607}. */
// PGMTrap0eHandler() 沒辦法分辨造成 PG 的是 insn emulation 還是 event injection，
// 因此在此模擬原本的 event 去 imject event
if (pVmxTransient->fVectoringPF)
{
    // 確定 flag 有紀錄 event 正在 pending
    Assert(pVCpu->hm.s.Event.fPending);
    return VINF_EM_RAW_INJECT_TRPM_EVENT;
}

PCPUMCTX pCtx = &pVCpu->cpum.GstCtx;
int rc = hmR0VmxImportGuestState(pVCpu, pVmxTransient->pVmcsInfo, HMVMX_CPUMCTX_EXTRN_ALL);

TRPMAssertXcptPF(...); // Assert a page-fault exception
```

- Vectoring #PF - VM-exit 是因為 page fault 在 external interrupt or NMI delivery 時發生
- VINF_EM_RAW_INJECT_TRPM_EVENT - Inject a TRPM event
  - TRPM - Trap Manager

```c
// #PF handler
rc = PGMTrap0eHandler(pVCpu, pVmxTransient->uExitIntErrorCode, CPUMCTX2CORE(pCtx), (RTGCPTR)pVmxTransient->uExitQual);
// 通常是 shadow page table sync 或者 MMIO instruction
if (rc == VINF_SUCCESS)
{
    ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_ALL_GUEST);
    TRPMResetTrap(pVCpu);
    return rc;
}

if (rc == VINF_EM_RAW_GUEST_TRAP) // 沒辦法 handle guest trap，轉給 REM 執行
{
    // guest page fault，需要反映給 guest
    if (!pVmxTransient->fVectoringDoublePF)
    {
		// 取得 error code
        uint32_t const uGstErrorCode = TRPMGetErrorCode(pVCpu);
        // 清除當前的 active trap/exception/interrupt
        TRPMResetTrap(pVCpu);
        pVCpu->hm.s.Event.fPending = false;
        // inject 一個 event 給 guest
        hmR0VmxSetPendingEvent(pVCpu, VMX_ENTRY_INT_INFO_FROM_EXIT_INT_INFO(pVmxTransient->uExitIntInfo), 0, uGstErrorCode, pVmxTransient->uExitQual);
    }
    else
    {
        // double fault (page fault in delivery of page fault), so inject DF
        TRPMResetTrap(pVCpu);
		// 清除當前的 PF
        pVCpu->hm.s.Event.fPending = false;
        // replace PF to DF
        hmR0VmxSetPendingXcptDF(pVCpu);
    }
    return VINF_SUCCESS;
}

// 清除當前的 active trap/exception/interrupt，代表處理完畢
TRPMResetTrap(pVCpu);
return rc;
```

- RC short for ???? (maybe return code)
- REM - Recompiled Execution Monitor
- 如果發生 double fault，則會送 #DF event 給 guest
- `PGMTrap0eHandler()` - host 會先透過 page manager and monitor 處理，如果需要特別處理才會進入下面的 if-else

---

`hmR0VmxExitXcptGP()` - VM-exit exception handler for \#GP (General-protection exception)

```c
HMVMX_VALIDATE_EXIT_XCPT_HANDLER_PARAMS(pVCpu, pVmxTransient);

PCPUMCTX     pCtx      = &pVCpu->cpum.GstCtx;
PVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;

if (pVmcsInfo->RealMode.fRealOnV86Active) // real mode
{ /* likely */ }
else
{
    // 如果 guest 不在 real-mode 或是有 unrestricted guest execution support，就反應 #GP 給 guest
    int rc = hmR0VmxImportGuestState(pVCpu, pVmcsInfo, HMVMX_CPUMCTX_EXTRN_ALL);
    hmR0VmxSetPendingEvent(pVCpu, VMX_ENTRY_INT_INFO_FROM_EXIT_INT_INFO(pVmxTransient->uExitIntInfo), pVmxTransient->cbExitInstr, pVmxTransient->uExitIntErrorCode, 0);
    return rc;
}

int rc = hmR0VmxImportGuestState(pVCpu, pVmcsInfo, HMVMX_CPUMCTX_EXTRN_ALL);
// 執行一行 instruction，但是透過 IEM (Instruction Decoding and Emulation) 跑
VBOXSTRICTRC rcStrict = IEMExecOne(pVCpu);
if (rcStrict == VINF_SUCCESS)
{
    if (!CPUMIsGuestInRealModeEx(pCtx)) // 執行完不在 real-mode
    {
        // 如果可以繼續透過 VMX 執行的話就繼續 (VMX)，否則就只能用 IEM
        pVmcsInfo->RealMode.fRealOnV86Active = false;
        if (HMCanExecuteVmxGuest(pVCpu->pVMR0, pVCpu, pCtx))
            ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_ALL_GUEST);
        else
            rcStrict = VINF_EM_RESCHEDULE; // VM 需要被 rescheduling
    }
    else // 
        ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_ALL_GUEST);
}
else if (rcStrict == VINF_IEM_RAISED_XCPT) // 出現 exception，不過展開等同於 VINF_EM_RESCHEDULE
{
    rcStrict = VINF_SUCCESS;
    ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_RAISED_XCPT_MASK);
}
return VBOXSTRICTRC_VAL(rcStrict);
```

- **NOTE**: guest OS 本身也有 exception/interrupt handler 等等，而當發生 VMExit 時會先到 host 處理，之後若 inject event 到 guest 當中代表呼叫 guest 內的對應 handler 即可
- 模式切換後需要檢查是否能透過 VMX 繼續執行，否則就用模擬的 (IEM)

---

`hmR0VmxExitXcptMF()` - VM-exit exception handler for \#MF (Math Fault: floating point exception)

```c
// 從 VMCS import 到 guest context
int rc = hmR0VmxImportGuestState(pVCpu, pVmxTransient->pVmcsInfo, CPUMCTX_EXTRN_CR0);

// NE - Numeric error
if (!(pVCpu->cpum.GstCtx.cr0 & X86_CR0_NE))
{
    // 將 #MF 轉為 FERR
    rc = PDMIsaSetIrq(pVCpu->CTX_SUFF(pVM), 13, 1, 0 /* uTagSrc */);
    int rc2 = hmR0VmxAdvanceGuestRip(pVCpu, pVmxTransient);
    return rc;
}

hmR0VmxSetPendingEvent(...); // 似乎就送 inject event 到 guest 就好
return VINF_SUCCESS;
```

- `PDMIsaSetIrq()` - Sets the pending interrupt coming from ISA source or HPET

---

`hmR0VmxExitXcptDB()` - VM-exit exception handler for \#DB (Debug exception)

```c
// 從 Exit qualification 取得 DR6 並傳給 DBGF
hmR0VmxReadExitQualVmcs(pVmxTransient);
uint64_t const uDR6 = X86_DR6_INIT_VAL | (pVmxTransient->uExitQual & (  X86_DR6_B0 | X86_DR6_B1 | X86_DR6_B2 | X86_DR6_B3 | X86_DR6_BD | X86_DR6_BS));

int rc;
PCPUMCTX pCtx = &pVCpu->cpum.GstCtx;
// 先給 host 處理
rc = DBGFRZTrap01Handler(pVCpu->CTX_SUFF(pVM), pVCpu, CPUMCTX2CORE(pCtx), uDR6, pVCpu->hm.s.fSingleInstruction);

// 避免執行兩次相同的 insn，確保為 single stepping
if (rc == VINF_EM_DBG_STEPPED && (pVmxTransient->pVmcsInfo->u32ProcCtls & VMX_PROC_CTLS_MONITOR_TRAP_FLAG))
	rc = VINF_EM_RAW_GUEST_TRAP;

if (rc == VINF_EM_RAW_GUEST_TRAP) // guest trap
{
    // 更新 DR6, DR7 以及 LBR
    VMMRZCallRing3Disable(pVCpu);
    HM_DISABLE_PREEMPT(pVCpu);

    pCtx->dr[6] &= ~X86_DR6_B_MASK;
    pCtx->dr[6] |= uDR6;
    if (CPUMIsGuestDebugStateActive(pVCpu))
        ASMSetDR6(pCtx->dr[6]);

    HM_RESTORE_PREEMPT();
    VMMRZCallRing3Enable(pVCpu);

    rc = hmR0VmxImportGuestState(pVCpu, pVmxTransient->pVmcsInfo, CPUMCTX_EXTRN_DR7);

	// 更新 DR7，不過對 debugging 沒有很了解，不確定這邊的行為
    pCtx->dr[7] &= ~(uint64_t)X86_DR7_GD;
    pCtx->dr[7] &= ~(uint64_t)X86_DR7_RAZ_MASK;
    pCtx->dr[7] |= X86_DR7_RA1_MASK;

    rc = VMXWriteVmcsNw(VMX_VMCS_GUEST_DR7, pCtx->dr[7]);

    // 註解說明透過 VMExit 回傳的資訊來對 guest 送 #DB，會比呼叫 hmR0VmxSetPendingXcptDB() 好，因為有些並非 regular #DB
    hmR0VmxSetPendingEvent(pVCpu, VMX_ENTRY_INT_INFO_FROM_EXIT_INT_INFO(pVmxTransient->uExitIntInfo), pVmxTransient->cbExitInstr, pVmxTransient->uExitIntErrorCode, 0);
    return VINF_SUCCESS;
}

// 並非 guest trap 而是 hypervisor 相關的 debug event
// 猜測為 host 正在 debugging
AssertMsg(rc == VINF_EM_DBG_STEPPED || rc == VINF_EM_DBG_BREAKPOINT, ("%Rrc\n", rc));
// 單純設置 VCPU 的 Hyper dr6 即可
CPUMSetHyperDR6(pVCpu, uDR6);

return rc;
```

- `DBGFRZTrap01Handler()` - 給 host 處理 debug 相關的 trap 的 function
- `VINF_EM_RAW_GUEST_TRAP` - 直接 reinject event 給 guest 處理
- REM (Recompiled Execution Monitor) 提供 CPU insn 的 software emulation
- Hyper (`CPUMHYPERCTX`)- The hypervisor context CPU state (just DRx left now)

---

`hmR0VmxExitXcptBP()` - VM-exit exception handler for \#BP (Breakpoint exception)

```c
int rc = hmR0VmxImportGuestState(pVCpu, pVmxTransient->pVmcsInfo, HMVMX_CPUMCTX_EXTRN_ALL);

// 先透過 DBGFRZTrap03Handler() 處理
rc = DBGFRZTrap03Handler(pVCpu->CTX_SUFF(pVM), pVCpu, CPUMCTX2CORE(&pVCpu->cpum.GstCtx));

if (rc == VINF_EM_RAW_GUEST_TRAP) // 如果種類為 raw guest trap，則由 guest 自行處理
{
    // inject guest pending event
    hmR0VmxSetPendingEvent(pVCpu, VMX_ENTRY_INT_INFO_FROM_EXIT_INT_INFO(pVmxTransient->uExitIntInfo), pVmxTransient->cbExitInstr, pVmxTransient->uExitIntErrorCode, 0);
    rc = VINF_SUCCESS;
}
return rc;
```

---

`hmR0VmxExitXcptAC()` - VM-exit exception handler for \#AC (Alignment-check exception)

```c
// 透過 host 開啟 split-lock detection 偵測到 #AC
int rc = hmR0VmxImportGuestState(pVCpu, pVmxTransient->pVmcsInfo,
                                    CPUMCTX_EXTRN_CR0 | CPUMCTX_EXTRN_RFLAGS | CPUMCTX_EXTRN_SS | CPUMCTX_EXTRN_CS);

// 判斷 split-lock 的依據有三種:
// 1. Alignment check 為 disable
// 2. #AC 發生在 0~2
// 3. EFLAGS.AC != 0
// 此 if-else 用來 handle split lock
if (!(pVCpu->cpum.GstCtx.cr0 & X86_CR0_AM) || CPUMGetGuestCPL(pVCpu) != 3 || !(pVCpu->cpum.GstCtx.eflags.u & X86_EFL_AC) )
{
    // 檢查 debug/trace 的 event
    PVMCC pVM = pVCpu->pVMR0; // pointer to vm r0
    
    // 但是 split-lock event 為 disable，並且 VMX split lock 也沒開
    if (   !DBGF_IS_EVENT_ENABLED(pVM, DBGFEVENT_VMX_SPLIT_LOCK)
        && !VBOXVMM_VMX_SPLIT_LOCK_ENABLED())
    {
        if (pVM->cCpus == 1) // 只有一個 CPU
            // potentially wrong，需要 sync 一下 state
            rc = hmR0VmxImportGuestState(pVCpu, pVmxTransient->pVmcsInfo, HMVMX_CPUMCTX_EXTRN_ALL);
    }
    else
    {
        rc = hmR0VmxImportGuestState(pVCpu, pVmxTransient->pVmcsInfo, HMVMX_CPUMCTX_EXTRN_ALL);

        // undefined macro
        VBOXVMM_XCPT_DF(pVCpu, &pVCpu->cpum.GstCtx);

        if (DBGF_IS_EVENT_ENABLED(pVM, DBGFEVENT_VMX_SPLIT_LOCK))
        {
            // raise debug event
            VBOXSTRICTRC rcStrict = DBGFEventGenericWithArgs(pVM, pVCpu, DBGFEVENT_VMX_SPLIT_LOCK, DBGFEVENTCTX_HM, 0);
            if (rcStrict != VINF_SUCCESS)
                return rcStrict;
        }
    }
    ...
}
...
```

- split-lock - a **low-level memory-bus** lock taken by the processor for a memory range that crosses a cache line，而一個 split lock insn 需要消耗 1000 clock cycles
  - 實際上 split lock 為一種 misaligned memory access，並且影響的是整個系統的執行速度
  - 較近期的 intel 會在 CPU 嘗試執行 split lock 時產生 trap，讓 user 決定是否繼續執行
  - 更多資訊可以看 lwn.net 上的 [Developers split over split-lock detection](https://lwn.net/Articles/806466/)
- `DBGFEventGenericWithArgs()` - Raises a generic debug event if enabled and not being ignored
- DBGF - Debugger Facility

```c
{
    ...
    if (pVM->cCpus == 1) // 只有一個 VCPU
    {
	    // 模擬 insn，並且 ignore lock prefix 
        VBOXSTRICTRC rcStrict = IEMExecOneIgnoreLock(pVCpu);
        if (rcStrict == VINF_SUCCESS)
            ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_ALL_GUEST);
        else if (rcStrict == VINF_IEM_RAISED_XCPT)
        {
            ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_RAISED_XCPT_MASK);
            rcStrict = VINF_SUCCESS;
        }
        return rcStrict;
    }
    return VINF_EM_EMULATE_SPLIT_LOCK; // 請求 REM emulation
}

// reinject dbg event，並且到此時不會有 nested 的 case
hmR0VmxSetPendingEvent(pVCpu, VMX_ENTRY_INT_INFO_FROM_EXIT_INT_INFO(pVmxTransient->uExitIntInfo), pVmxTransient->cbExitInstr, pVmxTransient->uExitIntErrorCode, 0);
return VINF_SUCCESS;
```

- VINF_EM_EMULATE_SPLIT_LOCK - Emulate split-lock access on SMP

---

`hmR0VmxExitXcptOthers()` - VM-exit exception handler wrapper for all other exceptions that are not handled by a specific handler，不過此 function 只簡單的 re-injects the exception 到 VM 當中

```c
PCVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;

// 嘗試 reinject 此 exception 給 guest，而此 exception 不能為 double fault
uint8_t const uVector = VMX_EXIT_INT_INFO_VECTOR(pVmxTransient->uExitIntInfo);

#ifdef HMVMX_ALWAYS_TRAP_ALL_XCPTS
int rc = hmR0VmxImportGuestState(pVCpu, pVmxTransient->pVmcsInfo, CPUMCTX_EXTRN_CS | CPUMCTX_EXTRN_RIP);
#endif

// reinject original exception into VM
hmR0VmxSetPendingEvent(pVCpu, VMX_ENTRY_INT_INFO_FROM_EXIT_INT_INFO(pVmxTransient->uExitIntInfo), pVmxTransient->cbExitInstr, pVmxTransient->uExitIntErrorCode, 0);
return VINF_SUCCESS;
```

- `VMX_EXIT_INT_INFO_IS_XCPT_PF()` - 檢測是否為 page fault

---

`hmR0VmxExitIntWindow()` - VM-exit handler for interrupt-window exiting (VMX_EXIT_INT_WINDOW)

```c
// 代表 guest 已經準備好要接收 interrupt，不需要在執行 VMExit
PVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;
hmR0VmxClearIntWindowExitVmcs(pVmcsInfo);
return VINF_SUCCESS;
```

---

`hmR0VmxClearIntWindowExitVmcs()` - Clears the interrupt-window exiting control in the VMCS

```c
if (pVmcsInfo->u32ProcCtls & VMX_PROC_CTLS_INT_WINDOW_EXIT)
{
    pVmcsInfo->u32ProcCtls &= ~VMX_PROC_CTLS_INT_WINDOW_EXIT; // unset
    // 更新到 VMCS
    int rc = VMXWriteVmcs32(VMX_VMCS32_CTRL_PROC_EXEC, pVmcsInfo->u32ProcCtls);
}
```

- `u32ProcCtls` 紀錄與 Processor-based VM-execution controls 相關的屬性

---

`hmR0VmxExitGetsec()` - VM-exit handler for **GETSEC** (VMX_EXIT_GETSEC). Unconditional VM-exit

```c
PVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;
int rc = hmR0VmxImportGuestState(pVCpu, pVmcsInfo, CPUMCTX_EXTRN_CR4);

if (pVCpu->cpum.GstCtx.cr4 & X86_CR4_SMXE) // 需要 SMXE enabled
    return VINF_EM_RAW_EMULATE_INSTR; // 回傳給 host 來模擬

... // return expected error
```

- Safer Mode Extensions (SMX) 相關的功能可以透過 GETSEC 系列的 instruction 來存取

---

`hmR0VmxExitRdtsc()` - VM-exit handler for RDTSC (VMX_EXIT_RDTSC). Conditional VM-exit

```c
PVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;
// 從 VMCS 讀 exit insn 的長度
hmR0VmxReadExitInstrLenVmcs(pVmxTransient);
int rc = hmR0VmxImportGuestState(pVCpu, pVmcsInfo, IEM_CPUMCTX_EXTRN_MUST_MASK);

// 模擬執行 Rdtsc insn
VBOXSTRICTRC rcStrict = IEMExecDecodedRdtsc(pVCpu, pVmxTransient->cbExitInstr);
if (RT_LIKELY(rcStrict == VINF_SUCCESS))
{
    // 當 tsc offsetting 開啟而得到 VMExit 時，需要 reset offsetting
    if (pVmcsInfo->u32ProcCtls & VMX_PROC_CTLS_USE_TSC_OFFSETTING)
        pVmxTransient->fUpdatedTscOffsettingAndPreemptTimer = false;
    // 需要更新 guest rip / rflags
    ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_GUEST_RIP | HM_CHANGED_GUEST_RFLAGS);
}
else if (rcStrict == VINF_IEM_RAISED_XCPT) // rescheduled
{
    // 如果模擬執行失敗，inject 一個 exception
    ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_RAISED_XCPT_MASK);
    rcStrict = VINF_SUCCESS;
}
return rcStrict;
```

- `IEMExecDecodedRdtsc()` - Interface for HM and EM to emulate the `RDTSC` instruction

---

`hmR0VmxExitRdtscp()` - VM-exit handler for RDTSCP (VMX_EXIT_RDTSCP). Conditional VM-exit，基本上與 `hmR0VmxExitRdtsc()` 相同，只差在模擬時執行的是 `IEMExecDecodedRdtscp()`

```c
PVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;
hmR0VmxReadExitInstrLenVmcs(pVmxTransient);
int rc = hmR0VmxImportGuestState(pVCpu, pVmcsInfo, IEM_CPUMCTX_EXTRN_MUST_MASK | CPUMCTX_EXTRN_TSC_AUX);

VBOXSTRICTRC rcStrict = IEMExecDecodedRdtscp(pVCpu, pVmxTransient->cbExitInstr);
if (RT_LIKELY(rcStrict == VINF_SUCCESS))
{
    if (pVmcsInfo->u32ProcCtls & VMX_PROC_CTLS_USE_TSC_OFFSETTING)
        pVmxTransient->fUpdatedTscOffsettingAndPreemptTimer = false;
    ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_GUEST_RIP | HM_CHANGED_GUEST_RFLAGS);
}
else if (rcStrict == VINF_IEM_RAISED_XCPT)
{
    ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_RAISED_XCPT_MASK);
    rcStrict = VINF_SUCCESS;
}
return rcStrict;
```

---

`hmR0VmxExitRdpmc()` - VM-exit handler for RDPMC (VMX_EXIT_RDPMC). Conditional VM-exit

```c
PVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;
int rc = hmR0VmxImportGuestState(pVCpu, pVmcsInfo, CPUMCTX_EXTRN_CR4 | CPUMCTX_EXTRN_CR0 | CPUMCTX_EXTRN_RFLAGS | CPUMCTX_EXTRN_SS);

PCPUMCTX pCtx = &pVCpu->cpum.GstCtx;
// Interpret RDPMC
rc = EMInterpretRdpmc(pVCpu->CTX_SUFF(pVM), pVCpu, CPUMCTX2CORE(pCtx));
if (RT_LIKELY(rc == VINF_SUCCESS))
    // 如果模擬執行成功，更新 guest rip
    rc = hmR0VmxAdvanceGuestRip(pVCpu, pVmxTransient);
else
    rc = VERR_EM_INTERPRETER;
return rc;
```

- rdpmc - Read Performance-Monitoring Counters

---

`hmR0VmxExitVmcall()` - VM-exit handler for VMCALL (VMX_EXIT_VMCALL). Unconditional VM-exit

```c
VBOXSTRICTRC rcStrict = VERR_VMX_IPE_3;
// 檢查是否可以呼叫 hypercall (VMMCALL & VMCALL)
if (EMAreHypercallInstructionsEnabled(pVCpu))
{
    PVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;
    int rc = hmR0VmxImportGuestState(pVCpu, pVmcsInfo, CPUMCTX_EXTRN_RIP | CPUMCTX_EXTRN_RFLAGS | CPUMCTX_EXTRN_CR0 | CPUMCTX_EXTRN_SS  | CPUMCTX_EXTRN_CS | CPUMCTX_EXTRN_EFER);

    // 執行 hypercall
    rcStrict = GIMHypercall(pVCpu, &pVCpu->cpum.GstCtx);
    if (rcStrict == VINF_SUCCESS)
        // 成功就更新 rip
        rc = hmR0VmxAdvanceGuestRip(pVCpu, pVmxTransient);
    else
        // 代表要回到 r3 去執行 hypercall
        Assert(   rcStrict == VINF_GIM_R3_HYPERCALL
                || rcStrict == VINF_GIM_HYPERCALL_CONTINUING
                || RT_FAILURE(rcStrict));
}

// 如果 hypercall disable 或是 failed，就送 #UD
if (RT_FAILURE(rcStrict))
{
    hmR0VmxSetPendingXcptUD(pVCpu);
    rcStrict = VINF_SUCCESS;
}

return rcStrict;
```

- hypercall 透過 GIM (Guest Interface Manager) 來呼叫
- VINF_GIM_R3_HYPERCALL - Return to ring-3 to perform the hypercall there

---

`hmR0VmxExitInvlpg()` - VM-exit handler for INVLPG (VMX_EXIT_INVLPG). Conditional VM-exit

```c
PVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;
// 從 VMCS 更新 qual 以及 exit insn len
hmR0VmxReadExitQualVmcs(pVmxTransient);
hmR0VmxReadExitInstrLenVmcs(pVmxTransient);
int rc = hmR0VmxImportGuestState(pVCpu, pVmcsInfo, IEM_CPUMCTX_EXTRN_EXEC_DECODED_MEM_MASK);

// 模擬執行 Invlpg
VBOXSTRICTRC rcStrict = IEMExecDecodedInvlpg(pVCpu, pVmxTransient->cbExitInstr, pVmxTransient->uExitQual);

if (rcStrict == VINF_SUCCESS || rcStrict == VINF_PGM_SYNC_CR3)
    // 更新 rip 與 rflags
    ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_GUEST_RIP | HM_CHANGED_GUEST_RFLAGS);
else if (rcStrict == VINF_IEM_RAISED_XCPT)
{
    ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_RAISED_XCPT_MASK);
    rcStrict = VINF_SUCCESS;
}
return rcStrict;
```

- INVLPG - Invalidate TLB Entries
- VINF_PGM_SYNC_CR3 - The urge to syncing CR3

---

`hmR0VmxExitHlt()` - VM-exit handler for HLT (VMX_EXIT_HLT). Conditional VM-exit，handle `hlt` instruction

```c
// update rip
int rc = hmR0VmxAdvanceGuestRip(pVCpu, pVmxTransient);
// 檢查是否在 hlt 後需要繼續執行
if (EMShouldContinueAfterHalt(pVCpu, &pVCpu->cpum.GstCtx))
    rc = VINF_SUCCESS;
else
    rc = VINF_EM_HALT;
return rc;
```

---

`hmR0VmxExitPreemptTimer()` - VM-exit handler for expiry of the VMX-preemption timer，timer 過期

```c
/* If the VMX-preemption timer has expired, reinitialize the preemption timer on next VM-entry. */
// 如果 VMX-preemption timer 過期，在下次重新初始化
pVmxTransient->fUpdatedTscOffsettingAndPreemptTimer = false;

/* If there are any timer events pending, fall back to ring-3, otherwise resume guest execution. */

PVMCC pVM = pVCpu->CTX_SUFF(pVM);
// 如果有 timer events 在 pending，有的話就回傳 VINF_EM_RAW_TIMER_PENDING
bool fTimersPending = TMTimerPollBool(pVM, pVCpu);
return fTimersPending ? VINF_EM_RAW_TIMER_PENDING : VINF_SUCCESS;
```

- VINF_EM_RAW_TIMER_PENDING - 回到 ring3 在做處理

---

`hmR0VmxExitXsetbv()` - VM-exit handler for XSETBV (VMX_EXIT_XSETBV). Unconditional VM-exit

```c
PVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;
// 讀 exit insn len
hmR0VmxReadExitInstrLenVmcs(pVmxTransient);
int rc = hmR0VmxImportGuestState(pVCpu, pVmcsInfo, IEM_CPUMCTX_EXTRN_MUST_MASK | CPUMCTX_EXTRN_CR4);

// 模擬執行 ISETBV
VBOXSTRICTRC rcStrict = IEMExecDecodedXsetbv(pVCpu, pVmxTransient->cbExitInstr);
ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, rcStrict != VINF_IEM_RAISED_XCPT ? HM_CHANGED_GUEST_RIP | HM_CHANGED_GUEST_RFLAGS : HM_CHANGED_RAISED_XCPT_MASK);

PCCPUMCTX pCtx = &pVCpu->cpum.GstCtx;
// 當 XCR0 需要在進入 VM 前後保存時就要 set
pVCpu->hm.s.fLoadSaveGuestXcr0 = (pCtx->cr4 & X86_CR4_OSXSAVE) && pCtx->aXcr[0] != ASMGetXcr0();

return rcStrict;
```

- `IEMExecDecodedXsetbv()` - Interface for HM and EM to emulate the `XSETBV` instruction (loads XCRx)
- XSETBV - Set Extended Control Register
- X86_CR4_OSXSAVE - XSAVE and Processor Extended States Enable
  - XSAVE - Save Processor Extended States

---

後續還有許多類似操作的 VMExit handler，在 host 模擬某個 insn 的執行，並根據結果判斷是否要回 guest os 自己處理，就不一一贅述，選擇一些比較特別的介紹。



`hmR0VmxExitIoInstr()` - VM-exit handler for I/O instructions (VMX_EXIT_IO_INSTR). Conditional VM-exit

```c
PCPUMCTX pCtx = &pVCpu->cpum.GstCtx;
PVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;
hmR0VmxReadExitQualVmcs(pVmxTransient);
hmR0VmxReadExitInstrLenVmcs(pVmxTransient);
int rc = hmR0VmxImportGuestState(pVCpu, pVmcsInfo, IEM_CPUMCTX_EXTRN_MUST_MASK | CPUMCTX_EXTRN_SREG_MASK | CPUMCTX_EXTRN_EFER);

// 參考 intel spec. 27-5 "Exit Qualifications for I/O Instructions" 所定的結構
uint32_t const uIOPort      = VMX_EXIT_QUAL_IO_PORT(pVmxTransient->uExitQual);
uint8_t  const uIOSize      = VMX_EXIT_QUAL_IO_SIZE(pVmxTransient->uExitQual);
bool     const fIOWrite     = (VMX_EXIT_QUAL_IO_DIRECTION(pVmxTransient->uExitQual) == VMX_EXIT_QUAL_IO_DIRECTION_OUT);
bool     const fIOString    = VMX_EXIT_QUAL_IO_IS_STRING(pVmxTransient->uExitQual);
bool     const fGstStepping = RT_BOOL(pCtx->eflags.Bits.u1TF);
bool     const fDbgStepping = pVCpu->hm.s.fSingleInstruction;

// 更新 exit history
VBOXSTRICTRC rcStrict;
PCEMEXITREC  pExitRec = NULL;
if (   !fGstStepping
    && !fDbgStepping)
    pExitRec = EMHistoryUpdateFlagsAndTypeAndPC(pVCpu, ...);
```

- `EMEXITREC` - Accumulative exit record

```c
if (!pExitRec) // pExitRec (Pointer to an exit record) 為空
{
    // I/O accesses 的大小
	static uint32_t const s_aIOSizes[4] = { 1, 2, 0, 4 };
    // 將 return value 存放在 rax/eax/ax 的 AND masks
    static uint32_t const s_aIOOpAnd[4] = { 0xff, 0xffff, 0, 0xffffffff };

    uint32_t const cbValue  = s_aIOSizes[uIOSize];
    uint32_t const cbInstr  = pVmxTransient->cbExitInstr;
    bool  fUpdateRipAlready = false;
    PVMCC pVM = pVCpu->CTX_SUFF(pVM);
	// 如果是 String IO operation (INS / OUTS) 的話
    if (fIOString)
    {
        bool const fInsOutsInfo = RT_BF_GET(pVM->hm.s.vmx.Msrs.u64Basic, VMX_BF_BASIC_VMCS_INS_OUTS);
        // 可以的話用 instruction-information，否則就 interpret 此 insn
        if (fInsOutsInfo) // 成功取得 info
        {
            hmR0VmxReadExitInstrInfoVmcs(pVmxTransient);
            // 取得 addr 大小： 0=16-bit, 1=32-bit, 2=64-bit
            IEMMODE const enmAddrMode = (IEMMODE)pVmxTransient->ExitInstrInfo.StrIo.u3AddrSize;
            // 是否為 Repeated IO operation
            bool const fRep = VMX_EXIT_QUAL_IO_IS_REP(pVmxTransient->uExitQual);
            if (fIOWrite) // 模擬執行 write
                rcStrict = IEMExecStringIoWrite(pVCpu, cbValue, enmAddrMode, fRep, cbInstr, pVmxTransient->ExitInstrInfo.StrIo.iSegReg, true);
            else // 模擬執行 read
                rcStrict = IEMExecStringIoRead(pVCpu, cbValue, enmAddrMode, fRep, cbInstr, true);
            }
        }
        else
            rcStrict = IEMExecOne(pVCpu); // 只能 interpret 模擬執行

        ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_GUEST_RIP);
        fUpdateRipAlready = true; // 已經在執行時更新 rip
    }
    else // 一般的 IO operation
    {
        uint32_t const uAndVal = s_aIOOpAnd[uIOSize];
        if (fIOWrite) // write
        {
            rcStrict = IOMIOPortWrite(pVM, pVCpu, uIOPort, pCtx->eax & uAndVal, cbValue);
            // TF - Trap flag
            if (rcStrict == VINF_IOM_R3_IOPORT_WRITE && !pCtx->eflags.Bits.u1TF)
                // 離開 VMX 並且在 r3 處理此 IO operation
                rcStrict = EMRZSetPendingIoPortWrite(pVCpu, uIOPort, cbInstr, cbValue, pCtx->eax & uAndVal);
        }
        else // read (in)
        {
            uint32_t u32Result = 0;
            
            rcStrict = IOMIOPortRead(pVM, pVCpu, uIOPort, &u32Result, cbValue);
            if (IOM_SUCCESS(rcStrict))
                // 儲存 IN insn 的回傳值到 AL/AX/EAX
                pCtx->eax = (pCtx->eax & ~uAndVal) | (u32Result & uAndVal);
            if (rcStrict == VINF_IOM_R3_IOPORT_READ && !pCtx->eflags.Bits.u1TF)
                rcStrict = EMRZSetPendingIoPortRead(pVCpu, uIOPort, cbInstr, cbValue);
        }
    }
	...
}
```

- `IEMExecStringIoWrite()` - Interface for HM and EM for executing string I/O OUT (write) instructions
  - IN (read) 則是 `IEMExecStringIoRead()` 
  - IEM - Interpreted execution manager
- IOM - in/out monitor
- 分成 IOString 以及普通的 IO，如果為普通 IO，在執行完後會檢查是否要回到 r3 處理 (`VINF_IOM_R3_IOPORT_READ` 以及 `VINF_IOM_R3_IOPORT_WRITE`)，舉例來說 device emulation 需要在 r3 模擬

```c
if (!pExitRec)
{
    ...
    if (IOM_SUCCESS(rcStrict))
    {
        if (!fUpdateRipAlready) // 如果操作中沒有更新 rip，現在更新
        {
            hmR0VmxAdvanceGuestRipBy(pVCpu, cbInstr);
            ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_GUEST_RIP);
        }

        // 如果是有 rep prefix 的 ins/outs，需要更新 rflags
        if (fIOString)
            ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_GUEST_RFLAGS);

        rc = hmR0VmxImportGuestState(pVCpu, pVmcsInfo, CPUMCTX_EXTRN_DR7);

        // 如果有 IO breakpoint，需要檢查是否被 trigger，有的話作出對應的回覆
        uint32_t const uDr7 = pCtx->dr[7];
        // DE 為 Debugging Extensions
        if (RT_UNLIKELY(((uDr7 & X86_DR7_ENABLED_MASK) && X86_DR7_ANY_RW_IO(uDr7) && (pCtx->cr4 & X86_CR4_DE)) || DBGFBpIsHwIoArmed(pVM)))
        {
            // 在 host CPU 當中處理 debugging，避免 preempt 發生
            // 也需要 disable r3 call，避免 longjump
            VMMRZCallRing3Disable(pVCpu);
            HM_DISABLE_PREEMPT(pVCpu);

            // 保存 guest DRx state
            bool fIsGuestDbgActive = CPUMR0DebugStateMaybeSaveGuest(pVCpu, true /* fDr6 */);
            // 檢查 guest 或 hypervisor breakpoints 的 I/O access
            VBOXSTRICTRC rcStrict2 = DBGFBpCheckIo(pVM, pVCpu, pCtx, uIOPort, cbValue);
            if (rcStrict2 == VINF_EM_RAW_GUEST_TRAP)
            {
                // guest raw trap --> inject #DB event 給 guest 處理
                if (fIsGuestDbgActive)
                    ASMSetDR6(pCtx->dr[6]);
                if (pCtx->dr[7] != uDr7)
                    pVCpu->hm.s.fCtxChanged |= HM_CHANGED_GUEST_DR7;

                hmR0VmxSetPendingXcptDB(pVCpu);
            }
            else if (rcStrict2 != VINF_SUCCESS && (rcStrict == VINF_SUCCESS || rcStrict2 < rcStrict))
                rcStrict = rcStrict2;

            // 恢復 preempt / longjump
            HM_RESTORE_PREEMPT();
            VMMRZCallRing3Enable(pVCpu);
        }
    }
    ...
}
```

- `VMMRZCallRing3Disable()` - 能 disable host call 來避免 r3 的 longjump，實際上把 VCPU 當中用於記錄 ring3 call counter 的 `cCallRing3Disabled` 做加減 1 來 disable/enable 而已
  - Call Ring-3 - Formerly known as host calls，看起來是作用於 guest，不過不確定具體行為

```c
if (!pExitRec) { ... /* 上方的程式碼 */ }
else // 有 exit record
{
    // 透過 EMHistoryExec() 即可
    int rc2 = hmR0VmxImportGuestState(pVCpu, pVmcsInfo, HMVMX_CPUMCTX_EXTRN_ALL);
    rcStrict = EMHistoryExec(pVCpu, pExitRec, 0);
    ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_ALL_GUEST);
}
return rcStrict;
```

---

`hmR0VmxExitTaskSwitch()` - VM-exit handler for task switches (VMX_EXIT_TASK_SWITCH). Unconditional VM-exit

```c
/* Check if this task-switch occurred while delivery an event through the guest IDT. */
// 檢查 task-switch 是否在 delivery event 發生時透過 IDT 執行
hmR0VmxReadExitQualVmcs(pVmxTransient);
if (VMX_EXIT_QUAL_TASK_SWITCH_TYPE(pVmxTransient->uExitQual) == VMX_EXIT_QUAL_TASK_SWITCH_TYPE_IDT)
{
    hmR0VmxReadIdtVectoringInfoVmcs(pVmxTransient); // 讀取 vectoring IDT
    if (VMX_IDT_VECTORING_INFO_IS_VALID(pVmxTransient->uIdtVectoringInfo))
    {
        uint32_t uErrCode;
        // 取得 error code
        if (VMX_IDT_VECTORING_INFO_IS_ERROR_CODE_VALID(pVmxTransient->uIdtVectoringInfo))
        {
            hmR0VmxReadIdtVectoringErrorCodeVmcs(pVmxTransient);
            uErrCode = pVmxTransient->uIdtVectoringErrorCode;
        }
        else
            uErrCode = 0;

        RTGCUINTPTR GCPtrFaultAddress;
        // 取得 fault address
        if (VMX_IDT_VECTORING_INFO_IS_XCPT_PF(pVmxTransient->uIdtVectoringInfo))
            GCPtrFaultAddress = pVCpu->cpum.GstCtx.cr2;
        else
            GCPtrFaultAddress = 0;

        hmR0VmxReadExitInstrLenVmcs(pVmxTransient);
        // 給 guest 自行處理
        hmR0VmxSetPendingEvent(pVCpu, VMX_ENTRY_INT_INFO_FROM_EXIT_IDT_INFO(pVmxTransient->uIdtVectoringInfo), pVmxTransient->cbExitInstr, uErrCode, GCPtrFaultAddress);
        // Inject a TRPM event
        return VINF_EM_RAW_INJECT_TRPM_EVENT;
    }
}

// 註解表示需要透過 interpreter 來模擬 task-switch，但 VERR_EM_INTERPRETER 的註解卻說 interpreter 無法 emulate (?)
return VERR_EM_INTERPRETER;
```

- VMX_EXIT_QUAL_TASK_SWITCH_TYPE_IDT - Task switch caused by an interrupt gate
- Vectoring 代表正在處理的 interrupt

---

`hmR0VmxExitEptMisconfig()` - VM-exit handler for EPT misconfiguration (VMX_EXIT_EPT_MISCONFIG). Conditional VM-exit

- 舉例來說，guest 存取 physical address 時，如果 EPT table 沒有對應的 host address，就會觸發此異常
- 首先會透過 `EMHistoryUpdateFlagsAndTypeAndPC()` 嘗試將 engine specific exit 轉成 generic one
  - 回傳 pointer 時用 `EMHistoryExec()` 處理此 special action
  - 回傳 NULL 時代表用 normal exit action 處理即可，後續程式碼透過  `PGMR0Trap0eHandlerNPMisconfig()` 處理

---

`hmR0VmxExitEptViolation()` - VM-exit handler for EPT violation (VMX_EXIT_EPT_VIOLATION). Conditional VM-exit，EPT 內有 3 bit 表示 page perm，如果權限錯誤就會 trigger EPT violation

```c
HMVMX_VALIDATE_EXIT_HANDLER_PARAMS(pVCpu, pVmxTransient);
Assert(pVCpu->CTX_SUFF(pVM)->hm.s.fNestedPaging);

... // 從 VMCS 讀一些狀態更新到 pVmxTransient

// VMExit 發生在 event delivery
VBOXSTRICTRC rcStrict = hmR0VmxCheckExitDueToEventDelivery(pVCpu, pVmxTransient);
if (RT_LIKELY(rcStrict == VINF_SUCCESS))
{
    // delivery event 時發生 EPT violation，需要解析一開始的 #PF，然後 reinject 原本的事件
}
else { ... /* other error */ }

PVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;
hmR0VmxReadGuestPhysicalAddrVmcs(pVmxTransient);
int rc = hmR0VmxImportGuestState(pVCpu, pVmcsInfo, IEM_CPUMCTX_EXTRN_MUST_MASK);
AssertRCReturn(rc, rc);

RTGCPHYS const GCPhys    = pVmxTransient->uGuestPhysicalAddr;
uint64_t const uExitQual = pVmxTransient->uExitQual;

RTGCUINT uErrorCode = 0;
if (uExitQual & VMX_EXIT_QUAL_EPT_INSTR_FETCH)
    uErrorCode |= X86_TRAP_PF_ID;
if (uExitQual & VMX_EXIT_QUAL_EPT_DATA_WRITE)
    uErrorCode |= X86_TRAP_PF_RW;
if (uExitQual & VMX_EXIT_QUAL_EPT_ENTRY_PRESENT)
    uErrorCode |= X86_TRAP_PF_P;

PVMCC    pVM  = pVCpu->CTX_SUFF(pVM);
PCPUMCTX pCtx = &pVCpu->cpum.GstCtx;

// 雖然是 assert，但是有更新 trpm，感覺也是做 inject event
TRPMAssertXcptPF(pVCpu, GCPhys, uErrorCode);
// 處理 nested shadow table 發生的 PF trap
rcStrict = PGMR0Trap0eHandlerNestedPaging(pVM, pVCpu, PGMMODE_EPT, uErrorCode, CPUMCTX2CORE(pCtx), GCPhys);
TRPMResetTrap(pVCpu);

if (rcStrict == VINF_SUCCESS || rcStrict == VERR_PAGE_TABLE_NOT_PRESENT || rcStrict == VERR_PAGE_NOT_PRESENT)
{
    // 成功 sync nested page tables
    ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, HM_CHANGED_GUEST_RIP | HM_CHANGED_GUEST_RSP | HM_CHANGED_GUEST_RFLAGS);
    return VINF_SUCCESS;
}
return rcStrict;
```

---

`hmR0VmxInjectEventVmcs()` - Injects an event into the guest upon VM-entry by updating the relevant fields in the VM-entry area in the VMCS，透過此 function 能送 guest 一個 interrupt event (inject)，通常會需要以下資訊：

- interrupt info
- exception error code
- cr2

```c
/* Intel spec. 24.8.3 "VM-Entry Controls for Event Injection" specifies the interruption-information field to be 32-bits. */
PCPUMCTX          pCtx       = &pVCpu->cpum.GstCtx;
uint32_t          u32IntInfo = pEvent->u64IntInfo;
uint32_t const    u32ErrCode = pEvent->u32ErrCode;
uint32_t const    cbInstr    = pEvent->cbInstr;
RTGCUINTPTR const GCPtrFault = pEvent->GCPtrFaultAddress;
uint8_t const     uVector    = VMX_ENTRY_INT_INFO_VECTOR(u32IntInfo);
uint32_t const    uIntType   = VMX_ENTRY_INT_INFO_TYPE(u32IntInfo);


// hw interrupt / exception 沒辦法在 real mode 透過 software interrupt redirection bitmap 轉為 real mode task，需要透過 guest 的 interrupt handler 處理
// 如果在 real mode (PE, Protected Mode Enable == 0)
if (CPUMIsGuestInRealModeEx(pCtx))
{
    // 如果 unrestricted guest execution
    if (pVCpu->CTX_SUFF(pVM)->hm.s.vmx.fUnrestrictedGuest)
        // unset deliver-error-code bit
        u32IntInfo &= ~VMX_ENTRY_INT_INFO_ERROR_CODE_VALID;
    else
        {
            PVMCC pVM = pVCpu->CTX_SUFF(pVM);
            PVMXVMCSINFO pVmcsInfo = pVmxTransient->pVmcsInfo;
            int rc2 = hmR0VmxImportGuestState(pVCpu, pVmcsInfo, CPUMCTX_EXTRN_SREG_MASK | CPUMCTX_EXTRN_TABLE_MASK | CPUMCTX_EXTRN_RIP | CPUMCTX_EXTRN_RSP | CPUMCTX_EXTRN_RFLAGS);

        	// interrupt handler 存在於 IVT (real-mode IDT)
            size_t const cbIdtEntry = sizeof(X86IDTR16);
            if (uVector * cbIdtEntry + (cbIdtEntry - 1) > pCtx->idtr.cbIdt)
            {
                // 如果沒有 IDT entry 的情況下 inject #DF，會觸發 triple-fault
                if (uVector == X86_XCPT_DF)
                    return VINF_EM_RESET; // 需要重啟

                // 如果沒有 IDT entry 的情況下 inject #GP，inject double-fault
                if (uVector == X86_XCPT_GP)
                {
                    uint32_t const uXcptDfInfo = ...;
                    HMEVENT EventXcptDf;
                    RT_ZERO(EventXcptDf);
                    EventXcptDf.u64IntInfo = uXcptDfInfo;
                    return hmR0VmxInjectEventVmcs(pVCpu, pVmxTransient, &EventXcptDf, fStepping, pfIntrState);
                }
                
                // 無效的 IDT entry --> inject #GP event
                uint32_t const uXcptGpInfo = ...;
                HMEVENT EventXcptGp;
                RT_ZERO(EventXcptGp);
                EventXcptGp.u64IntInfo = uXcptGpInfo;
                return hmR0VmxInjectEventVmcs(pVCpu, pVmxTransient, &EventXcptGp, fStepping, pfIntrState);
            }

        	// SW: software exception
            uint16_t uGuestIp = pCtx->ip;
            if (uIntType == VMX_ENTRY_INT_INFO_TYPE_SW_XCPT)
                // #BP and #OF 就直接恢復下一個 insn
                uGuestIp = pCtx->ip + (uint16_t)cbInstr;
            else if (uIntType == VMX_ENTRY_INT_INFO_TYPE_SW_INT)
                uGuestIp = pCtx->ip + (uint16_t)cbInstr;

            ...
        }
}
```

- IRB - interrupt redirection bitmap

```c
{
    {
        {
			...
			// 從 IDT entry 取得 code segment selector 跟 offset
            X86IDTR16 IdtEntry;
            RTGCPHYS const GCPhysIdtEntry = (RTGCPHYS)pCtx->idtr.pIdt + uVector * cbIdtEntry;
            rc2 = PGMPhysSimpleReadGCPhys(pVM, &IdtEntry, GCPhysIdtEntry, cbIdtEntry);

			// 為 interrupt handler 建立 stack frame
            VBOXSTRICTRC rcStrict;
			// pushes 2-byte 到 real-mode 中的 guest's stack
            rcStrict = hmR0VmxRealModeGuestStackPush(pVCpu, pCtx->eflags.u32);
            if (rcStrict == VINF_SUCCESS)
            {
                rcStrict = hmR0VmxRealModeGuestStackPush(pVCpu, pCtx->cs.Sel);
                if (rcStrict == VINF_SUCCESS)
                    rcStrict = hmR0VmxRealModeGuestStackPush(pVCpu, uGuestIp);
            }

			// 清除 eflag bit 並且跳去執行 interrupt/exception handler
            if (rcStrict == VINF_SUCCESS)
            {
                pCtx->eflags.u32 &= ~(X86_EFL_IF | X86_EFL_TF | X86_EFL_RF | X86_EFL_AC);
                pCtx->rip         = IdtEntry.offSel;
                pCtx->cs.Sel      = IdtEntry.uSel;
                pCtx->cs.ValidSel = IdtEntry.uSel;
                pCtx->cs.u64Base  = IdtEntry.uSel << cbIdtEntry;
                // hardware exception & page fault
                if (uIntType == VMX_ENTRY_INT_INFO_TYPE_HW_XCPT && uVector == X86_XCPT_PF)
                    pCtx->cr2 = GCPtrFault;

                // 更新要在 guest 執行前更新的 register
                ASMAtomicUoOrU64(&pVCpu->hm.s.fCtxChanged, ...);

               	// 如果處理的是 hw 並且有 block-by-sti，就把他清除
                if (*pfIntrState & VMX_VMCS_GUEST_INT_STATE_BLOCK_STI)
                    *pfIntrState &= ~VMX_VMCS_GUEST_INT_STATE_BLOCK_STI;

                // 已經將 event 分發給 guest，mark pending false 讓我們如果在執行 guest code 前回 r3 的話不需要取消 event
                pVCpu->hm.s.Event.fPending = false;

                // 成功 single stepping，回傳給 debugger
                if (fStepping)
                    rcStrict = VINF_EM_DBG_STEPPED;
            }
            return rcStrict;
			...
        }
    }
}
```

```c
// 如果 VM 在 protected mode

// inject event into VMCS
int rc = VMXWriteVmcs32(VMX_VMCS32_CTRL_ENTRY_INTERRUPTION_INFO, u32IntInfo);
if (VMX_ENTRY_INT_INFO_IS_ERROR_CODE_VALID(u32IntInfo))
    rc |= VMXWriteVmcs32(VMX_VMCS32_CTRL_ENTRY_EXCEPTION_ERRCODE, u32ErrCode);
rc |= VMXWriteVmcs32(VMX_VMCS32_CTRL_ENTRY_INSTR_LENGTH, cbInstr);

// update cr2 if #PF
if (VMX_ENTRY_INT_INFO_IS_XCPT_PF(u32IntInfo))
    pCtx->cr2 = GCPtrFault;

return VINF_SUCCESS;
```

- 在 protected mode 就直接透過 VMCS 傳 event



而一些 VMExit handler 會呼叫 `hmR0VmxSetPendingEvent()` 來送 event 給 guest，在執行 `hmR0VmxPreRunGuest()` 準備進 VM 時，會呼叫 `hmR0VmxInjectPendingEvent()` --> `hmR0VmxInjectEventVmcs()` 來 inject 這些 exception



## 7

上面部分為 VT-X 的架構，後續 HM (Hardware Assisted Virtualization Manager) 就能利用這些 API 實作，一共分成 R0 跟 R3 兩個部分，code 存在於 VMM\VMMR0\HMR0.cpp , VMM\VMMR0\VMMR0.cpp  以及 VMM\VMMR3\HM.cpp。

---

`ModuleInit()` - Initialize the module. This is called when we're first loaded

```c
VMM_CHECK_SMAP_SETUP();
VMM_CHECK_SMAP_CHECK(RT_NOTHING);

// 初始化過程中會參雜 VMM_CHECK_SMAP_CHECK，檢查是否有 trigger SMAP
int rc = vmmInitFormatTypes();
rc = GVMMR0Init(); // 初始化 GVMM
rc = GMMR0Init(); // 初始化 GMM
rc = HMR0Init(); // 初始化 HM
PDMR0Init(hMod); // 初始化 PDM
rc = PGMRegisterStringFormatTypes();
rc = PGMR0DynMapInit(); // optional
rc = IntNetR0Init(); // internal network 初始化
rc = PciRawR0Init(); // optional
rc = CPUMR0ModuleInit();
rc = vmmR0TripleFaultHackInit();
rc = NEMR0Init();

// 只要上方初始化時失敗，就會執行下面的 function
NEMR0Term();
vmmR0TripleFaultHackTerm();
PciRawR0Term();
IntNetR0Term();
PGMR0DynMapTerm();
PGMDeregisterStringFormatTypes();
HMR0Term();
GMMR0Term();
GVMMR0Term();
vmmTermFormatTypes();
```

- GVMM - Global VM Manager
- GMM - Global Memory Manager
- HM - Hardware Assisted Virtualization Manager
- PDM - Pluggable Device and Driver Manager
- IntNet - Internal Network

---

`vmmR0InitVM()` - Initiates the R0 driver for a particular VM instance

```c
// r3 跟 r0 的 SVN revision 不相符
// uSvnRev: r3, VMMGetSvnRev(): r0
if (uSvnRev != VMMGetSvnRev())
    return VERR_VMM_R0_VERSION_MISMATCH;
if (uBuildType != vmmGetBuildType()) // r0, r3 的 build type
    return VERR_VMM_R0_VERSION_MISMATCH;

int rc = GVMMR0ValidateGVMandEMT(pGVM, 0 /*idCpu*/);

// 檢查 host 是否支援高精度的 timer
if (   pGVM->vmm.s.fUsePeriodicPreemptionTimers
    && !RTTimerCanDoHighResolution())
    pGVM->vmm.s.fUsePeriodicPreemptionTimers = false;

// 初始化 per VM data: GVMM 與 GMM
// 但是似乎沒有 GMMR0InitVM()
rc = GVMMR0InitVM(pGVM);
if (RT_SUCCESS(rc))
{
    // 初始化 HM, CPUM, PGM
    rc = HMR0InitVM(pGVM);
    rc = CPUMR0InitVM(pGVM);
    rc = PGMR0InitVM(pGVM);
    rc = EMR0InitVM(pGVM); // EM: emulation manager
    rc = PciRawR0InitVM(pGVM); // optional
    rc = GIMR0InitVM(pGVM); // optional
    GVMMR0DoneInitVM(pGVM);
    return rc;
}

// 如果失敗會執行
GIMR0TermVM(pGVM);
PciRawR0TermVM(pGVM); // optional
HMR0TermVM(pGVM);
return rc;
```

- EM - emulation manager ?

---

`VMMR0EntryFast()` - The Ring 0 entry point, called by the fast-ioctl path，此處為 R0 的入口點，當 R3 要進 guest OS 時會呼叫此 function

```c
// 檢查 cpu id 是否落在合理的範圍
if (   idCpu < pGVM->cCpus
    && pGVM->cCpus == pGVM->cCpusUnsafe)
{ /*likely*/ }
else { ... /* error handle */ }

PGVMCPU pGVCpu = &pGVM->aCpus[idCpu];
RTNATIVETHREAD const hNativeThread = RTThreadNativeSelf();
if (RT_LIKELY(   pGVCpu->hEMT == hNativeThread && pGVCpu->hNativeThreadR0 == hNativeThread))
{ /* likely */ }
else { ... /* error handle */ }

// 處理 requested operation
switch (enmOperation)
{
    // 用 HM 來執行 guest code
    case VMMR0_DO_HM_RUN:
    {
        for (;;) /* hlt loop */
        {
            // Disable preemption
            RTTHREADPREEMPTSTATE PreemptState = RTTHREADPREEMPTSTATE_INITIALIZER;
            RTThreadPreemptDisable(&PreemptState);

            // 檢查 host cpu id 是否合法，並且查看對應 cpu id 的 TSC delta 是否 available
            RTCPUID  idHostCpu;
            uint32_t iHostCpuSet = RTMpCurSetIndexAndId(&idHostCpu);
            if (RT_LIKELY(iHostCpuSet < RTCPUSET_MAX_CPUS && SUPIsTscDeltaAvailableForCpuSetIndex(iHostCpuSet)))
            {
                pGVCpu->iHostCpuSet = iHostCpuSet;
                ASMAtomicWriteU32(&pGVCpu->idHostCpu, idHostCpu);

                /*
                    * Update the periodic preemption timer if it's active.
                    */
                // 更新週期的 preeption timer
                if (pGVM->vmm.s.fUsePeriodicPreemptionTimers)
                    GVMMR0SchedUpdatePeriodicPreemptionTimer(pGVM, pGVCpu->idHostCpu, TMCalcHostTimerFrequency(pGVM, pGVCpu));

				...
```

- EMT - emulation thread

```c
{
    {
        {
            {
                ...
				int  rc;
                bool fPreemptRestored = false;
                // 如果目前有 suspend event 如 power event，就先不執行 guest OS
                if (!HMR0SuspendPending())
                {
                    // 如果有 context switching hook 就 enable 此功能
                    if (pGVCpu->vmm.s.hCtxHook != NIL_RTTHREADCTXHOOK)
                        int rc2 = RTThreadCtxHookEnable(pGVCpu->vmm.s.hCtxHook);
                    
                    // 讓目前 CPU 開啟 VT-X
                    rc = HMR0Enter(pGVCpu);
                    if (RT_SUCCESS(rc))
                    {
                        VMCPU_SET_STATE(pGVCpu, VMCPUSTATE_STARTED_HM);

                        // 如果有 preemption hooks，因為已經在 HM context 了
                        // 因此可以 enable preemption
                        if (vmmR0ThreadCtxHookIsEnabled(pGVCpu))
                        {
                            fPreemptRestored = true;
                            RTThreadPreemptRestore(&PreemptState);
                        }

                        // 設置 longjmp 來執行 HMR0RunGuestCode()
                        rc = vmmR0CallRing3SetJmp(&pGVCpu->vmm.s.CallRing3JmpBufR0, HMR0RunGuestCode, pGVM, pGVCpu);

                        // 因為我們在 setjmp/longjmp 區域之外，所以用 normal assertion 會讓 host panic，因此用 manual assertion
                        if (RT_UNLIKELY(   VMCPU_GET_STATE(pGVCpu) != VMCPUSTATE_STARTED_HM && RT_SUCCESS_NP(rc) && rc != VINF_VMM_CALL_HOST ))
                            // 表示 HM 處於 wrong state
                            rc = VERR_VMM_WRONG_HM_VMCPU_STATE;

                        VMCPU_SET_STATE(pGVCpu, VMCPUSTATE_STARTED);
                    }

                    // 在禁用 context hook / 恢復 preemption 前無效化 host CPU id
                    pGVCpu->iHostCpuSet = UINT32_MAX; // mark 成無效的值
                    ASMAtomicWriteU32(&pGVCpu->idHostCpu, NIL_RTCPUID);

                    // 因為 cleanup 的問題，回 ring-3 時 context hook 不能為 enable
                    if (pGVCpu->vmm.s.hCtxHook != NIL_RTTHREADCTXHOOK)
                    {
                        ASMAtomicWriteU32(&pGVCpu->idHostCpu, NIL_RTCPUID);
                        RTThreadCtxHookDisable(pGVCpu->vmm.s.hCtxHook); // disable
                    }
                }
                else // system 處於 suspend，回 r3 處理
                {
                    rc = VINF_EM_RAW_INTERRUPT;
                    pGVCpu->iHostCpuSet = UINT32_MAX;
                    ASMAtomicWriteU32(&pGVCpu->idHostCpu, NIL_RTCPUID);
                }
                ...
            }
        }
    }
...
```

- `HMR0Enter()` - Enters the VT-x or AMD-V session
- VINF_EM_RAW_INTERRUPT 似乎會回 r3 處理

```c
{
    {
        {
            {
                ...
				// 恢復 preemption
                if (!fPreemptRestored)
                    RTThreadPreemptRestore(&PreemptState);

                pGVCpu->vmm.s.iLastGZRc = rc;

                // halt
                if (rc != VINF_EM_HALT) { /* do nothing*/ }
                else // guest os 執行到 hlt 會回傳 VINF_EM_HALT
                {
                    // 如果有 external interrupt，就繼續執行
                    pGVCpu->vmm.s.iLastGZRc = rc = vmmR0DoHalt(pGVM, pGVCpu);
                    if (rc == VINF_SUCCESS)
                    {
                        pGVCpu->vmm.s.cR0HaltsSucceeded++;
                        continue;
                    }
                    // 沒有的話就回 r3
                    pGVCpu->vmm.s.cR0HaltsToRing3++;
                }
            }
            else
            {
                pGVCpu->iHostCpuSet = UINT32_MAX; // mark 成 invalid
                ASMAtomicWriteU32(&pGVCpu->idHostCpu, NIL_RTCPUID);
                
                // enable preemption
                RTThreadPreemptRestore(&PreemptState);
                if (iHostCpuSet < RTCPUSET_MAX_CPUS)
                {
                    // 用 iHostCpuSet 來算 TSC delta
                    int rc = SUPR0TscDeltaMeasureBySetIndex(pGVM->pSession, iHostCpuSet, 0, 2, 5*RT_MS_1SEC, 0);
                    // target cpu 目前沒在運作 (offline)
                    if (RT_SUCCESS(rc) || rc == VERR_CPU_OFFLINE)
                        pGVCpu->vmm.s.iLastGZRc = VINF_EM_RAW_TO_R3; // 回 r3
                    else
                        pGVCpu->vmm.s.iLastGZRc = rc;
                }
                else
                    pGVCpu->vmm.s.iLastGZRc = VERR_INVALID_CPU_INDEX;
            }
            break;

        } /* halt loop. */
        break;
    }
    case VMMR0_DO_NOP: ... ; /* for 效能測量 */
    default:
        pGVCpu->vmm.s.iLastGZRc = VERR_NOT_SUPPORTED;
        break;
}
```

- hlt 可以讓 CPU 進入待機模式，而在收到 external interrupt 時 (動到鍵盤、滑鼠) 就會醒來繼續執行
- VMMR0_DO_RAW_RUN 已經被拔掉，不然似乎會透過 DBT 來執行

---

關於 r0、r3、rc/gc 的功用，在官方的討論區有[一篇文章](https://www.virtualbox.org/pipermail/vbox-dev/2016-February/013689.html)做了簡單的介紹：

```
Hi Luca,

device emulation code in VirtualBox can run within three contexts:

// 當我們在離開 guest 並回到 userland 時就會執行到這段 code
* R3 (part of VBoxDD): Normal userland code executed in the VM
  process context. This code is executed each time we leave the
  guest and go back to userland. This code is not that performance-
  critical, e.g. device initialization, memory allocation etc.

// 從 VM 離開後進入 root mode 就會執行這段 code，整體的 code 比 r3 小很多，因為有些都可以直接用 host OS 所提供的 feature 實作
* R0 (part of VMMR0): Code which is executed in kernel context.
  This happens if the VM runs in VT-x/AMD-V mode and we left the
  VM and entered the root mode where the VirtualBox VMM runs
  (next to the host OS kernel). For performance reasons we don't
  switch to userland (R3). The amount of R0 code is much smaller
  than the amount of R3 code. Such code can also call host OS
  kernel functions directly (e.g. submit a network IP packet to
  the host OS network layer). Calling the host OS code from VMMR0
  is usually done using SUPR0* functions which are implemented in
  src/VBox/HostDrivers/Support and runtime functions which are
  implemented in src/VBox/Runtime/r0drv

// rc/gc 負責處理沒辦法在 VT-X AMD-V 執行的情況，這些 code 為 r0 的一部份
* RC/GC (part of VMMRC.rc): This code is executed if the VM runs
  in non VT-x/AMD-V mode (legacy). Only 32-bit code. This code is
  part of the hypervisor which runs in R0 in the context of the
  guest process. The guest itself runs at R1 (guest userland as
  R3 as usual). Google should explain you x86 ring compression.
  
// guest os 運行在 r1，而 guest userland 一樣執行在 r3

Of course R3 code cannot directly call R0 code. The code in our
device driver has sections which are unique to two or all three
contexts. That means that this code is compiled three times and
exists in all three contexts. Other code is exclusively used in
one or two contexts.
```

而前幾封信件中也有一些有用的資訊，稍微做個整理：

- R3 process 需要透過 #GP 來存取 I/O space
- with hardware virtualization, guest code 可以直接運行在 host's R0 context，因為 VM entries and exits 就是在此發生

---

`vmmR0DoHalt()` - This does one round of `vmR3HaltGlobal1Halt()`，如果 function 回傳 VINF_SUCCESS 代表繼續執行，其他的就回 R3。而此 function 會執行 2 次 waiting，一次為 polling、一次為 sleep，如果還是沒有 exteral interrupt 就回 r3

```c
// Number of ring-0 halts
if (++pGVCpu->vmm.s.cR0Halts & 0xff)
{ /* likely */ }
else if (pGVCpu->vmm.s.cR0HaltsSucceeded > pGVCpu->vmm.s.cR0HaltsToRing3)
{
    pGVCpu->vmm.s.cR0HaltsSucceeded = 2;
    pGVCpu->vmm.s.cR0HaltsToRing3   = 0;
}
else
{
    pGVCpu->vmm.s.cR0HaltsSucceeded = 0;
    pGVCpu->vmm.s.cR0HaltsToRing3   = 2;
}

// 設置回 r3 前的 flag

// VM 相關
uint32_t const fVmFFs  = VM_FF_TM_VIRTUAL_SYNC | VM_FF_PDM_QUEUES | VM_FF_PDM_DMA | VM_FF_DBGF | VM_FF_REQUEST | VM_FF_CHECK_VM_STATE | VM_FF_RESET | VM_FF_EMT_RENDEZVOUS | VM_FF_PGM_NEED_HANDY_PAGES | VM_FF_PGM_NO_MEMORY              | VM_FF_DEBUG_SUSPEND;

// CPU 相關
uint64_t const fCpuFFs = VMCPU_FF_TIMER | VMCPU_FF_PDM_CRITSECT | VMCPU_FF_IEM | VMCPU_FF_REQUEST | VMCPU_FF_DBGF | VMCPU_FF_HM_UPDATE_CR3 | VMCPU_FF_HM_UPDATE_PAE_PDPES | VMCPU_FF_PGM_SYNC_CR3 | VMCPU_FF_PGM_SYNC_CR3_NON_GLOBAL | VMCPU_FF_TO_R3 | VMCPU_FF_IOM;

// Checks 是否處於 MWAIT (monitor wait)
unsigned const uMWait = EMMonitorWaitIsActive(pGVCpu);
// 計算 guest 的 interruptiblity
CPUMINTERRUPTIBILITY const enmInterruptibility = CPUMGetGuestInterruptibility(pGVCpu);

if (pGVCpu->vmm.s.fMayHaltInRing0 && !TRPMHasTrap(pGVCpu) && (   enmInterruptibility == CPUMINTERRUPTIBILITY_UNRESTRAINED || uMWait > 1))
{
    // 如果 VM/CPU 的 force flag 的其中一個有 set，則需要回 r3 處理
    if (!VM_FF_IS_ANY_SET(pGVM, fVmFFs) && !VMCPU_FF_IS_ANY_SET(pGVCpu, fCpuFFs))
    {
        // 檢查是否有 APIC pending interrupts 並更新
        if (VMCPU_FF_TEST_AND_CLEAR(pGVCpu, VMCPU_FF_UPDATE_APIC))
            APICUpdatePendingInterrupts(pGVCpu);

        // wake up from hlt 的 flag
        uint64_t const fIntMask = VMCPU_FF_INTERRUPT_APIC | VMCPU_FF_INTERRUPT_PIC | VMCPU_FF_INTERRUPT_NESTED_GUEST | VMCPU_FF_INTERRUPT_NMI  | VMCPU_FF_INTERRUPT_SMI | VMCPU_FF_UNHALT;

        // VCPU 有 interrupt event 時，處理並回傳結果
        if (VMCPU_FF_IS_ANY_SET(pGVCpu, fIntMask))
            return vmmR0DoHaltInterrupt(pGVCpu, uMWait, enmInterruptibility);
        ASMNopPause();

        // 查看距離下個 time event 的時間
        uint64_t u64Delta;
        uint64_t u64GipTime = TMTimerPollGIP(pGVM, pGVCpu, &u64Delta);

        // check again
        if (!VM_FF_IS_ANY_SET(pGVM, fVmFFs) && !VMCPU_FF_IS_ANY_SET(pGVCpu, fCpuFFs))
        {
            if (VMCPU_FF_TEST_AND_CLEAR(pGVCpu, VMCPU_FF_UPDATE_APIC))
                APICUpdatePendingInterrupts(pGVCpu);
            if (VMCPU_FF_IS_ANY_SET(pGVCpu, fIntMask))
                return vmmR0DoHaltInterrupt(pGVCpu, uMWait, enmInterruptibility);
            
            // 等到有足夠的時間執行 timer event
            if (u64Delta >= pGVCpu->vmm.s.cNsSpinBlockThreshold)
            {
                // 同時有多個 CPU 執行，就延遲一下在做循環，等待其他 VCPU 會讓 device 發生 interrupt
                if (pGVCpu->vmm.s.cR0HaltsSucceeded > pGVCpu->vmm.s.cR0HaltsToRing3 && RTMpGetOnlineCount() >= 4)
                {
                    uint32_t cSpinLoops = 42;
                    // 重複做上述的事情：
                    // 1. 檢查 APIC interrupt 並更新
                    // 2. VM / CPU 的 force flag 是否設置，如果有的話要回 r3
                    // 3. 是否有 interrupt，執行 vmmR0DoHaltInterrupt() 並回傳結果
                    while (cSpinLoops-- > 0)
                    {
                        ASMNopPause();
                        if (VMCPU_FF_TEST_AND_CLEAR(pGVCpu, VMCPU_FF_UPDATE_APIC))
                            APICUpdatePendingInterrupts(pGVCpu);
                        ASMNopPause();
                        if (VM_FF_IS_ANY_SET(pGVM, fVmFFs))
                            return VINF_EM_HALT;
                        ASMNopPause();
                        if (VMCPU_FF_IS_ANY_SET(pGVCpu, fCpuFFs))
                            return VINF_EM_HALT;
                        ASMNopPause();
                        if (VMCPU_FF_IS_ANY_SET(pGVCpu, fIntMask))
                            return vmmR0DoHaltInterrupt(pGVCpu, uMWait, enmInterruptibility);
                        ASMNopPause();
                    }
                }

                // STARTED --> STARTED_HALTED
                if (VMCPU_CMPXCHG_STATE(pGVCpu, VMCPUSTATE_STARTED_HALTED, VMCPUSTATE_STARTED))
                {
                    if (!VM_FF_IS_ANY_SET(pGVM, fVmFFs) && !VMCPU_FF_IS_ANY_SET(pGVCpu, fCpuFFs))
                    {
                        if (VMCPU_FF_TEST_AND_CLEAR(pGVCpu, VMCPU_FF_UPDATE_APIC))
                            APICUpdatePendingInterrupts(pGVCpu);
                        if (VMCPU_FF_IS_ANY_SET(pGVCpu, fIntMask))
                        {
                            // HALTED --> STARTED
                            VMCPU_CMPXCHG_STATE(pGVCpu, VMCPUSTATE_STARTED, VMCPUSTATE_STARTED_HALTED);
                            return vmmR0DoHaltInterrupt(pGVCpu, uMWait, enmInterruptibility);
                        }

                        // hlt block
                        uint64_t const u64StartSchedHalt   = RTTimeNanoTS();
                        // 模擬 thread 停 u64GipTime 時間，也就是第二次 wait
                        int rc = GVMMR0SchedHalt(pGVM, pGVCpu, u64GipTime);
                        uint64_t const u64EndSchedHalt     = RTTimeNanoTS();
                        uint64_t const cNsElapsedSchedHalt = u64EndSchedHalt - u64StartSchedHalt;
                        // 設置狀態為 STARTED_HALTED --> STARTED
                        VMCPU_CMPXCHG_STATE(pGVCpu, VMCPUSTATE_STARTED, VMCPUSTATE_STARTED_HALTED);
                        if (rc == VINF_SUCCESS || rc == VERR_INTERRUPTED)
                        {
                            int64_t const cNsOverslept = u64EndSchedHalt - u64GipTime;
                            // 重新檢查是否可以恢復執行 or 必須要回 r3 處理
                            if (!VM_FF_IS_ANY_SET(pGVM, fVmFFs) && !VMCPU_FF_IS_ANY_SET(pGVCpu, fCpuFFs))
                            {
                                if (VMCPU_FF_TEST_AND_CLEAR(pGVCpu, VMCPU_FF_UPDATE_APIC))
                                    APICUpdatePendingInterrupts(pGVCpu);
                                if (VMCPU_FF_IS_ANY_SET(pGVCpu, fIntMask))
                                    return vmmR0DoHaltInterrupt(pGVCpu, uMWait, enmInterruptibility);
                            }
                        }
                    }
                }
            }
        }
    }
}
```

- `vmmR0DoHaltInterrupt()` - An interrupt or unhalt force flag is set, deal with it
- `XXX_FF_IS_ANY_SET()` 看 force flag 有沒有被設置，如果有的話應該就需要回 r3

---

`vmmR0EntryExWorker()` - `VMMR0EntryEx()` worker function, either called directly or when ever possible called thru a longjmp so we can exit safely on failure，類似 driver 當中的 DispatchRoutine，VMMR0 driver 也同樣提供一些 ioctl 的 command 給 VMMR3 使用

```c
... // 省略參數檢查
int rc;
switch (enmOperation)
{
    // GVM request
    case VMMR0_DO_GVMM_CREATE_VM:
        if (pGVM == NULL && u64Arg == 0 && idCpu == NIL_VMCPUID)
            rc = GVMMR0CreateVMReq((PGVMMCREATEVMREQ)pReqHdr, pSession);
        else
            rc = VERR_INVALID_PARAMETER;
        VMM_CHECK_SMAP_CHECK(RT_NOTHING);
        break;
    ...
}
```

其中有一些 operation 如 `VMMR0TermVM()` 比較有趣，提出來做分析。

---

`VMMR0TermVM()` - Terminates the R0 bits for a particular VM instance

```c
if (idCpu != NIL_VMCPUID)
{
    // Validates a GVM/EMT pair 是否合法
    int rc = GVMMR0ValidateGVMandEMT(pGVM, idCpu);
    if (RT_FAILURE(rc))
        return rc;
}

// VM 的離開需要在 GVMM / GIM / HM 做一些處理
if (GVMMR0DoingTermVM(pGVM))
{
    GIMR0TermVM(pGVM); 
    HMR0TermVM(pGVM);
}

// 取消註冊 logger
RTLogSetDefaultInstanceThread(NULL, (uintptr_t)pGVM->pSession);
return VINF_SUCCESS;
```

- GVM - ring-0 (global) global VM
- GVMM - Global VM Manager

---

>  進入 VMX mode 以及退出的相關 function



`HMR0Enter()` - Enters the VT-x or AMD-V session

```c
// 當 suspend 的過程中 disable HM，這樣做能確保不進入 session 當中
AssertReturn(!ASMAtomicReadBool(&g_HmR0.fSuspended), VERR_HM_SUSPEND_PENDING);
Assert(!RTThreadPreemptIsEnabled(NIL_RTTHREAD)); // preemption 已經 disable

// 加載進入 HM 所需的最低限度的狀態
int rc = hmR0EnterCpu(pVCpu);
if (RT_SUCCESS(rc))
{
    // 如果 support VMX (intel) 就會是 set 的
    if (g_HmR0.hwvirt.u.vmx.fSupported) { ... /* assertion */ }
    else  { ... /* assertion */ } // 否則為 SVM (amd)

    // keep track 有 VMCS 的 CPU，可能會用來 debugging 奇怪的 scheduling & ring-3 call
    rc = g_HmR0.pfnEnterSession(pVCpu);

    // 因為可能會在 longjump 後執行 code，有機會被其他 CPU schedule 到，所以在此保存 host-state
    rc = g_HmR0.pfnExportHostState(pVCpu);
}
return rc;
```

---

`hmR0EnterCpu()` - Turns on HM on the CPU if necessary and initializes the bare minimum state required for entering HM context

```c
Assert(!RTThreadPreemptIsEnabled(NIL_RTTHREAD)); // preemption 已經 disable
int              rc       = VINF_SUCCESS;
RTCPUID const    idCpu    = RTMpCpuId();
PHMPHYSCPU       pHostCpu = &g_HmR0.aCpuInfo[idCpu];

// 如果還沒 config (or init ?)，就 enable VT-x or AMD-V on cpu
if (!pHostCpu->fConfigured)
    rc = hmR0EnableCpu(pVCpu->CTX_SUFF(pVM), idCpu);

// 在 longjump to r3 前註冊 callback，讓 HM 可以在需要時禁用 VT-x/AMD-V
VMMRZCallRing3SetNotification(pVCpu, hmR0CallRing3Callback, NULL);

// 在從 r3/migrated CPU 回來時重新載入 host-state
if (g_HmR0.hwvirt.u.vmx.fSupported) // VMX 
    pVCpu->hm.s.fCtxChanged |= HM_CHANGED_HOST_CONTEXT | HM_CHANGED_VMX_HOST_GUEST_SHARED_STATE;
else // SVM
    pVCpu->hm.s.fCtxChanged |= HM_CHANGED_HOST_CONTEXT | HM_CHANGED_SVM_HOST_GUEST_SHARED_STATE;

pVCpu->hm.s.idEnteredCpu = idCpu;
return rc;
```

---

`HMR0LeaveCpu()` - Deinitializes the bare minimum state used for HM context and if necessary disable HM on the CPU，離開 root mode

```c
RTCPUID const idCpu    = RTMpCpuId();
PCHMPHYSCPU   pHostCpu = &g_HmR0.aCpuInfo[idCpu];

// fGlobalInit: VT-x/AMD-V is enabled globally at init time，否則會在每次執行 guest code 前
// fConfigured: VT-x or AMD-V 是否已經設置
if (!g_HmR0.fGlobalInit && pHostCpu->fConfigured)
{
    int rc = hmR0DisableCpu(idCpu); // disable HW
    // 確保在下次執行時獲得一個 non-zero ASID/VPID (NIL_RTCPUID for the first time)
    pVCpu->hm.s.idLastCpu = NIL_RTCPUID;
}

// 目前擁有 VMCS 的 CPU 的 CPU ID，在離開 HW 時清除，hmPokeCpuForTlbFlush() 會需要
pVCpu->hm.s.idEnteredCpu = NIL_RTCPUID;

// deregister 跳到 r3 的 callback，代表我們已經不需要 hardware resources
VMMRZCallRing3RemoveNotification(pVCpu);
return VINF_SUCCESS;
```

- `hmR0DisableCpu()` - Disable VT-x or AMD-V on the current CPU

---

`hmR0DisableCpu()` - Disable VT-x or AMD-V on the current CPU

```c
PHMPHYSCPU pHostCpu = &g_HmR0.aCpuInfo[idCpu];

Assert(!g_HmR0.hwvirt.u.vmx.fSupported || !g_HmR0.hwvirt.u.vmx.fUsingSUPR0EnableVTx);
Assert(!RTThreadPreemptIsEnabled(NIL_RTTHREAD)); // 關閉 preemption
Assert(idCpu == (RTCPUID)RTMpCpuIdToSetIndex(idCpu)); /** @todo fix idCpu == index assumption (rainy day) */
Assert(idCpu < RT_ELEMENTS(g_HmR0.aCpuInfo)); // cpuid 合法
Assert(!pHostCpu->fConfigured || pHostCpu->hMemObj != NIL_RTR0MEMOBJ);

if (pHostCpu->hMemObj == NIL_RTR0MEMOBJ) // objec ptr 指向 NULL
    return pHostCpu->fConfigured ? VERR_NO_MEMORY : VINF_SUCCESS;

int rc;
if (pHostCpu->fConfigured)
{
    rc = g_HmR0.pfnDisableCpu(pHostCpu, pHostCpu->pvMemObj, pHostCpu->HCPhysMemObj);
    pHostCpu->fConfigured = false; // 標註為還沒 config
    pHostCpu->idCpu = NIL_RTCPUID; // 清除 cpuid
}
else
    rc = VINF_SUCCESS;
return rc;
```

- 有些 assertion 是要滿足 `!VMX` or `!enableVTx`，不太確定原因

---

`HMR0RunGuestCode()` - Runs guest code in a hardware accelerated VM，不過就是一個 wrapper function，呼叫對應支援的 VT run guest code function (`pfnRunGuestCode()`)

```c
... // some optional code
VBOXSTRICTRC rcStrict = g_HmR0.pfnRunGuestCode(pVCpu);
... // some optional code
return VBOXSTRICTRC_VAL(rcStrict);
```

---

`HMR0InvalidatePage()` - Invalidates a guest page from the host TLB，透過 HM 來 invalidate page

```c
PVMCC pVM = pVCpu->CTX_SUFF(pVM);
if (pVM->hm.s.vmx.fSupported) // VMX
    return VMXR0InvalidatePage(pVCpu, GCVirt);
return SVMR0InvalidatePage(pVCpu, GCVirt); // SVM
```

---

進入 HM 的 r3 部分前，大致瀏覽整個 r3 的執行流程中關於 init 與 fini 的部分：

- `hmR3Init()`
  - `hmR3InitFinalizeR0()`
    - `hmR3InitFinalizeR0Intel()`
    - `hmR3InitFinalizeR0Amd()`
  - `hmR3InitFinalizeR3()`
- `hmR3Term()`

相關的 struct 有：

- `struct HM` - HM VM Instance data. Changes to this must checked against the padding of the hm union in VM
- `struct HMCPU` - HM VMCPU Instance data，其中**包含 VMCS**

---

`hmR3Init()` - Initializes the HM

因為是 r3 重要的 function，因此一併附上官方的註解

```c
/* This is the very first component to really do init after CFGM so that we can
 * establish the predominant execution engine for the VM prior to initializing
 * other modules.  It takes care of NEM initialization if needed (HM disabled or
 * not available in HW).
 *
 * If VT-x or AMD-V hardware isn't available, HM will try fall back on a native
 * hypervisor API via NEM, and then back on raw-mode if that isn't available
 * either.  The fallback to raw-mode will not happen if /HM/HMForced is set
 * (like for guest using SMP or 64-bit as well as for complicated guest like OS
 * X, OS/2 and others).
 *
 * Note that a lot of the set up work is done in ring-0 and thus postponed till
 * the ring-3 and ring-0 callback to HMR3InitCompleted.
 */
```

- 建立 execution engine
- NEM initialization
- 如果 VT-X or AMD-V 不支援，則 HM 會透過 NEM 使用 native hypervisor API 或回 raw-mode
- **猜測**註解的意思為：在 r3 做的一些 setup 完成後會呼叫 r0 的 callback function `HMR3InitCompleted()`

並且由於此 function 太大，只會取其中相較重要的部分

```c
// 註冊 internal data unit
int rc = SSMR3RegisterInternal(pVM, "HWACCM", ...);
// 註冊 info handler
rc = DBGFR3InfoRegisterInternalEx(pVM, "hm", "Dumps HM info.", ...);
...
// 驗證 HM setting
rc = CFGMR3ValidateConfig(pCfgHm, "/HM/", ...);
...
// 檢查 VT-X 或 AMD-v 是否支援，並設置一些相關的 flag
if (pVM->fHMEnabled)
{
    uint32_t fCaps;
    // 檢查是否支援，內部呼叫 ioctl 交給 VMMR0 處理 
    rc = SUPR3QueryVTCaps(&fCaps);
    if (RT_SUCCESS(rc))
    {
		...
    }
    else
    {
        const char *pszMsg;
        switch (rc)
        {
            case VERR_UNSUPPORTED_CPU: ...; break;
            case VERR_VMX_NO_VMX: ...; break;
            ... // 省略其他 case，可以從 error msg 知道對應 error 在做什麼
            default:
                return VMSetError(pVM, rc, RT_SRC_POS, "SUPR3QueryVTCaps failed with %Rrc", rc);
        }

        pVM->fHMEnabled = false;
        // 嘗試執行 NEM (native emulation monitor)
        if (fFallbackToNEM)
        {
            int rc2 = NEMR3Init(pVM, true /*fFallback*/, fHMForced);
        	...
        }
        if (RT_FAILURE(rc))
            // 已經不支援 DBT
            return VM_SET_ERROR(pVM, rc, pszMsg);
    }
```

- NEM - native emulation monitor
- 較新的 Vbox 已經不支援 DBT

---

`HMR3InitCompleted()` - Called when a init phase has completed

```c
switch (enmWhat)
{
    // ring-3 init 完成
    case VMINITCOMPLETED_RING3:
        return hmR3InitFinalizeR3(pVM);
    // ring-0 init 完成
    case VMINITCOMPLETED_RING0:
        return hmR3InitFinalizeR0(pVM);
    default:
        return VINF_SUCCESS;
}
```

---

`hmR3InitFinalizeR0()` - Initialize VT-x or AMD-V，做了 flag 檢測以及對應的 error handler、CPU 初始化等等，由於大多相似，因此省略大部分程式碼

```c
// Enable VT-x or AMD-V on all host CPUs
rc = SUPR3CallVMMR0Ex(VMCC_GET_VMR0_FOR_CALL(pVM), 0 /*idCpu*/, VMMR0_DO_HM_ENABLE, 0, NULL);
...
if (pVM->hm.s.vmx.fSupported)
    rc = hmR3InitFinalizeR0Intel(pVM);
else
    rc = hmR3InitFinalizeR0Amd(pVM);
...
```

---

`hmR3InitFinalizeR0Intel()` - Finish VT-x initialization (after ring-0 init)

```c
// 透過 CPUID 取得對應的 value，失敗就將其清除
if (... && CPUMR3GetGuestCpuIdFeature(pVM, CPUMCPUIDFEATURE_RDTSCP))
    CPUMR3ClearGuestCpuIdFeature(pVM, CPUMCPUIDFEATURE_RDTSCP);
...

// Call ring-0 to set up the VM
rc = SUPR3CallVMMR0Ex(VMCC_GET_VMR0_FOR_CALL(pVM), 0 /* idCpu */, VMMR0_DO_HM_SETUP_VM, 0 /* u64Arg */, NULL /* pReqHdr */);
...
CPUMR3SetGuestCpuIdFeature(pVM, CPUMCPUIDFEATURE_SEP);
if (pVM->hm.s.fAllow64BitGuests)
{
    CPUMR3SetGuestCpuIdFeature(pVM, CPUMCPUIDFEATURE_PAE);
    CPUMR3SetGuestCpuIdFeature(pVM, CPUMCPUIDFEATURE_LONG_MODE); // long mode
    CPUMR3SetGuestCpuIdFeature(pVM, CPUMCPUIDFEATURE_SYSCALL); // 使用 syscall
    CPUMR3SetGuestCpuIdFeature(pVM, CPUMCPUIDFEATURE_LAHF);
    CPUMR3SetGuestCpuIdFeature(pVM, CPUMCPUIDFEATURE_NX);
}
...
if (pVM->hm.s.fNestedPaging) // 支援 nested paging
{
	...
    if (pVM->hm.s.fLargePages) // 支援 large paging
        // 設置 EPT 開啟 2 MB
        PGMSetLargePageUsage(pVM, true);
}
...
// 針對 support 的 feature 執行對應的 handler
if (pVM->hm.s.vmx.fVpid) { ... }
if (pVM->hm.s.vmx.fUsePreemptTimer) { ... }
if (pVM->hm.s.vmx.fUseVmcsShadowing) { ... }
```

---

`hmR3InitFinalizeR3()` - Initializes HM components after ring-3 phase has been fully initialized

```c
if (!HMIsEnabled(pVM))
    return VINF_SUCCESS;

for (VMCPUID idCpu = 0; idCpu < pVM->cCpus; idCpu++)
{
    PVMCPU pVCpu = pVM->apCpusR3[idCpu];
    pVCpu->hm.s.fActive = false; // 還沒使用 VT
    // GIMR3Init() 跑完了，所以此時使用與 GIM 相關的 function 很安全
    pVCpu->hm.s.fGIMTrapXcptUD = GIMShouldTrapXcptUD(pVCpu);
}
...
```

- `fGIMTrapXcptUD` -紀錄是否 \#UD 需要被 intercepted (required by certain GIM providers)

---

`HMR3Reset()` - The VM is being reset

```c
if (HMIsEnabled(pVM))
    hmR3DisableRawMode(pVM);

for (VMCPUID idCpu = 0; idCpu < pVM->cCpus; idCpu++)
    HMR3ResetCpu(pVM->apCpusR3[idCpu]); // reset CPU

// 清除所有 patch information
pVM->hm.s.pGuestPatchMem     = 0;
pVM->hm.s.pFreeGuestPatchMem = 0;
pVM->hm.s.cbGuestPatchMem    = 0;
pVM->hm.s.cPatches           = 0;
pVM->hm.s.PatchTree          = 0;
pVM->hm.s.fTPRPatchingActive = false;
ASMMemZero32(pVM->hm.s.aPatches, sizeof(pVM->hm.s.aPatches));
```

---

`HMR3ResetCpu()` - Resets a virtual CPU

```c
pVCpu->hm.s.fCtxChanged |= HM_CHANGED_HOST_CONTEXT | HM_CHANGED_ALL_GUEST;
// 設置一些 event，當各種 manager 讀取到這些 flag 並跳出 for loop 進行處理，如呼叫 HMR3IsActive() 時檢查目前是否正在使用 hardware acceleration
pVCpu->hm.s.fActive                        = false;
pVCpu->hm.s.Event.fPending                 = false;
pVCpu->hm.s.vmx.u64GstMsrApicBase          = 0;
pVCpu->hm.s.vmx.VmcsInfo.fSwitchedTo64on32Obsolete = false;
pVCpu->hm.s.vmx.VmcsInfo.fWasInRealMode    = true;
```

---

`hmR3TermCPU()` - Terminates the per-VCPU HM，但什麼都沒有

```c
return VINF_SUCCESS;
```

---

`HMR3Term()` - Terminates the HM

```c
if (pVM->hm.s.vmx.pRealModeTSS)
{
    // 釋放 VMM device heap 的記憶體
    PDMR3VmmDevHeapFree(pVM, pVM->hm.s.vmx.pRealModeTSS);
    pVM->hm.s.vmx.pRealModeTSS       = 0;
}
hmR3TermCPU(pVM);
return 0;
```



## 8

