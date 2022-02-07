[notion link](https://www.notion.so/Virtualbox-694abab61a5c4a19aec48671bf747069)



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

`HMR0Init(void)` - Does global Ring-0 HM initialization (at module init)

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
```

---

`hmR0VmxExitXcptGP()` - VM-exit exception handler for \#GP (General-protection exception)

```c
```

---

`hmR0VmxExitXcptMF()` - VM-exit exception handler for \#MF (Math Fault: floating point exception)

```c
```

---

`hmR0VmxExitXcptDB()` - VM-exit exception handler for \#DB (Debug exception)

```c
```

---

`hmR0VmxExitXcptBP()` - VM-exit exception handler for \#BP (Breakpoint exception)

```c
```

---

`hmR0VmxExitXcptAC()` - VM-exit exception handler for \#AC (Alignment-check exception)

```c
```

---

`hmR0VmxExitXcptOthers()` - VM-exit exception handler wrapper for all other exceptions that are not handled by a specific handler

```c
```

