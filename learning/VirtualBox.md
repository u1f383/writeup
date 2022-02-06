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
pVmcsInfo->pfnStartVM = VMXR0StartVM64;
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
    // 要求 TSC_AUX MSR 在執行完 VMExit 後從 auto-load/store MSR 被移出 (?)
    pVmxTransient->fRemoveTscAuxMsr = true;
}
```

- 整個 function 基本上都是載入 guest os context 到 host 中，並且視情況保存 host 原先的執行狀態

---

`hmR0VmxRunGuest()` - Wrapper for running the guest code in VT-x

---

`hmR0VmxPostRunGuest()` - First C routine invoked after running guest code using hardware-assisted VMX