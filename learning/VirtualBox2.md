## 8

`vmR3InitRing3()` - Initializes all R3 components of the VM，此 function 對所有 manager 初始化

```c
int rc;

// 對每個 cpu 註冊 EMT 與 GVM
for (VMCPUID idCpu = 1; idCpu < pVM->cCpus; idCpu++)
    // vmR3RegisterEMT: Register the calling EMT with GVM
    rc = VMR3ReqCallWait(pVM, idCpu, (PFNRT)vmR3RegisterEMT, 2, pVM, idCpu);

... // 註冊與 statistic 相關的 function
Assert(pVM->bMainExecutionEngine == VM_EXEC_ENGINE_NOT_SET);
rc = NEMR3InitConfig(pVM); // NEM config
rc = HMR3Init(pVM); // 在初始化 VM 的過程中也會一併初始化 HM

rc = MMR3Init(pVM);
rc = CPUMR3Init(pVM);
rc = NEMR3InitAfterCPUM(pVM);
rc = PGMR3Init(pVM);
rc = MMR3InitPaging(pVM);
rc = TMR3Init(pVM);
rc = VMMR3Init(pVM);
rc = SELMR3Init(pVM);
rc = TRPMR3Init(pVM);
rc = SSMR3RegisterStub(pVM, "CSAM", 0);
rc = SSMR3RegisterStub(pVM, "PATM", 0);
rc = IOMR3Init(pVM);
rc = EMR3Init(pVM);
rc = IEMR3Init(pVM);
rc = DBGFR3Init(pVM);
// GIM 需要在 PDM 之前被 init
rc = GIMR3Init(pVM);
rc = PDMR3Init(pVM);
rc = PGMR3InitDynMap(pVM);
rc = MMR3HyperInitFinalize(pVM);
rc = PGMR3InitFinalize(pVM);
rc = TMR3InitFinalize(pVM);
PGMR3MemSetup(pVM, false /*fAtReset*/);
PDMR3MemSetup(pVM, false /*fAtReset*/);
rc = vmR3InitDoCompleted(pVM, VMINITCOMPLETED_RING3);
return VINF_SUCCESS;

// 如果上面失敗，就會呼叫 XXXTerm() 終止對應的 manager
int rc2 = PDMR3Term(pVM);
int rc2 = GIMR3Term(pVM);
int rc2 = DBGFR3Term(pVM);
int rc2 = IEMR3Term(pVM);
int rc2 = EMR3Term(pVM);
int rc2 = IOMR3Term(pVM);
int rc2 = TRPMR3Term(pVM);
int rc2 = SELMR3Term(pVM);
int rc2 = VMMR3Term(pVM);
int rc2 = TMR3Term(pVM);
int rc2 = PGMR3Term(pVM);
int rc2 = CPUMR3Term(pVM);
// 不能呼叫 MMR3Term()，不然 heap 會被 release
int rc2 = HMR3Term(pVM);
NEMR3Term(pVM);
```

- `NEMR3InitConfig()` - Basic init and configuration reading
- 名詞解釋
  - NEM - native emulation manager
  - MM - memory manager
  - CPUM - CPU manager / monitor
  - PGM - page manager / monitor
  - TM - time manager
  - VMM - virtual machine monitor
  - SELM - the selector manager，用在 DBT
  - TRPM - trap monitor
  - SSM - saved state manager
  - IOM - input / output monitor
  - EM - execution manager / monitor
  - IEM - interpreted execution manager
  - DBGF - debugger facility
  - GIM - guest interface manager
  - PDM - pluggable device manager

---

VM manager 提供一系列的 API 用來建立執行 guest 的 VMM instance，包含 guest os 的執行 (emulation thread, EMT) 以及 guest os 的執行錯誤處理。程式碼中可以看到 VM manager 更細部的初始化其他 manager，並且呼叫了 API，可以視為各個 manger 的包裝，一共分成 R3 跟 R0 兩個部分：

- R3 - VM.cpp - create / start / terminate / pause / continue / schudule 虛擬機
- R0 - VMMR0.cpp



`VMR3Create()` - Creates a virtual machine by calling the supplied configuration constructor

```c
if (pVmm2UserMethods) // VMM user 自己提供的 optional function table
{ ... /* 一些 assertion 確定傳入的東西可以使用 */ }
... // 一些 assertion 確保其他 manager 非 NULL ptr

// 建立 UVM (user VM)，讓我們可以註冊 at-error callback
PUVM pUVM = NULL;
int rc = vmR3CreateUVM(cCpus, pVmm2UserMethods, &pUVM); // Creates the UVM
if (pfnVMAtError)
    // 使用者傳入指向 callback function 的 pointer，在 setting VM 發生 error 時可以呼叫
    rc = VMR3AtErrorRegister(pUVM, pfnVMAtError, pvUserVM);
if (RT_SUCCESS(rc))
{
    // 初始化用於建立 session 的 support library (vboxdrv.sys)
    rc = SUPR3Init(&pUVM->vm.s.pSession);
    if (RT_SUCCESS(rc))
    {
        // 在 EMT thread 內呼叫 vmR3CreateU() 並等待其執行完畢
        PVMREQ pReq;
        // 為 call request 分配一塊資源並放到 queue 等待執行
        rc = VMR3ReqCallU(pUVM, VMCPUID_ANY, &pReq, RT_INDEFINITE_WAIT, VMREQFLAGS_VBOX_STATUS, (PFNRT)vmR3CreateU, 4, pUVM, cCpus, pfnCFGMConstructor, pvUserCFGM);
        rc = pReq->iStatus;
        VMR3ReqFree(pReq); // 釋放 request packet
        if (RT_SUCCESS(rc))
        {
			if (ppVM)
                *ppVM = pUVM->pVM;
            if (ppUVM)
            {
                // 增加 ref count of the UVM handle 來維持 user mode VM handle
                VMR3RetainUVM(pUVM);
                *ppUVM = pUVM;
            }
            return VINF_SUCCESS;
        }
		// 在建立 VM 時出現 error，設置錯誤訊息後呼叫 callback function
        const char *pszError;
        switch (rc)
        {
            case VERR_VMX_IN_VMX_ROOT_MODE:
				...; break; // VM incorrectly left in VMX root mode
            case VERR_HM_CONFIG_MISMATCH:
                ...; break; // host VT-x/AMD-V 沒開但 vbox 用 VT 執行
            case VERR_SVM_IN_USE:
                ...; break; // unsupport AMD-V
            case VERR_SUPDRV_COMPONENT_NOT_FOUND:
                ...; break; // kernel module 沒載入成功，建議重裝
            case VERR_RAW_MODE_INVALID_SMP:
                ...; break; // 需要 VT-x/AMD-V 來模擬 SMP
            case VERR_SUPDRV_KERNEL_TOO_OLD_FOR_VTX:
                ...; break; // kernel 太舊了
            case VERR_PDM_DEVICE_NOT_FOUND:
                ...; break; // virtual device 找不到
            case VERR_PCI_PASSTHROUGH_NO_HM:
                ...; break; // PCI passthrough 需要 VT-x/AMD-V
            case VERR_PCI_PASSTHROUGH_NO_NESTED_PAGING:
                ...; break; // PCI passthrough 需要 nested paging
            default:
                // 如果沒 error (count == 0)，
                if (VMR3GetErrorCount(pUVM) == 0)
                    pszError = RTErrGetFull(rc);
                else
                    pszError = NULL; /* already set. */
                break;
        }
        // 如果有 error，更新 UVM
        if (pszError)
            vmR3SetErrorU(pUVM, rc, RT_SRC_POS, pszError, rc);
    }
    else // 在初始化 support library 時發生錯誤
    {
        const char *pszError;
        switch (rc)
        {
            case VERR_VM_DRIVER_LOAD_ERROR:
                ...; break; // vbox kernel driver 沒有被載入
            case VERR_VM_DRIVER_OPEN_ERROR:
                ...; break; // vbox kernel driver 無法打開
            case VERR_VM_DRIVER_NOT_ACCESSIBLE:
                ...; break; // vbox kernel driver 無法存取
            case VERR_VM_DRIVER_NOT_INSTALLED:
                ...; break; // vbox kernel driver 沒裝
            case VERR_NO_MEMORY:
                ...; break; // support library 沒有記憶體可以用
            case VERR_VERSION_MISMATCH:
            case VERR_VM_DRIVER_VERSION_MISMATCH:
                ...; break; // vbox support driver 跟 vbox 版本不同
            default: ...; break; // error happen 
        }
        vmR3SetErrorU(pUVM, rc, RT_SRC_POS, pszError, rc);
    }
}
vmR3DestroyUVM(pUVM, 2000); // 等待 2 秒後 destroy UVM portion 
```

- IPRT - VirtualBox Portable Runtime (from official document)

---

`vmR3CreateUVM()` - Creates the UVM

```c
// 建立且初始化 UVM

// 分配記憶體
PUVM pUVM = (PUVM)RTMemPageAllocZ(RT_UOFFSETOF_DYN(UVM, aCpus[cCpus]));
pUVM->u32Magic          = UVM_MAGIC;
pUVM->cCpus             = cCpus;
pUVM->pVmm2UserMethods  = pVmm2UserMethods;

pUVM->vm.s.cUvmRefs      = 1;
// pointer 指向自己
pUVM->vm.s.ppAtStateNext = &pUVM->vm.s.pAtState;
pUVM->vm.s.ppAtErrorNext = &pUVM->vm.s.pAtError;
pUVM->vm.s.ppAtRuntimeErrorNext = &pUVM->vm.s.pAtRuntimeError;

pUVM->vm.s.enmHaltMethod = VMHALTMETHOD_BOOTSTRAP;
RTUuidClear(&pUVM->vm.s.Uuid);

// 初始化 UVM 內的 VMCPU
for (i = 0; i < cCpus; i++)
{
    pUVM->aCpus[i].pUVM   = pUVM;
    pUVM->aCpus[i].idCpu  = i;
}

// 分配 TLS entry 來儲存 VMINTUSERPERVMCPU pointer
int rc = RTTlsAllocEx(&pUVM->vm.s.idxTLS, NULL);
if (RT_SUCCESS(rc))
{
    // 為每個 halt 相關的 function 分配一個 event semaphore
    for (i = 0; i < cCpus; i++)
        pUVM->aCpus[i].vm.s.EventSemWait = NIL_RTSEMEVENT;
    for (i = 0; i < cCpus; i++)
        rc = RTSemEventCreate(&pUVM->aCpus[i].vm.s.EventSemWait);
    
    // critical section 初始化
    rc = RTCritSectInit(&pUVM->vm.s.AtStateCritSect);
    rc = RTCritSectInit(&pUVM->vm.s.AtErrorCritSect);
    rc = PDMR3InitUVM(pUVM); // 初始化 UVM in PDM
    rc = STAMR3InitUVM(pUVM); // 初始化 UVM in STAM
    rc = MMR3InitUVM(pUVM); // 初始化 UVM in MM
    for (i = 0; i < cCpus; i++)
    {
        // 每個 vcpu 開始執行 EMT
        rc = RTThreadCreateF(&pUVM->aCpus[i].vm.s.ThreadEMT, vmR3EmulationThread, &pUVM->aCpus[i], _1M, RTTHREADTYPE_EMULATION, RTTHREADFLAGS_WAITABLE | RTTHREADFLAGS_COM_MTA, cCpus > 1 ? "EMT-%u" : "EMT", i);
        pUVM->aCpus[i].vm.s.NativeThreadEMT = RTThreadGetNative(pUVM->aCpus[i].vm.s.ThreadEMT);
    }

    if (RT_SUCCESS(rc))
    {
        *ppUVM = pUVM;
        return VINF_SUCCESS;
    }

    // 如果上方任一個地方失敗，會執行下面的 function 來釋放資源
    MMR3TermUVM(pUVM);
    STAMR3TermUVM(pUVM);
    PDMR3TermUVM(pUVM);
    RTCritSectDelete(&pUVM->vm.s.AtErrorCritSect);
    RTCritSectDelete(&pUVM->vm.s.AtStateCritSect);
    for (i = 0; i < cCpus; i++)
    {
        RTSemEventDestroy(pUVM->aCpus[i].vm.s.EventSemWait);
        pUVM->aCpus[i].vm.s.EventSemWait = NIL_RTSEMEVENT;
    }
    RTTlsFree(pUVM->vm.s.idxTLS);
}
RTMemPageFree(pUVM, RT_UOFFSETOF_DYN(UVM, aCpus[pUVM->cCpus]));
return rc;
```

- VMINTUSERPERVMCPU - VMCPU internal data kept in the UVM
- `PDMR3InitUVM()` - Initializes the PDM part of the UVM
- `MMR3InitUVM()` - Initializes the MM members of the UVM
- `vmR3EmulationThread()` - The emulation thread main function
- 以 VCPU 來 schedule Guest OS

---

`vmR3CreateU()` - Creates and initializes the VM

```c
// 需要支援 SSE2
if (!(ASMCpuId_EDX(1) & X86_CPUID_FEATURE_EDX_SSE2))
{
    LogRel(("vboxdrv: Requires SSE2 (cpuid(0).EDX=%#x)\n", ASMCpuId_EDX(1)));
    return VERR_UNSUPPORTED_CPU;
}

// 載入 VMMR0.r0 module 這樣才能呼叫 GVMMR0CreateVM() 以及 ioctl
int rc = PDMR3LdrLoadVMMR0U(pUVM);
if (RT_FAILURE(rc))
{
    if (rc == VERR_VMX_IN_VMX_ROOT_MODE)
        return rc;
    return vmR3SetErrorU(pUVM, rc, RT_SRC_POS, N_("Failed to load VMMR0.r0"));
}

// 向 GVMM 請求一個 VM instance
GVMMCREATEVMREQ CreateVMReq;
CreateVMReq.Hdr.u32Magic    = SUPVMMR0REQHDR_MAGIC;
CreateVMReq.Hdr.cbReq       = sizeof(CreateVMReq);
CreateVMReq.pSession        = pUVM->vm.s.pSession;
CreateVMReq.pVMR0           = NIL_RTR0PTR;
CreateVMReq.pVMR3           = NULL;
CreateVMReq.cCpus           = cCpus;
// VMMR0_DO_GVMM_CREATE_VM: Ask the GVMM to create a new VM
rc = SUPR3CallVMMR0Ex(NIL_RTR0PTR, NIL_VMCPUID, VMMR0_DO_GVMM_CREATE_VM, 0, &CreateVMReq.Hdr);
if (RT_SUCCESS(rc))
{
    PVM pVM = pUVM->pVM = CreateVMReq.pVMR3;

    // 初始化 VM struct 以及 internal data (VMINT)
    pVM->pUVM = pUVM;

    for (VMCPUID i = 0; i < pVM->cCpus; i++)
    {
        PVMCPU pVCpu = pVM->apCpusR3[i];
        pVCpu->pUVCpu            = &pUVM->aCpus[i];
        pVCpu->idCpu             = i;
        pVCpu->hNativeThread     = pUVM->aCpus[i].vm.s.NativeThreadEMT;
        // hNativeThreadR0 在註冊 EMT 時就已經初始化
        Assert(pVCpu->hNativeThread != NIL_RTNATIVETHREAD);
        pUVM->aCpus[i].pVCpu     = pVCpu;
        pUVM->aCpus[i].pVM       = pVM;
    }

    // 初始化設置
    rc = CFGMR3Init(pVM, pfnCFGMConstructor, pvUserCFGM);
    // 基本設置，如多少個 CPU、VM 的名字
    rc = vmR3ReadBaseConfig(pVM, pUVM, cCpus);
    // 初始化 r3 的 component 以及 r3 per cpu data
    rc = vmR3InitRing3(pVM, pUVM);
    // 初始化 r0 的 component (GVMMR0)
    rc = vmR3InitRing0(pVM);
    // 因為一些 switcher 在 r0 初始化時會更新，所以需要 relocate
    VMR3Relocate(pVM, 0 /* offDelta */);

    // 可以將 VM 的 halt method 設為 default method
    // 此時 VM 為 hlt 狀態，並且尚未開機
    rc = vmR3SetHaltMethodU(pUVM, VMHALTMETHOD_DEFAULT);
    // 將狀態設置為建立完畢
    vmR3SetState(pVM, VMSTATE_CREATED, VMSTATE_CREATING);
    return VINF_SUCCESS;
    ... // 一些 error handling
}
else
    vmR3SetErrorU(pUVM, rc, RT_SRC_POS, N_("VM creation failed (GVMM)"));
return rc;
```

- `PDMR3LdrLoadVMMR0U()` - Loads the VMMR0.r0 module early in the init process
- VMINT - VM internal data
- `CFGMR3Init()` - Constructs the configuration for the VM
  - CFGM - Configuration manager

---

`vmR3ReadBaseConfig()` - Reads the base configuation from CFGM

```c
int rc;
PCFGMNODE pRoot = CFGMR3GetRoot(pVM); // 取得指向 root node 的 ptr 

// Hardware VM support 已經開啟 (enable) 並且可以使用 (available)
pVM->fHMEnabled = true;
// 確定 CPU conut 跟 config 相同
uint32_t cCPUsCfg;
rc = CFGMR3QueryU32Def(pRoot, "NumCPUs", &cCPUsCfg, 1);
// 取得 CPU 的執行權限
rc = CFGMR3QueryU32Def(pRoot, "CpuExecutionCap", &pVM->uCpuExecutionCap, 100);
// 取的 VM 名字以及 UUID
rc = CFGMR3QueryStringAllocDef(pRoot, "Name", &pUVM->vm.s.pszName, "<unknown>");
rc = CFGMR3QueryBytes(pRoot, "UUID", &pUVM->vm.s.Uuid, sizeof(pUVM->vm.s.Uuid));
// 取得開機資訊
rc = CFGMR3QueryBoolDef(pRoot, "PowerOffInsteadOfReset", &pVM->vm.s.fPowerOffInsteadOfReset, false);
return VINF_SUCCESS;
```

- `PCFGMNODE` - Configuration manager tree node

---

`VMR3Relocate()` - Calls the relocation functions for all VMM components so they can update any GC pointers

```c
// 順序不能調整，並且會影響執行結果
PGMR3Relocate(pVM, offDelta);
PDMR3LdrRelocateU(pVM->pUVM, offDelta);
PGMR3Relocate(pVM, 0); // Repeat after PDM relocation
CPUMR3Relocate(pVM);
HMR3Relocate(pVM);
SELMR3Relocate(pVM);
VMMR3Relocate(pVM, offDelta);
SELMR3Relocate(pVM);
TRPMR3Relocate(pVM, offDelta);
IOMR3Relocate(pVM, offDelta);
EMR3Relocate(pVM);
TMR3Relocate(pVM, offDelta);
IEMR3Relocate(pVM);
DBGFR3Relocate(pVM, offDelta);
PDMR3Relocate(pVM, offDelta);
GIMR3Relocate(pVM, offDelta);
```

- 通知每個 manager 都做一次 gc (garbage collection)

---

`vmR3InitRing0()` - Initializes all R0 components of the VM

```c
// FAKE suplib mode 會有對應的環境變數
int rc = VINF_SUCCESS;
const char *psz = RTEnvGet("VBOX_SUPLIB_FAKE");
if (!psz || strcmp(psz, "fake"))
    // 呼叫 VMMR0 component 來初始化
    rc = VMMR3InitR0(pVM);
else
    Log(("vmR3InitRing0: skipping because of VBOX_SUPLIB_FAKE=fake\n"));

// 通知並返回
if (RT_SUCCESS(rc))
    rc = vmR3InitDoCompleted(pVM, VMINITCOMPLETED_RING0);
if (RT_SUCCESS(rc))
    rc = vmR3InitDoCompleted(pVM, VMINITCOMPLETED_HM);

return rc;
```

- `vmR3InitDoCompleted()` - Do init completed notifications

---

`VMR3PowerOn()` - Powers on the virtual machine，開機的 function ?

```c
PVM pVM = pUVM->pVM;
// 聚集所有 EMT 減少 init TSC drift (?)
// 呼叫 worker function vmR3PowerOn()
int rc = VMMR3EmtRendezvous(pVM, VMMEMTRENDEZVOUS_FLAGS_TYPE_DESCENDING | VMMEMTRENDEZVOUS_FLAGS_STOP_ON_ERROR, vmR3PowerOn, NULL);
return rc;
```

---

`vmR3PowerOn() `- EMT rendezvous worker for VMR3PowerOn，開機

```c
if (pVCpu->idCpu == pVM->cCpus - 1) // 若為第一個 EMT
{
    // 嘗試將狀態轉為 VMSTATE_POWERING_ON，代表正在啟動中
    int rc = vmR3TrySetState(pVM, "VMR3PowerOn", 1, VMSTATE_POWERING_ON, VMSTATE_CREATED);
    // failed 就不再處理
    if (RT_FAILURE(rc))
        return rc;
}

VMSTATE enmVMState = VMR3GetState(pVM); // 取得 state 並在後續做一些 assertion
// 將所有 EMT 的狀態都設成 started
VMCPU_SET_STATE(pVCpu, VMCPUSTATE_STARTED);

// 如果 EMT(0) 為最後一個到這，會發出通知給 device 以及 driver，即將要轉為運行
if (pVCpu->idCpu == 0)
{
    // 確實開機並將狀態轉為運行
    PDMR3PowerOn(pVM);
    vmR3SetState(pVM, VMSTATE_RUNNING, VMSTATE_POWERING_ON);
}

return VINF_SUCCESS;
```

- `vmR3TrySetState()` - Tries to perform a state transition
- EMT 對應到一個 CPU，index 記錄在 `pvCpu->idCpu`
- `PDMR3PowerOn()` - This function will notify all the devices and their attached drivers about the VM now being powered on

---

`VMR3Suspend()` - Suspends a running VM

```c
// 確保在改變 VM 狀態前不會有 race 發生
int rc = VMMR3EmtRendezvous(pUVM->pVM, VMMEMTRENDEZVOUS_FLAGS_TYPE_DESCENDING | VMMEMTRENDEZVOUS_FLAGS_STOP_ON_ERROR,
                            vmR3Suspend, (void *)(uintptr_t)enmReason);
return rc;
```

- 為了確保不會發生 race，VM 會呼叫 rendezvous worker 去執行實際在做 suspend / poweron 等等 function

---

`vmR3Suspend()` - EMT rendezvous worker for VMR3Suspend

```c
VMSUSPENDREASON enmReason = (VMSUSPENDREASON)(uintptr_t)pvUser;
// first EMT 來轉換狀態成 suspending，如果 failed 代表有 racing，就不繼續呼叫
if (pVCpu->idCpu == pVM->cCpus - 1)
{
    int rc = vmR3TrySetState(pVM, "VMR3Suspend", 2,
                                VMSTATE_SUSPENDING,        VMSTATE_RUNNING,
                                VMSTATE_SUSPENDING_EXT_LS, VMSTATE_RUNNING_LS);
    if (RT_FAILURE(rc))
        return rc;
    pVM->pUVM->vm.s.enmSuspendReason = enmReason;
}

VMSTATE enmVMState = VMR3GetState(pVM);

// EMT(0) 在其他 CPU 都結束後，到此才會真正的 suspending
if (pVCpu->idCpu == 0)
{
    vmR3SuspendDoWork(pVM); // suspend notification
    int rc = vmR3TrySetState(pVM, "VMR3Suspend", 2,
                                VMSTATE_SUSPENDED,        VMSTATE_SUSPENDING,
                                VMSTATE_SUSPENDED_EXT_LS, VMSTATE_SUSPENDING_EXT_LS);
    if (RT_FAILURE(rc))
        return VERR_VM_UNEXPECTED_UNSTABLE_STATE;
}

return VINF_EM_SUSPEND;
```

- XXX_LS - LS 代表 Live save

---

`VMR3Resume()` - Resume VM execution，行為與 suspend / poweron 都相同

```c
PVM pVM = pUVM->pVM;

int rc = VMMR3EmtRendezvous(pVM, VMMEMTRENDEZVOUS_FLAGS_TYPE_DESCENDING | VMMEMTRENDEZVOUS_FLAGS_STOP_ON_ERROR, vmR3Resume, (void *)(uintptr_t)enmReason);
return rc;
```

- `vmR3Resume()` 為 worker function

---

`VMR3Save()` - Save current VM state，用來單純保存狀態，或是在做 snapshot 時也會使用到

```c
*pfSuspended = false;
PVM pVM = pUVM->pVM;

// 與 VMR3Teleport() 的 path 做 concat
SSMAFTER enmAfter = fContinueAfterwards ? SSMAFTER_CONTINUE : SSMAFTER_DESTROY;
int rc = vmR3SaveTeleport(pVM, 250 /*cMsMaxDowntime*/, pszFilename, NULL /* pStreamOps */, NULL /* pvStreamOpsUser */,enmAfter, pfnProgress, pvUser, pfSuspended);
return rc;
```

---

`vmR3SaveTeleport()` - Common worker for VMR3Save and VMR3Teleport

```c
// 發送請求給 EMT(0)
PSSMHANDLE pSSM;
// 呼叫 vmR3Save 來保存狀態
int rc = VMR3ReqCallWait(pVM, 0 /*idDstCpu*/, (PFNRT)vmR3Save, 9, pVM, cMsMaxDowntime, pszFilename, pStreamOps, pvStreamOpsUser, enmAfter, pfnProgress, pvProgressUser, &pSSM);
if (RT_SUCCESS(rc) && pSSM)
{
    // 做 live snapshow step1，需要一些時間，官方建議看 VMSTATE diagram for details
    rc = SSMR3LiveDoStep1(pSSM);
    if (RT_SUCCESS(rc))
    {
        if (VMR3GetState(pVM) != VMSTATE_SAVING)
            for (;;)
            {
                // 嘗試在 step1 後，用 vmR3LiveDoSuspend() 來 suspend VM
                rc = VMMR3EmtRendezvous(pVM, VMMEMTRENDEZVOUS_FLAGS_TYPE_DESCENDING | VMMEMTRENDEZVOUS_FLAGS_STOP_ON_ERROR, vmR3LiveDoSuspend, pfSuspended);
                if (rc != VERR_TRY_AGAIN) // 如果不需要在嘗試一次，就跳出回圈
                    break;

                // sleep()，state 改變可能會需要一些時間
                RTThreadSleep(250);
            }
        if (RT_SUCCESS(rc))
            // do vmR3LiveDoStep2()
            rc = VMR3ReqCallWait(pVM, 0 /*idDstCpu*/, (PFNRT)vmR3LiveDoStep2, 2, pVM, pSSM);
        else
            // 關閉 SSM handle，清除狀態
            int rc2 = VMR3ReqCallWait(pVM, 0 /*idDstCpu*/, (PFNRT)SSMR3LiveDone, 1, pSSM);
    }
    else
    {
        // 關閉 SSM handle，清除狀態
        int rc2 = VMR3ReqCallWait(pVM, 0 /*idDstCpu*/, (PFNRT)SSMR3LiveDone, 1, pSSM);
        // 透過 vmR3LiveDoStep1Cleanup() 清除資源
        rc2 = VMMR3EmtRendezvous(pVM, VMMEMTRENDEZVOUS_FLAGS_TYPE_ONCE, vmR3LiveDoStep1Cleanup, pfSuspended);
        if (RT_FAILURE(rc2) && rc == VERR_SSM_CANCELLED)
            rc = rc2;
    }
}

return rc;
```

- `vmR3Save()` - Worker for vmR3SaveTeleport that validates the state and calls SSMR3Save or SSMR3LiveSave
- 都正常的情況下： `SSMR3LiveDoStep1()` --> `vmR3LiveDoSuspend()` --> `vmR3LiveDoStep2()`
  - `vmR3LiveDoStep2()` 內包含 `SSMR3LiveDoStep2()` 以及 `SSMR3LiveDone()`
- SSM - Saved State Manager

---

`SSMR3LiveDoStep1()` - Continue a live state saving operation on the worker thread

```c
PVM pVM = pSSM->pVM;

// prepare work
int rc = ssmR3DoLivePrepRun(pVM, pSSM);
if (RT_SUCCESS(rc))
    rc = ssmR3DoLiveExecVoteLoop(pVM, pSSM); // 進入 exec+vote cycle
return rc;
```

---

`vmR3LiveDoSuspend()` - EMT rendezvous worker for VMR3Save and VMR3Teleport that suspends the VM after the live step has been completed，根據 VM 當前狀態不同呼叫不同的 function

---

`vmR3LiveDoStep2()` - EMT(0) worker for VMR3Save and VMR3Teleport that completes the live save

```c
int rc = VINF_SUCCESS;
VMSTATE enmVMState = VMR3GetState(pVM);
// VM 等待 live save operation
if (enmVMState == VMSTATE_SUSPENDED_LS)
    // 設為正在保存
    vmR3SetState(pVM, VMSTATE_SAVING, VMSTATE_SUSPENDED_LS);
else
{
    // 更新狀態成正在保存
    if (enmVMState != VMSTATE_SAVING)
        vmR3SetState(pVM, VMSTATE_SAVING, VMSTATE_SUSPENDED_EXT_LS);
    rc = VINF_SSM_LIVE_SUSPENDED;
}

// 保存 EMT0 剩餘的狀態
int rc2 = SSMR3LiveDoStep2(pSSM);
if (rc == VINF_SUCCESS || (RT_FAILURE(rc2) && RT_SUCCESS(rc)))
    rc = rc2;

// 做一些 assertion 與資料保存，確定是否真的結束
rc2 = SSMR3LiveDone(pSSM);
if (rc == VINF_SUCCESS || (RT_FAILURE(rc2) && RT_SUCCESS(rc)))
    rc = rc2;

// 變成 suspend 狀態
vmR3SetState(pVM, VMSTATE_SUSPENDED, VMSTATE_SAVING);
return rc;
```

---

> 在先前介紹 `vmmR0EntryExWorker()` 內不同 `enmOperation` 的不同 handler 時，只介紹了一些相較常見的 operation，在此補充其他沒有說明到的 function，並且這部分也是 R0 透過 IOCTL 的方式提供一些 interface 给 R3 的 VM manager 使用。



VMMR0_DO_GVMM_CREATE_VM - `GVMMR0CreateVMReq()` - Request wrapper for the GVMMR0CreateVM API，創建一個 VM，其實就是建立一個 VM 的 global variable 和**第一個 EMT**。

```c
PGVM pGVM;
pReq->pVMR0 = NULL;
pReq->pVMR3 = NIL_RTR3PTR;
int rc = GVMMR0CreateVM(pSession, pReq->cCpus, &pGVM);
if (RT_SUCCESS(rc))
{
    // 如果成功，VMR0 為 pGVM (global (r0) VM)
    pReq->pVMR0 = pGVM; // 這個不能 expose 給 R3
    pReq->pVMR3 = pGVM->pVMR3;
}
return rc;
```



`GVMMR0CreateVM()` - Allocates the VM structure and registers it with GVM

```c
PGVMM pGVMM;
*ppGVM = NULL;

// 整個分配的過程會用 lock 保護
int rc = gvmmR0CreateDestroyLock(pGVMM);
if (SUPR0GetSessionVM(pSession) != NULL)
    return VERR_ALREADY_EXISTS;

// 先處理 handle，避免浪費資源
uint16_t iHandle = pGVMM->iFreeHead; // 取得 free handle chain
if (iHandle)
{
    PGVMHANDLE pHandle = &pGVMM->aHandles[iHandle];

    // 註冊 VM object，關閉時會呼叫 gvmmR0HandleObjDestructor() 釋放資源
    pHandle->pvObj = SUPR0ObjRegister(pSession, SUPDRVOBJTYPE_VM, gvmmR0HandleObjDestructor, pGVMM, pHandle);

    // 將 handle 從 free list 放到 used list
    rc = GVMMR0_USED_EXCLUSIVE_LOCK(pGVMM);
    pGVMM->iFreeHead = pHandle->iNext;
    pHandle->iNext = pGVMM->iUsedHead;
    pGVMM->iUsedHead = iHandle;
    pGVMM->cVMs++;
    pHandle->pGVM     = NULL;
    pHandle->pSession = pSession;
    pHandle->hEMT0    = NIL_RTNATIVETHREAD;
    pHandle->ProcId   = NIL_RTPROCESS;
    GVMMR0_USED_EXCLUSIVE_UNLOCK(pGVMM);

    // 確保可以存取
    rc = SUPR0ObjVerifyAccess(pHandle->pvObj, pSession, NULL);

    // 為 VM+GVM struct 分配記憶體
    const uint32_t  cbVM      = RT_UOFFSETOF_DYN(GVM, aCpus[cCpus]);
    const uint32_t  cPages    = RT_ALIGN_32(cbVM, PAGE_SIZE) >> PAGE_SHIFT;
    RTR0MEMOBJ      hVMMemObj = NIL_RTR0MEMOBJ;
    rc = RTR0MemObjAllocPage(&hVMMemObj, cPages << PAGE_SHIFT, false);
    PGVM pGVM = (PGVM)RTR0MemObjAddress(hVMMemObj);
    
    // 初始化 pGVM struct
    RT_BZERO(pGVM, cPages << PAGE_SHIFT);
    gvmmR0InitPerVMData(pGVM, iHandle, cCpus, pSession);
    pGVM->gvmm.s.VMMemObj  = hVMMemObj;
    rc = GMMR0InitPerVMData(pGVM);
    int rc2 = PGMR0InitPerVMData(pGVM);
    PDMR0InitPerVMData(pGVM);
    IOMR0InitPerVMData(pGVM);
    
    // 分配 page array，目前可以讓 r3 存取，但在最後會把權限收回來
    rc = RTR0MemObjAllocPage(&pGVM->gvmm.s.VMPagesMemObj, cPages * sizeof(SUPPAGE), false);
    PSUPPAGE paPages = (PSUPPAGE)RTR0MemObjAddress(pGVM->gvmm.s.VMPagesMemObj); AssertPtr(paPages);
    for (uint32_t iPage = 0; iPage < cPages; iPage++)
    {
        paPages[iPage].uReserved = 0;
        paPages[iPage].Phys = RTR0MemObjGetPagePhysAddr(pGVM->gvmm.s.VMMemObj, iPage);
    }
	
    // 將 page array, VM, VMCPU 結構 mapping 到 r3
    // VM mapping
    rc = RTR0MemObjMapUserEx(&pGVM->gvmm.s.VMMapObj, pGVM->gvmm.s.VMMemObj, (RTR3PTR)-1, 0, RTMEM_PROT_READ | RTMEM_PROT_WRITE, NIL_RTR0PROCESS, 0, sizeof(VM));
    
    // VMCPU mapping
    for (VMCPUID i = 0; i < cCpus && RT_SUCCESS(rc); i++)
        rc = RTR0MemObjMapUserEx(&pGVM->aCpus[i].gvmm.s.VMCpuMapObj, pGVM->gvmm.s.VMMemObj, (RTR3PTR)-1, 0, RTMEM_PROT_READ | RTMEM_PROT_WRITE, NIL_RTR0PROCESS, RT_UOFFSETOF_DYN(GVM, aCpus[i]), sizeof(VMCPU));
    
    // page mapping
    rc = RTR0MemObjMapUser(&pGVM->gvmm.s.VMPagesMapObj, pGVM->gvmm.s.VMPagesMemObj, (RTR3PTR)-1, 0, RTMEM_PROT_READ | RTMEM_PROT_WRITE, NIL_RTR0PROCESS);
    
    // 初始化所有的 VM pointer
    PVMR3 pVMR3 = RTR0MemObjAddressR3(pGVM->gvmm.s.VMMapObj);
    for (VMCPUID i = 0; i < cCpus; i++)
    {
        pGVM->aCpus[i].pVMR0 = pGVM;
        pGVM->aCpus[i].pVMR3 = pVMR3;
        pGVM->apCpusR3[i] = RTR0MemObjAddressR3(pGVM->aCpus[i].gvmm.s.VMCpuMapObj);
        pGVM->aCpus[i].pVCpuR3 = pGVM->apCpusR3[i];
        pGVM->apCpusR0[i] = &pGVM->aCpus[i];
    }
    pGVM->paVMPagesR3 = RTR0MemObjAddressR3(pGVM->gvmm.s.VMPagesMapObj);

    // 完成 handle
    rc = GVMMR0_USED_EXCLUSIVE_LOCK(pGVMM);

    pHandle->pGVM                   = pGVM;
    pHandle->hEMT0                  = hEMT0;
    pHandle->ProcId                 = ProcId;
    pGVM->pVMR3                     = pVMR3;
    pGVM->pVMR3Unsafe               = pVMR3;
    pGVM->aCpus[0].hEMT             = hEMT0;
    pGVM->aCpus[0].hNativeThreadR0  = hEMT0;
    pGVMM->cEMTs += cCpus;

    // 建立 context hook、或是與 session 相連
    rc = SUPR0SetSessionVM(pSession, pGVM, pGVM);
    // 建立第一個 EMT
    rc = VMMR0ThreadCtxHookCreateForEmt(&pGVM->aCpus[0]);
    
    // Done
    VBOXVMM_R0_GVMM_VM_CREATED(pGVM, pGVM, ProcId, (void *)hEMT0, cCpus);

    GVMMR0_USED_EXCLUSIVE_UNLOCK(pGVMM);
    gvmmR0CreateDestroyUnlock(pGVMM);

    // 註冊 VCPU
    CPUMR0RegisterVCpuThread(&pGVM->aCpus[0]);

    *ppGVM = pGVM;
    return VINF_SUCCESS;
}
... // error handling
gvmmR0CreateDestroyUnlock(pGVMM);
return rc;
```

---

VMMR0_DO_GVMM_DESTROY_VM - `GVMMR0DestroyVM()` - Destroys the VM, freeing all associated resources (the ring-0 ones anyway)，當關閉 VM 時會呼叫到 `gvmmR0HandleObjDestructor()`，因此在此 function 當中只會檢查所有 EMT 都 deregister 了

```c
PGVMM pGVMM;
... // 一開始會 Validate VM structure、state 以及 caller

uint32_t hGVM = pGVM->hSelf;
ASMCompilerBarrier();
PGVMHANDLE pHandle = &pGVMM->aHandles[hGVM];
RTPROCESS ProcId = RTProcSelf();
RTNATIVETHREAD  hSelf  = RTThreadNativeSelf();
... // 這邊省略了許多 assertion

// 取得 destroy lock
int rc = gvmmR0CreateDestroyLock(pGVMM);
if (... /* 因為這邊可能會出現 racing，因此放了許多檢查 */)
{
    // 檢查其他 EMT 是否已經 deregistered
    uint32_t cNotDeregistered = 0;
    for (VMCPUID idCpu = 1; idCpu < pGVM->cCpus; idCpu++)
        cNotDeregistered += pGVM->aCpus[idCpu].hEMT != ~(RTNATIVETHREAD)1;
    if (cNotDeregistered == 0)
    {
        void *pvObj = pHandle->pvObj;
        pHandle->pvObj = NULL;
        gvmmR0CreateDestroyUnlock(pGVMM);
        // unlock 後釋放 pvObj
        SUPR0ObjRelease(pvObj, pHandle->pSession);
    }
    else
    {
        gvmmR0CreateDestroyUnlock(pGVMM);
        rc = VERR_GVMM_NOT_ALL_EMTS_DEREGISTERED; // 還有沒 deregister 的
    }
}
else
{
    gvmmR0CreateDestroyUnlock(pGVMM);
    // Internal processing error #2 in the GVMM code
    rc = VERR_GVMM_IPE_2;
}

return rc;
```

`gvmmR0HandleObjDestructor()` - VM handle destructor

```c
// input validation
PGVMHANDLE pHandle = (PGVMHANDLE)pvUser2;
PGVMM pGVMM = (PGVMM)pvUser1;
const uint16_t iHandle = pHandle - &pGVMM->aHandles[0];
int rc = gvmmR0CreateDestroyLock(pGVMM);
rc = GVMMR0_USED_EXCLUSIVE_LOCK(pGVMM);

// 雖然有點慢，但是 double linked list 太麻煩
if (pGVMM->iUsedHead == iHandle)
    pGVMM->iUsedHead = pHandle->iNext;
else
{
    uint16_t iPrev = pGVMM->iUsedHead;
    int c = RT_ELEMENTS(pGVMM->aHandles) + 2;
    // 找 handle 的 prev of prev
    while (iPrev)
    {
        if (RT_UNLIKELY(c-- <= 0))
        {
            iPrev = 0;
            break;
        }

        if (pGVMM->aHandles[iPrev].iNext == iHandle)
            break;
        iPrev = pGVMM->aHandles[iPrev].iNext;
    }
    if (!iPrev)
    {
        SUPR0Printf("GVM: can't find the handle previous previous of %d!\n", pHandle->iSelf);
        ...
        return;
    }
    pGVMM->aHandles[iPrev].iNext = pHandle->iNext;
}
pHandle->iNext = 0;
pGVMM->cVMs--;

// global cleanup
PGVM pGVM = pHandle->pGVM;
if (RT_VALID_PTR(pGVM) && pGVM->u32Magic == GVM_MAGIC) // 確定還沒被釋放
{
    pGVMM->cEMTs -= pGVM->cCpus;
    if (pGVM->pSession)
        SUPR0SetSessionVM(pGVM->pSession, NULL, NULL);

    GVMMR0_USED_EXCLUSIVE_UNLOCK(pGVMM);
    // 釋放 VCPU 對應的 EMT
    gvmmR0CleanupVM(pGVM);

    // gvmm cleanup
    // 釋放 VM 以及 VM pages
    if (pGVM->gvmm.s.VMPagesMapObj != NIL_RTR0MEMOBJ)
    {
        rc = RTR0MemObjFree(pGVM->gvmm.s.VMPagesMapObj, false);
        pGVM->gvmm.s.VMPagesMapObj = NIL_RTR0MEMOBJ;
    }

    if (pGVM->gvmm.s.VMMapObj != NIL_RTR0MEMOBJ)
    {
        rc = RTR0MemObjFree(pGVM->gvmm.s.VMMapObj, false);
        pGVM->gvmm.s.VMMapObj = NIL_RTR0MEMOBJ;
    }

    if (pGVM->gvmm.s.VMPagesMemObj != NIL_RTR0MEMOBJ)
    {
        rc = RTR0MemObjFree(pGVM->gvmm.s.VMPagesMemObj, false);
        pGVM->gvmm.s.VMPagesMemObj = NIL_RTR0MEMOBJ;
    }

    for (VMCPUID i = 0; i < pGVM->cCpus; i++)
    {
        // release event semaphore
        if (pGVM->aCpus[i].gvmm.s.HaltEventMulti != NIL_RTSEMEVENTMULTI)
        {
            rc = RTSemEventMultiDestroy(pGVM->aCpus[i].gvmm.s.HaltEventMulti);
            pGVM->aCpus[i].gvmm.s.HaltEventMulti = NIL_RTSEMEVENTMULTI;
        }
        // release r3 VMCPU mapping
        if (pGVM->aCpus[i].gvmm.s.VMCpuMapObj != NIL_RTR0MEMOBJ)
        {
            rc = RTR0MemObjFree(pGVM->aCpus[i].gvmm.s.VMCpuMapObj, false);
            pGVM->aCpus[i].gvmm.s.VMCpuMapObj = NIL_RTR0MEMOBJ;
        }
    }

    // 釋放 GVM 自己
    pGVM->u32Magic |= UINT32_C(0x80000000);
    Assert(pGVM->gvmm.s.VMMemObj != NIL_RTR0MEMOBJ);
    rc = RTR0MemObjFree(pGVM->gvmm.s.VMMemObj, true);
    pGVM = NULL;

    // 在 free handle 之前重新要 usedlock
    rc = GVMMR0_USED_EXCLUSIVE_LOCK(pGVMM);
}

// 釋放 handle
pHandle->iNext = pGVMM->iFreeHead;
pGVMM->iFreeHead = iHandle;
ASMAtomicWriteNullPtr(&pHandle->pGVM);
ASMAtomicWriteNullPtr(&pHandle->pvObj);
ASMAtomicWriteNullPtr(&pHandle->pSession);
ASMAtomicWriteHandle(&pHandle->hEMT0, NIL_RTNATIVETHREAD);
ASMAtomicWriteU32(&pHandle->ProcId, NIL_RTPROCESS);

GVMMR0_USED_EXCLUSIVE_UNLOCK(pGVMM);
gvmmR0CreateDestroyUnlock(pGVMM);
```

- VMPagesMapObj - The **ring-3** mapping of the VM pages
- VMPagesMemObj - The allocation object for the VM pages
- VMMapObj - The **Ring-3** mapping of the shared VM data structure (PVMR3)
- VMMemObj - The shared VM data structure allocation object (PVMR0)
- VMCpuMapObj - The ring-3 mapping of the VMCPU structure
- HaltEventMulti - The event semaphore the EMT thread is blocking on

---

VMMR0_DO_GVMM_REGISTER_VMCPU - `GVMMR0RegisterVCpu()` - Registers the calling thread as the EMT of a Virtual CPU，綁定 VCPU 對應的 EMT (emulation thread)

```c
int rc = gvmmR0ByGVM(pGVM, &pGVMM, false);
if (RT_SUCCESS(rc))
{
    if (idCpu < pGVM->cCpus)
    {
        // 檢查是否 EMT 還沒被 assigned 到 thread 上
        if (pGVM->aCpus[idCpu].hEMT == NIL_RTNATIVETHREAD)
        {
            // 一個 thread 對到一個 EMT
            RTNATIVETHREAD const hNativeSelf = RTThreadNativeSelf();
            // assignment 自己到 VCPU 的 hNativeThreadR0
            pGVM->aCpus[idCpu].hNativeThreadR0 = pGVM->aCpus[idCpu].hEMT = RTThreadNativeSelf();
           	// 建立 R0 的 EMT
            rc = VMMR0ThreadCtxHookCreateForEmt(&pGVM->aCpus[idCpu]);
            if (RT_SUCCESS(rc))	
                // 成功的話，就向 CPUM 註冊此 thread
                CPUMR0RegisterVCpuThread(&pGVM->aCpus[idCpu]);
            else
                pGVM->aCpus[idCpu].hNativeThreadR0 = pGVM->aCpus[idCpu].hEMT = NIL_RTNATIVETHREAD; // 失敗就 undo
        }
        else
            rc = VERR_ACCESS_DENIED;
    }
    else
        rc = VERR_INVALID_CPU_ID;
}
return rc;
```

- hEMT - Handle to the EMT thread

- `VMMR0ThreadCtxHookCreateForEmt()` - Creates thread switching hook for the current EMT thread

- vbox 定義了幾個 VCPU 的狀態，當 VMM 進入和退出 guest 的時候都會修改相應的狀態

  ```c
  typedef enum VMCPUSTATE
  {
      /** The customary invalid zero. */
      VMCPUSTATE_INVALID = 0,
      /** Virtual CPU has not yet been started.  */
      VMCPUSTATE_STOPPED,
      /** CPU started. */
      VMCPUSTATE_STARTED,
      /** CPU started in HM context. */
      VMCPUSTATE_STARTED_HM,
      /** Executing guest code and can be poked (RC or STI bits of HM). */
      VMCPUSTATE_STARTED_EXEC,
      /** Executing guest code using NEM. */
      VMCPUSTATE_STARTED_EXEC_NEM,
      VMCPUSTATE_STARTED_EXEC_NEM_WAIT,
      VMCPUSTATE_STARTED_EXEC_NEM_CANCELED,
      /** Halted. */
      VMCPUSTATE_STARTED_HALTED,
      /** The end of valid virtual CPU states. */
      VMCPUSTATE_END,
      /** Ensure 32-bit type. */
      VMCPUSTATE_32BIT_HACK = 0x7fffffff
  } VMCPUSTATE;
  ```

  

  VMMR0_DO_GVMM_DEREGISTER_VMCPU - `GVMMR0DeregisterVCpu()` - Deregisters the calling thread as the EMT of a Virtual CPU

  ```c
  PGVMM pGVMM;
  int rc = gvmmR0ByGVMandEMT(pGVM, idCpu, &pGVMM);
  if (RT_SUCCESS(rc))
  {
      gvmmR0CreateDestroyLock(pGVMM);
      uint32_t hSelf = pGVM->hSelf;
      ASMCompilerBarrier();
      if (... /* 避免 racing 的檢查 */)
      {
          // 清除 R0 的 EMT
          VMMR0ThreadCtxHookDestroyForEmt(&pGVM->aCpus[idCpu]);
  
          // invalidate hEMT (handle to the EMT)
          pGVM->aCpus[idCpu].hEMT           = ~(RTNATIVETHREAD)1;
          pGVM->aCpus[idCpu].hNativeThreadR0 = NIL_RTNATIVETHREAD;
      }
  
      gvmmR0CreateDestroyUnlock(pGVMM);
  }
  return rc;
  ```

  - `gvmmR0ByGVMandEMT()` - 在多數 emuOperation handler 的開頭都會呼叫，用於檢查 GVM 與 VM 的資料是否 matching

---

VMMR0_DO_GVMM_SCHED_POKE - `GVMMR0SchedPoke()` - Pokes an EMT if it's still busy running guest code，查看一個 VCPU 是否在運行 GuestOS code，實際上為 wrapper of `GVMMR0SchedPokeEx()`

```c
return GVMMR0SchedPokeEx(pGVM, idCpu, true /* fTakeUsedLock */);
```

`GVMMR0SchedPokeEx()` - 為 `gvmmR0SchedPokeOne()` 的 wrapper

```c
PGVMM pGVMM;
if (idCpu < pGVM->cCpus)
    rc = gvmmR0SchedPokeOne(pGVM, &pGVM->aCpus[idCpu]);
else
    rc = VERR_INVALID_CPU_ID;

if (fTakeUsedLock)
    int rc2 = GVMMR0_USED_SHARED_UNLOCK(pGVMM);
return rc;
```

`gvmmR0SchedPokeOne()` - Worker common to `GVMMR0SchedPoke()` and `GVMMR0SchedWakeUpAndPokeCpus()` that pokes the Virtual CPU if it's still busy executing guest code

```c
pGVM->gvmm.s.StatsSched.cPokeCalls++; // counter++

RTCPUID idHostCpu = pVCpu->idHostCpu; // 取得 VCPU 對應到的 host CPU id
// 如果沒有對應的 cpuid  || 當前 state 並非 VMCPUSTATE_STARTED_EXEC
if (idHostCpu == NIL_RTCPUID | VMCPU_GET_STATE(pVCpu) != VMCPUSTATE_STARTED_EXEC)
{
    pGVM->gvmm.s.StatsSched.cPokeNotBusy++; // counter++
    return VINF_GVM_NOT_BUSY_IN_GC; // EMT 沒在跑 guest code
}

// VCPU 在跑 guest code
RTMpPokeCpu(idHostCpu);
return VINF_SUCCESS;
```

- 原來 GC 是 guest code 的縮寫



VMMR0_DO_GVMM_SCHED_POLL - `GVMMR0SchedPoll()` - Poll the schedule to see if someone else should get a chance to run

```c
// 目前只支援 wakeups (fYield = false)
// fYielf == Whether to yield or not
if (!fYield && pGVMM->fDoEarlyWakeUps)
{
    rc = GVMMR0_USED_SHARED_LOCK(pGVMM);
    pGVM->gvmm.s.StatsSched.cPollCalls++; /// counter++

    const uint64_t u64Now = RTTimeNanoTS(); /* (GIP time) */

    pGVM->gvmm.s.StatsSched.cPollWakeUps += gvmmR0SchedDoWakeUps(pGVMM, u64Now);
    GVMMR0_USED_SHARED_UNLOCK(pGVMM);
}
else if (fYield)
    rc = VERR_NOT_IMPLEMENTED;
else
    rc = VINF_SUCCESS;
return rc;
```

`gvmmR0SchedDoWakeUps() ` - This is will wake up expired and soon-to-be expired VMs

```c
if (!ASMAtomicCmpXchgBool(&pGVMM->fDoingEarlyWakeUps, true, false))
    return 0;

// 第一輪會 wakeup expired VM (expired time <= 當前時間)
// 第二輪 <= uNsEarlyWakeUp2
// 第三輪 <= uNsEarlyWakeUp3
const uint64_t  uNsEarlyWakeUp2 = u64Now + pGVMM->nsEarlyWakeUp2;
const uint64_t  uNsEarlyWakeUp1 = u64Now + pGVMM->nsEarlyWakeUp1;
uint64_t        u64Min          = UINT64_MAX;
unsigned        cWoken          = 0;
unsigned        cHalted         = 0;
unsigned        cTodo2nd        = 0;
unsigned        cTodo3rd        = 0;

for (unsigned i = pGVMM->iUsedHead, cGuard = 0; i != NIL_GVM_HANDLE && i < RT_ELEMENTS(pGVMM->aHandles); i = pGVMM->aHandles[i].iNext)
{
    PGVM pCurGVM = pGVMM->aHandles[i].pGVM;
    if (RT_VALID_PTR(pCurGVM) && pCurGVM->u32Magic == GVM_MAGIC)
    {
        // traverse 每個 CPU id
        for (VMCPUID idCpu = 0; idCpu < pCurGVM->cCpus; idCpu++)
        {
            PGVMCPU  pCurGVCpu = &pCurGVM->aCpus[idCpu]; // 取出對應的 VCPU
            uint64_t u64 = ASMAtomicUoReadU64(&pCurGVCpu->gvmm.s.u64HaltExpire);
            if (u64) // expired time existed
            {
                if (u64 <= u64Now) // expired time <= now，代表過期
                {
                    if (ASMAtomicXchgU64(&pCurGVCpu->gvmm.s.u64HaltExpire, 0))
                    {
                        // trigger event
                        int rc = RTSemEventMultiSignal(pCurGVCpu->gvmm.s.HaltEventMulti);
                        cWoken++;
                    }
                }
                else
                {
                    cHalted++;
                    if (u64 <= uNsEarlyWakeUp1)
                        cTodo2nd++; // 在 round2 可能需要 wakeup
                    else if (u64 <= uNsEarlyWakeUp2)
                        cTodo3rd++; // 在 round3 可能需要 wakeup
                    else if (u64 < u64Min)
                        u64 = u64Min;
                }
            }
        }
    }
}

... // round2, round3
pGVMM->uNsNextEmtWakeup = u64Min; // 更新下次 wakeup time

ASMAtomicWriteBool(&pGVMM->fDoingEarlyWakeUps, false);
return cWoken;
```

---

VMMR0_DO_GVMM_SCHED_HALT - `GVMMR0SchedHaltReq()` - Halt the EMT thread，暫停一個 EMT

```c
PGVMM pGVMM;
rc = GVMMR0SchedHalt(pGVM, &pGVM->aCpus[idCpu], u64ExpireGipTime);
return rc;
```

`GVMMR0SchedHalt()` - Halt the EMT thread

```c
PGVMM pGVMM;
pGVM->gvmm.s.StatsSched.cHaltCalls++; // counter++

// 如果在執行 early wakeup，就需要在 query 當前時間前用 UsedList lock
// 並且目前需要 interruptable，因為需要 GIP time
bool const fDoEarlyWakeUps = pGVMM->fDoEarlyWakeUps;
if (fDoEarlyWakeUps)
{
    int rc2 = GVMMR0_USED_SHARED_LOCK(pGVMM); AssertRC(rc2);
    GVMM_CHECK_SMAP_CHECK2(pGVM, RT_NOTHING);
}

pGVCpu->gvmm.s.iCpuEmt = ASMGetApicId();

// 因為 GIP 和 system 的差在 high resolution system time 的 system 很重要，因此在此階段可能會頻繁的 sleep 一小段時間，最後把 GIP 轉成系統時間
Assert(ASMGetFlags() & X86_EFL_IF);
const uint64_t u64NowSys = RTTimeSystemNanoTS(); // 取得 system time
const uint64_t u64NowGip = RTTimeNanoTS(); // 取得 GIP

if (fDoEarlyWakeUps) 
    // early wakeup 代表先 wakeup
    pGVM->gvmm.s.StatsSched.cHaltWakeUps += gvmmR0SchedDoWakeUps(pGVMM, u64NowGip);

// 看看需不需要 sleep，最久 1 秒
int rc;
uint64_t cNsInterval = u64ExpireGipTime - u64NowGip;
if (    u64NowGip < u64ExpireGipTime
    &&  cNsInterval >= (pGVMM->cEMTs > pGVMM->cEMTsMeansCompany
                        ? pGVMM->nsMinSleepCompany
                        : pGVMM->nsMinSleepAlone))
{
    pGVM->gvmm.s.StatsSched.cHaltBlocking++;
    if (cNsInterval > RT_NS_1SEC)
        u64ExpireGipTime = u64NowGip + RT_NS_1SEC;
    ASMAtomicWriteU64(&pGVCpu->gvmm.s.u64HaltExpire, u64ExpireGipTime);
    ASMAtomicIncU32(&pGVMM->cHaltedEMTs);
    if (fDoEarlyWakeUps)
    {
        if (u64ExpireGipTime < pGVMM->uNsNextEmtWakeup)
            pGVMM->uNsNextEmtWakeup = u64ExpireGipTime;
        GVMMR0_USED_SHARED_UNLOCK(pGVMM);
    }

    // wait for event with timeout
    rc = RTSemEventMultiWaitEx(pGVCpu->gvmm.s.HaltEventMulti, RTSEMWAIT_FLAGS_ABSOLUTE | RTSEMWAIT_FLAGS_NANOSECS | RTSEMWAIT_FLAGS_INTERRUPTIBLE, u64NowGip > u64NowSys ? u64ExpireGipTime : u64NowSys + cNsInterval);

    ASMAtomicWriteU64(&pGVCpu->gvmm.s.u64HaltExpire, 0);
    ASMAtomicDecU32(&pGVMM->cHaltedEMTs);

    // reset event semaphore 避免不小心 wakeup
    if (rc == VINF_SUCCESS)
        RTSemEventMultiReset(pGVCpu->gvmm.s.HaltEventMulti);
    else if (rc == VERR_TIMEOUT)
    {
        pGVM->gvmm.s.StatsSched.cHaltTimeouts++; // counter++
        rc = VINF_SUCCESS;
    }
}
else
{
    pGVM->gvmm.s.StatsSched.cHaltNotBlocking++;
    if (fDoEarlyWakeUps)
        GVMMR0_USED_SHARED_UNLOCK(pGVMM);
    // reset event semaphore
    RTSemEventMultiReset(pGVCpu->gvmm.s.HaltEventMulti);
    rc = VINF_SUCCESS;
}

return rc;
```

---

Emulation Thread (EMT) - VM 創建的時候，會給每一個 VCPU 創建一個 Emulation Thread，負責執行GuestOS，for loop 到 VM 退出。

`vmR3EmulationThreadWithId()` - The **emulation thread main function**, with Virtual CPU ID for debugging

```c
PUVM    pUVM = pUVCpu->pUVM;
int     rc;

rc = RTTlsSet(pUVM->vm.s.idxTLS, pUVCpu);

if (pUVM->pVmm2UserMethods && pUVM->pVmm2UserMethods->pfnNotifyEmtInit)
    pUVM->pVmm2UserMethods->pfnNotifyEmtInit(pUVM->pVmm2UserMethods, pUVM, pUVCpu);

rc = VINF_SUCCESS;
ASMAtomicIncU32(&pUVM->vm.s.cActiveEmts);
// request loop
for (;;)
{
    // 在一開始 init 時可能沒有 pVM 或 pVCpu，因此需要額外用一個 if-else case 去 handle
    PVM    pVM   = pUVM->pVM;
    PVMCPU pVCpu = pUVCpu->pVCpu;
    if (!pVCpu || !pVM)
    {
        // 檢查 EMT 是否需要退出 (terminate)
        if (pUVM->vm.s.fTerminateEMT)
        {
            rc = VINF_EM_TERMINATE;
            break;
        }

        // 只有第一個 VCPU 被初始化，因此需要 handle 所有 VMCPUID_ANY type 的 request
        if ((pUVM->vm.s.pNormalReqs || pUVM->vm.s.pPriorityReqs) &&  pUVCpu->idCpu == 0)
            // handle EMT request
            rc = VMR3ReqProcessU(pUVM, VMCPUID_ANY, false);
        else if (pUVCpu->vm.s.pNormalReqs || pUVCpu->vm.s.pPriorityReqs)
            // 讓對應的 CPU handle EMT request
            rc = VMR3ReqProcessU(pUVM, pUVCpu->idCpu, false);
        else
            // 等待事件發生
            rc = VMR3WaitU(pUVCpu);
    }
    else
    {
        enmBefore = pVM->enmVMState;
        if (pUVM->vm.s.fTerminateEMT) // 檢查是否需要退出
        {
            rc = VINF_EM_TERMINATE;
            break;
        }

        if (VM_FF_IS_SET(pVM, VM_FF_EMT_RENDEZVOUS))
            rc = VMMR3EmtRendezvousFF(pVM, pVM->apCpusR3[idCpu]);
        else if (pUVM->vm.s.pNormalReqs || pUVM->vm.s.pPriorityReqs)
            rc = VMR3ReqProcessU(pUVM, VMCPUID_ANY, false);
        else if (pUVCpu->vm.s.pNormalReqs || pUVCpu->vm.s.pPriorityReqs)
            rc = VMR3ReqProcessU(pUVM, pUVCpu->idCpu, false);
        else if (VM_FF_IS_SET(pVM, VM_FF_DBGF) || VMCPU_FF_IS_SET(pVCpu, VMCPU_FF_DBGF))
            // debugger request
            rc = DBGFR3VMMForcedAction(pVM, pVCpu);
        else if (VM_FF_TEST_AND_CLEAR(pVM, VM_FF_RESET))
        {
            // delay reset request
            rc = VBOXSTRICTRC_VAL(VMR3ResetFF(pVM));
            VM_FF_CLEAR(pVM, VM_FF_RESET);
        }
        else
            rc = VMR3WaitU(pUVCpu); // do nothing and wait

    	// 檢查是否有 termination request
        if (rc == VINF_EM_TERMINATE || pUVM->vm.s.fTerminateEMT)
            break;
    }

    // 一些 request 可能會 resume/start VM，在此情況中需要透過 VM status 判斷是否正在執行
    if (RT_SUCCESS(rc)) // 已經處理完所有 event
    {
        pVM = pUVM->pVM;
        if (pVM)
        {
            pVCpu = pVM->apCpusR3[idCpu];
            if (pVM->enmVMState == VMSTATE_RUNNING && VMCPUSTATE_IS_STARTED(VMCPU_GET_STATE(pVCpu)))
                rc = EMR3ExecuteVM(pVM, pVCpu); // 執行VM
        }
    }

} /* forever */
...
```

- `EMR3ExecuteVM()` - **R3 執行 VM 的 entry point**

```c
// 如果還沒執行完 vmR3Destroy()，先減少 active EMT count，在 vmR3Destroy() 時就不需要執行 (?)
if (!pUVCpu->vm.s.fBeenThruVmDestroy)
    ASMAtomicDecU32(&pUVM->vm.s.cActiveEmts);

// cleanup and exit
// EMT0 最後才執行 destructor
PVM pVM;
if (idCpu == 0 && (pVM = pUVM->pVM) != NULL)
{
    // 等待所有的 EMT 都 terminate
    for (VMCPUID iCpu = 1; iCpu < pUVM->cCpus; iCpu++)
    {
        RTTHREAD hThread;
        ASMAtomicXchgHandle(&pUVM->aCpus[iCpu].vm.s.ThreadEMT, NIL_RTTHREAD, &hThread);
        if (hThread != NIL_RTTHREAD)
            // sleep for waiting
            int rc2 = RTThreadWait(hThread, 5 * RT_MS_1SEC, NULL);
    }

    // 設置成 terminated state，清除 VM ptr
    vmR3SetTerminated(pVM);
    pUVM->pVM = NULL;
    for (VMCPUID iCpu = 0; iCpu < pUVM->cCpus; iCpu++)
    {
        pUVM->aCpus[iCpu].pVM   = NULL;
        pUVM->aCpus[iCpu].pVCpu = NULL;
    }
	
    // deregister VM (VMMR0_DO_GVMM_DESTROY_VM)
    int rc2 = SUPR3CallVMMR0Ex(VMCC_GET_VMR0_FOR_CALL(pVM), 0, VMMR0_DO_GVMM_DESTROY_VM, 0, NULL);
}
else if (idCpu != 0 && (pVM = pUVM->pVM) != NULL)
    // 只 deregister VCPU (VMMR0_DO_GVMM_DEREGISTER_VMCPU)
    int rc2 = SUPR3CallVMMR0Ex(VMCC_GET_VMR0_FOR_CALL(pVM), idCpu, VMMR0_DO_GVMM_DEREGISTER_VMCPU, 0, NULL);

if (pUVM->pVmm2UserMethods && pUVM->pVmm2UserMethods->pfnNotifyEmtTerm)
    pUVM->pVmm2UserMethods->pfnNotifyEmtTerm(pUVM->pVmm2UserMethods, pUVM, pUVCpu);

pUVCpu->vm.s.NativeThreadEMT = NIL_RTNATIVETHREAD;
return rc;
```

- 在 EMT 非 EMT0 時只會 deregister VMCPU，其他 EMT 結束時才會 deregister VM 本身

---

和 OS 裡的 thread 類似， EMT 也提供了一套可以 pause / wakeup / waiting 的 API，在 VM 處於不同狀態的時候，對應的 function 也不同，以下為 method 的 enumeration：

```c
/** The halt method. */
typedef enum
{
    /** The usual invalid value. */
    VMHALTMETHOD_INVALID = 0,
    /** Use the method used during bootstrapping. */
    VMHALTMETHOD_BOOTSTRAP,
    /** Use the default method. */
    VMHALTMETHOD_DEFAULT,
    /** The old spin/yield/block method. */
    VMHALTMETHOD_OLD,
    /** The first go at a block/spin method. */
    VMHALTMETHOD_1,
    /** The first go at a more global approach. */
    VMHALTMETHOD_GLOBAL_1,
    /** The end of valid methods. (not inclusive of course) */
    VMHALTMETHOD_END,
    /** The usual 32-bit max value. */
    VMHALTMETHOD_32BIT_HACK = 0x7fffffff
} VMHALTMETHOD;
```

以及對應到的 function：

```c
// Array with halt method descriptors.
static const struct VMHALTMETHODDESC
{
    // method ID
    VMHALTMETHOD                enmHaltMethod;
    // 確定該 method 是否支援在 r0 暫停
    bool                        fMayHaltInRing0;
    // 用來初始化變數以及載入 config 的 init function
    DECLR3CALLBACKMEMBER(int,   pfnInit,(PUVM pUVM));
    // termination function
    DECLR3CALLBACKMEMBER(void,  pfnTerm,(PUVM pUVM));
    // VMR3WaitHaltedU() 做完 log & assertion 後會呼叫此 function
    DECLR3CALLBACKMEMBER(int,   pfnHalt,(PUVMCPU pUVCpu, const uint32_t fMask, uint64_t u64Now));
    // VMR3WaitU() 做完 log & assertion 後會呼叫此 function
    DECLR3CALLBACKMEMBER(int,   pfnWait,(PUVMCPU pUVCpu));
    // VMR3NotifyCpuFFU() 做完 log & assertion 後會呼叫此 function
    DECLR3CALLBACKMEMBER(void,  pfnNotifyCpuFF,(PUVMCPU pUVCpu, uint32_t fFlags));
    // VMR3NotifyGlobalFFU() 做完 log & assertion 後會呼叫此 function
    DECLR3CALLBACKMEMBER(void,  pfnNotifyGlobalFF,(PUVM pUVM, uint32_t fFlags));
} g_aHaltMethods[] =
{
    { VMHALTMETHOD_BOOTSTRAP, ...},
    { VMHALTMETHOD_OLD, ...},
    { VMHALTMETHOD_1, ...},
    { VMHALTMETHOD_GLOBAL_1, ...},
};
```

- 建立 VM 時 (`vmR3CreateUVM()`)，會執行 `pUVM->vm.s.enmHaltMethod = VMHALTMETHOD_BOOTSTRAP` 來指定呼叫 bootstrap halt method；啟動完 VM 後 (`vmR3CreateU()` 的後半段)，會執行 `vmR3SetHaltMethodU(pUVM, VMHALTMETHOD_DEFAULT)`，設置成呼叫 default method



`vmR3SetHaltMethodU()` - Changes the halt method

```c
PVM pVM = pUVM->pVM
// 改變成 default
if (enmHaltMethod == VMHALTMETHOD_DEFAULT)
{
    uint32_t u32;
    // 從 config 內讀指令的 method
    int rc = CFGMR3QueryU32(CFGMR3GetChild(CFGMR3GetRoot(pVM), "VM"), "HaltMethod", &u32);
    if (RT_SUCCESS(rc))
    {
        enmHaltMethod = (VMHALTMETHOD)u32;
        if (enmHaltMethod <= VMHALTMETHOD_INVALID || enmHaltMethod >= VMHALTMETHOD_END)
            return VMSetError(pVM, VERR_INVALID_PARAMETER, RT_SRC_POS, N_("Invalid VM/HaltMethod value %d"), enmHaltMethod);
    }
    else if (rc == VERR_CFGM_VALUE_NOT_FOUND || rc == VERR_CFGM_CHILD_NOT_FOUND)
        // 找不到對應的 function
        return VMSetError(pVM, rc, RT_SRC_POS, N_("Failed to Query VM/HaltMethod as uint32_t"));
    else
        // 如果沒設置，就把 method 狀態換成 VMHALTMETHOD_GLOBAL_1
        enmHaltMethod = VMHALTMETHOD_GLOBAL_1;
}

// 找 descriptor
unsigned i = 0;
while (i < RT_ELEMENTS(g_aHaltMethods) && g_aHaltMethods[i].enmHaltMethod != enmHaltMethod)
    i++;

// 透過 Rendezvous worker 呼叫 vmR3SetHaltMethodCallback()
return VMMR3EmtRendezvous(pVM, VMMEMTRENDEZVOUS_FLAGS_TYPE_ASCENDING, vmR3SetHaltMethodCallback, (void *)(uintptr_t)i);
```

---

`VMR3WaitHalted()` - Halted VM Wait，讓 VCPU 在 for loop 中等到可以繼續執行 (wakeup)

```c
// 檢查相關的 force flag
const uint32_t fMask = !fIgnoreInterrupts
    ? VMCPU_FF_EXTERNAL_HALTED_MASK
    : VMCPU_FF_EXTERNAL_HALTED_MASK & ~(VMCPU_FF_UPDATE_APIC | VMCPU_FF_INTERRUPT_APIC | VMCPU_FF_INTERRUPT_PIC);
if (VM_FF_IS_ANY_SET(pVM, VM_FF_EXTERNAL_HALTED_MASK) ||  VMCPU_FF_IS_ANY_SET(pVCpu, fMask))
    return VINF_SUCCESS;

if (pVCpu->idCpu == 0) // EMT0 在 halt 時先暫停 yielder
    VMMR3YieldSuspend(pVM);
TMNotifyStartOfHalt(pVCpu); // 通知 TM CPU 要進入 halt

PUVMCPU pUVCpu = pVCpu->pUVCpu;
uint64_t u64Now = RTTimeNanoTS();
... // 時間紀錄

VMCPU_SET_STATE(pVCpu, VMCPUSTATE_STARTED_HALTED); // update state
PUVM pUVM = pUVCpu->pUVM;
// 呼叫 halt method
int rc = g_aHaltMethods[pUVM->vm.s.iHaltMethod].pfnHalt(pUVCpu, fMask, u64Now);
// 呼叫完畢，換回 state
VMCPU_SET_STATE(pVCpu, VMCPUSTATE_STARTED);

// 通知 TM 並且 resume yielder
TMNotifyEndOfHalt(pVCpu);
if (pVCpu->idCpu == 0) // EMT0
    VMMR3YieldResume(pVM);

return rc;
```

- `TMNotifyStartOfHalt()` - Notification that the cpu is entering the halt state



`vmR3HaltGlobal1Halt()` - The global 1 halt method - Block in GMM (**ring-0**) and let it try take care of the global scheduling of EMT threads

```c
PUVM    pUVM  = pUVCpu->pUVM;
PVMCPU  pVCpu = pUVCpu->pVCpu;
PVM     pVM   = pUVCpu->pVM;

// halt loop
int rc = VINF_SUCCESS;
ASMAtomicWriteBool(&pUVCpu->vm.s.fWait, true); // mark 成正在等待
unsigned cLoops = 0;
for (;; cLoops++)
{
    // 向 timer 請求時間，檢查是否可以 exit
    TMR3TimerQueuesDo(pVM);
    if (VM_FF_IS_ANY_SET(pVM, VM_FF_EXTERNAL_HALTED_MASK) ||  VMCPU_FF_IS_ANY_SET(pVCpu, fMask))
        break;

    // 估算下個 event 的時間
    uint64_t u64Delta;
    uint64_t u64GipTime = TMTimerPollGIP(pVM, pVCpu, &u64Delta);
    // 如果有 external interrupt
    if (VM_FF_IS_ANY_SET(pVM, VM_FF_EXTERNAL_HALTED_MASK) ||  VMCPU_FF_IS_ANY_SET(pVCpu, fMask))
        break;

    // 如果沒有 spinning，並且時間間隔不是每個都很小，就 block
    // cNsSpinBlockThresholdCfg: threshold between spinning and blocking
    if (u64Delta >= pUVM->vm.s.Halt.Global1.cNsSpinBlockThresholdCfg)
    {
        VMMR3YieldStop(pVM); // 暫停 CPU yielder
        // FF checking
        if (VM_FF_IS_ANY_SET(pVM, VM_FF_EXTERNAL_HALTED_MASK) ||  VMCPU_FF_IS_ANY_SET(pVCpu, fMask))
            break;

        uint64_t const u64StartSchedHalt   = RTTimeNanoTS();
        rc = SUPR3CallVMMR0Ex(VMCC_GET_VMR0_FOR_CALL(pVM), pVCpu->idCpu, VMMR0_DO_GVMM_SCHED_HALT, u64GipTime, NULL);
        uint64_t const u64EndSchedHalt     = RTTimeNanoTS();
        uint64_t const cNsElapsedSchedHalt = u64EndSchedHalt - u64StartSchedHalt;

        if (rc == VERR_INTERRUPTED) // 接收到 interrupt
            rc = VINF_SUCCESS;
        else if (RT_FAILURE(rc))
        {
            rc = vmR3FatalWaitError(pUVCpu, "vmR3HaltGlobal1Halt: VMMR0_DO_GVMM_SCHED_HALT->%Rrc\n", rc);
            break;
        }
    }
    // 如果是進行 spinning，一陣子就 wakeup 一次，所以實際上並不是完全 spinning
    else if (!(cLoops & 0x1fff)) // 每 0x2000 就 wakeup
        rc = SUPR3CallVMMR0Ex(VMCC_GET_VMR0_FOR_CALL(pVM), pVCpu->idCpu, VMMR0_DO_GVMM_SCHED_POLL, false, NULL);
}
ASMAtomicUoWriteBool(&pUVCpu->vm.s.fWait, false);
return rc;
```



`vmR3HaltMethod1Halt()` - Method 1 - Block whenever possible, and when lagging behind switch to spinning for 10-30ms with occasional blocking until the lag has been eliminated，能做 block 就 block，當 lag 時就換成 spinning 10-30 ms 並偶爾切到 block，直到 lag 結束





---

>  再來分析 halt method array 內所對應到的 function，不過一部分已經在上面有介紹了

VMR3WaitU - 讓 VCPU waiting 事件的發生



`vmR3DefaultWait()` - Default `VMR3Wait()` worker

```c
ASMAtomicWriteBool(&pUVCpu->vm.s.fWait, true);
PVM    pVM   = pUVCpu->pVM;
PVMCPU pVCpu = pUVCpu->pVCpu;
int    rc    = VINF_SUCCESS;
for (;;) // FF 滿足 suspend 條件 or 有其他狀況發生時 (RT_FAILURE(rc)) 才會離開
{
    // 檢查相關的 force flag
    if (    VM_FF_IS_ANY_SET(pVM, VM_FF_EXTERNAL_SUSPENDED_MASK)
        ||  VMCPU_FF_IS_ANY_SET(pVCpu, VMCPU_FF_EXTERNAL_SUSPENDED_MASK))
        break;

    // 等待片刻，可能會有人呼叫 wakeup 或 interrupt
    rc = RTSemEventWait(pUVCpu->vm.s.EventSemWait, 1000);
    if (rc == VERR_TIMEOUT)
        rc = VINF_SUCCESS;
    else if (RT_FAILURE(rc))
    {
        rc = vmR3FatalWaitError(pUVCpu, "RTSemEventWait->%Rrc", rc);
        break;
    }
}
ASMAtomicUoWriteBool(&pUVCpu->vm.s.fWait, false);
return rc;
```



`vmR3HaltGlobal1Wait()` - VMR3Wait() worker

```c
ASMAtomicWriteBool(&pUVCpu->vm.s.fWait, true);

PVM    pVM   = pUVCpu->pUVM->pVM;
PVMCPU pVCpu = VMMGetCpu(pVM);
int rc = VINF_SUCCESS;
for (;;)
{
    // break when suspend
    if (    VM_FF_IS_ANY_SET(pVM, VM_FF_EXTERNAL_SUSPENDED_MASK)
        ||  VMCPU_FF_IS_ANY_SET(pVCpu, VMCPU_FF_EXTERNAL_SUSPENDED_MASK))
        break;
	// 用 ioctl 呼叫 r0 暫停 VCPU
    rc = SUPR3CallVMMR0Ex(VMCC_GET_VMR0_FOR_CALL(pVM), pVCpu->idCpu, VMMR0_DO_GVMM_SCHED_HALT, RTTimeNanoTS() + 1000000000 /* +1s */, NULL);
    if (rc == VERR_INTERRUPTED)
        rc = VINF_SUCCESS;
    else if (RT_FAILURE(rc))
    {
        rc = vmR3FatalWaitError(pUVCpu, "vmR3HaltGlobal1Wait: VMMR0_DO_GVMM_SCHED_HALT->%Rrc\n", rc);
        break;
    }
}

ASMAtomicUoWriteBool(&pUVCpu->vm.s.fWait, false);
return rc;
```

- `SUPR3CallVMMR0Ex()` - r3 通過 `ioctl()` 呼叫 r0 執行一些指令



`vmR3BootstrapWait()` - Bootstrap VMR3Wait() worker，當 VM 一開始建立時是使用這個 function，因為這時候還沒有初始化 VMMR0，因此這只是普通的 sleep

```c
... // 與上方相同
for (;;)
{
    // 檢查是否有 interrupt
	// global request (因為為 VM)
    if (pUVM->vm.s.pNormalReqs   || pUVM->vm.s.pPriorityReqs)
        break;
    // local request (為 VCPU)
    if (pUVCpu->vm.s.pNormalReqs || pUVCpu->vm.s.pPriorityReqs)
        break;

    if (... /* suspend FF */)
        break;
    if (pUVM->vm.s.fTerminateEMT) // VM 已經結束
        break;

    ... // 與上方相同
}
... // 與上方相同
```

---

VMR3NotifyCpuFFU - wakeup a VCPU



`vmR3DefaultNotifyCpuFF()` - Default `VMR3NotifyFF()` worker

```c
if (pUVCpu->vm.s.fWait)
    // 發送 signal
    int rc = RTSemEventSignal(pUVCpu->vm.s.EventSemWait);
else
{
    PVMCPU pVCpu = pUVCpu->pVCpu;
    if (pVCpu)
    {
        VMCPUSTATE enmState = pVCpu->enmState;
        if (   enmState == VMCPUSTATE_STARTED_EXEC_NEM
            || enmState == VMCPUSTATE_STARTED_EXEC_NEM_WAIT)
            NEMR3NotifyFF(pUVCpu->pVM, pVCpu, fFlags);
    }
}
```



`vmR3HaltGlobal1NotifyCpuFF()` - The global 1 halt method - `VMR3NotifyFF()` worker

```c
// 當 r0 halt 時，fWait 的狀態為 unset，因此需要檢查 CPU state 來看要做什麼 wakeup
PVMCPU pVCpu = pUVCpu->pVCpu;
if (pVCpu)
{
    VMCPUSTATE enmState = VMCPU_GET_STATE(pVCpu);
    // 如果 VCPU 在等待狀態
    if (enmState == VMCPUSTATE_STARTED_HALTED || pUVCpu->vm.s.fWait)
        // R0 - VMMR0_DO_GVMM_SCHED_WAKE_UP
        int rc = SUPR3CallVMMR0Ex(VMCC_GET_VMR0_FOR_CALL(pUVCpu->pVM), pUVCpu->idCpu, VMMR0_DO_GVMM_SCHED_WAKE_UP, 0, NULL);
    else if ((fFlags & VMNOTIFYFF_FLAGS_POKE) || !(fFlags & VMNOTIFYFF_FLAGS_DONE_REM))
    {
        if (enmState == VMCPUSTATE_STARTED_EXEC)
        {
            if (fFlags & VMNOTIFYFF_FLAGS_POKE)
                // VMMR0_DO_GVMM_SCHED_POKE
                int rc = SUPR3CallVMMR0Ex(VMCC_GET_VMR0_FOR_CALL(pUVCpu->pVM), pUVCpu->idCpu, VMMR0_DO_GVMM_SCHED_POKE, 0, NULL);
        }
        // 如果是 native EM (BT)
        else if (enmState == VMCPUSTATE_STARTED_EXEC_NEM || enmState == VMCPUSTATE_STARTED_EXEC_NEM_WAIT)
            NEMR3NotifyFF(pUVCpu->pVM, pVCpu, fFlags);
    }
}
else if (pUVCpu->vm.s.fWait)
    // VMMR0_DO_GVMM_SCHED_WAKE_UP
    int rc = SUPR3CallVMMR0Ex(VMCC_GET_VMR0_FOR_CALL(pUVCpu->pVM), pUVCpu->idCpu, VMMR0_DO_GVMM_SCHED_WAKE_UP, 0, NULL);
```

- VMMR0_DO_GVMM_SCHED_WAKE_UP - Wakes up the halted EMT thread so it can service a pending request
- VMMR0_DO_GVMM_SCHED_POKE - Pokes an EMT if it's still busy running guest code



`vmR3BootstrapNotifyCpuFF()` - Bootstrap VMR3NotifyFF() worker

```c
if (pUVCpu->vm.s.fWait)
{
    // 發送 event signal
    int rc = RTSemEventSignal(pUVCpu->vm.s.EventSemWait);
}
```

- fWait - Wait/Idle indicator



## 9

