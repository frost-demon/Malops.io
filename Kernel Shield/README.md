## Qs1:

> **Question:** The driver exposes itself to usermode applications under a specific name. What is this name?

**Answer:**

```text
NSecKrnl
```

**Finding:** 

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
