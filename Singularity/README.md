---
Qs1. What is the SHA256 hash of the sample?

**Answer:**

**Finding:** The sample's SHA256 was obtained from VirusTotal under Basic Properties.

```text
0b8ecdaccf492000f3143fa209481eb9db8c0a29da2b79ff5b7f6e84bb3ac7c8
```

**Artifact:**

![Question 01 Artifact](Artifacts/Malops-CTF-Singularity-Qs1.png)

---
Qs2. What is the name of the primary initialization function called when the module is loaded?

**Answer:**

**Finding:** IDA identifies singularity_init() as the module's primary initialization routine, with init_module listed as its alternative name. The routine orchestrates initialization of the rootkit's individual capabilities.

```text
init_module
```

**Decompiled Pseudocode:**

```text
// Alternative name is 'init_module'
int __cdecl singularity_init()
{
  int v0; // ebx
  int v1; // ebx
  int v2; // ebx
  int v3; // ebx
  int v4; // ebx
  int v5; // ebx
  int v6; // ebx
  int v7; // ebx
  int v8; // ebx
  int v9; // ebx
  int v10; // ebx
  int v11; // ebx
  int v12; // ebx
  int v13; // ebx

  _fentry__();
  v0 = reset_tainted_init();
  v1 = hiding_open_init() | v0;
  v2 = become_root_init() | v1;
  v3 = hiding_directory_init() | v2;
  v4 = hiding_stat_init() | v3;
  v5 = hiding_tcp_init() | v4;
  v6 = hooking_insmod_init() | v5;
  v7 = clear_taint_dmesg_init() | v6;
  v8 = hooks_write_init() | v7;
  v9 = hiding_chdir_init() | v8;
  v10 = hiding_readlink_init() | v9;
  v11 = bpf_hook_init() | v10;
  v12 = hiding_icmp_init() | v11;
  v13 = trace_pid_init() | v12;
  module_hide_current();
  return v13;
}
```

**Disassembly View:**

![Question 02 Disassembly View](Artifacts/Malops-CTF-Singularity-Qs2-Disassembly-View.png)

---
Qs3. How many distinct feature-initialization functions are called within above mentioned function?

**Answer:**

**Finding:** The initialization routine invokes 15 distinct feature-specific initialization functions, covering functionality such as process, directory, network, syscall, and BPF-related hiding/hooking.

```text
15
```

---
Qs4. The reset_tainted_init function creates a kernel thread for anti-forensics. What is the hardcoded name of this thread?

**Answer:**

**Finding:** reset_tainted_init() creates a kernel thread through kthread_create_on_node(). The hardcoded thread name passed to the call is "zer0t".

```text
zer0t
```

**Decompiled Pseudocode:**

```text
int __cdecl reset_tainted_init()
{
  kprobe_opcode_t *addr; // rbx
  task_struct *v1; // rax
  task_struct *v2; // rbx
  int pid; // edi

  if ( (int)register_kprobe(a1: &probe_lookup) < 0
    || (addr = probe_lookup.addr, unregister_kprobe(a1: &probe_lookup), addr == nullptr) )
  {
    taint_mask_ptr = nullptr;
    goto LABEL_7;
  }
    taint_mask_ptr = (unsigned __int64 *)((__int64 (__fastcall *)(const char *))addr)(a1: "tainted_mask");
    if ( taint_mask_ptr == nullptr )
  {
LABEL 7:
    LODWORD(v1) = -14;
    return (int)v1;
  }
  v1 = (task_struct *)kthread_create_on_node(a1: zt_thread, a2: 0, a3: 0xFFFFFFFFLL, a4: "zer0t");
  v2 = v1;
  if ( (unsigned __int64)v1 > 0xFFFFFFFFFFFFF000LL )
  {
    cleaner_thread = v1;
  }
  else
  {
    wake_up_process(a1: v1);
    pid = v2->pid;
    cleaner_thread = v2;
    add_hidden_pid(pid);
    LODWORD(v1) = 0;
  }
  return (int)v1;
}
```

**Disassembly View:**

![Question 04 Disassembly View](Artifacts/Malops-CTF-Singularity-Qs4-Disassembly-View.png)

---
Qs5. The add_hidden_pid function has a hardcoded limit. What is the maximum number of PIDs the rootkit can hide?

**Answer:**

**Finding:** add_hidden_pid() enforces a maximum hidden-PID count using the comparison cmp ecx, 20h. Since 0x20 = 32, the rootkit can maintain up to 32 hidden PIDs.

```text
32
```

**Decompiled Pseudocode:**

```text
void __fastcall add_hidden_pid(int pid)
{
  int v1; // ecx
  __int64 v2; // rsi
  int *v3; // rax

  v1 = hidden_count;
  v2 = hidden_count;
  if ( hidden_count <= 0 )
  {
LABEL 7:
    hidden_pids [v2] = pid;
    hidden_count = v1 + 1;
  }
  else
  {
    v2 = hidden_count;
    v3 = hidden_pids;
    while ( *v3 != pid )
    {
      if ( ++v3 == &hidden_pids[hidden_count] )
      {
        if ( hidden_count == 32 )
          return;
        goto LABEL_7;
      }
    }
  }
}
```

**Disassembly View:**

![Question 05 Disassembly View](Artifacts/Malops-CTF-Singularity-Qs5-Disassembly-View.png)

---
Qs6. What is the name of the function called last within init_module to hide the rootkit itself?

**Answer:**

**Finding:** module_hide_current() is the final function invoked by singularity_init(), indicating that the rootkit hides its own kernel module after completing feature initialization.

```text
module_hide_current
```

**Disassembly View:**

![Question 02 Disassembly View](Artifacts/Malops-CTF-Singularity-Qs2-Disassembly-View.png)

---
Qs7. The TCP port hiding module is initialized. What is the hardcoded port number it is configured to hide (decimal)?

**Answer:**

**Finding:** hooked_tcp4_seq_show() compares the TCP port field against 0xA146. Interpreting the value in network byte order results in 0x46A1, which corresponds to decimal port 18081.

```text
18081
```

**Decompiled Pseudocode:**

```text
__int64 __fastcall hooked_tcp4_seq_show(seq_file *seq, void *v)
{
  int v3; // r12d
  __int16 v4; // r14
  __int16 v6; // r13
  int v7; // r12d

  if ( v == (char *)&_UNIQUE_ID___addressable_trace_pid_cleanup878 + 1 )
    return orig_tcp4_seq_show(a1: seq, a2: (char *)&_UNIQUE_ID___addressable_trace_pid_cleanup878 + 1);
  v3 = *((_DWORD *)v + 198);
  v4 = *((_WORD *)v + 6);
  v6 = *((_WORD *)v + 399);
  if ( v3 == (unsigned int)in_aton(a1: "192.168.5.128") )
    return 0;
  v7 = *(_DWORD *)v;
  if ( v7 == (unsigned int)in_aton(a1: "192.168.5.128") || v6 == -24250 || v4 == -24250 )
    return 0;
  else
    return orig_tcp4_seq_show(a1: seq, a2: v);
}
```

Port numbers are stored in Network Byte Order (Big-Endian). In reverse engineering tools such as IDA, a 16-bit port value may sometimes appear as a signed integer, which is why -24250 is displayed instead of its unsigned representation.

Convert the signed value to its unsigned 16-bit equivalent:

```text
-24250 + 65536 = 41286 = 0xA146
```

Now byte-swap the value to convert it from network byte order:

```text
0xA146 → Byte Swap → 0x46A1 → Decimal → 18081
```

**Disassembly View:**

![Question 07 Disassembly View](Artifacts/Malops-CTF-Singularity-Qs7-Disassembly-View.png)

---
Qs8. What is the hardcoded "magic word" string, checked for by the privilege escalation module?

**Answer:**

```text

```







