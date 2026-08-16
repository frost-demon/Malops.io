---
Qs1. What is the SHA256 hash of the sample?

**Answer:**

```text
0b8ecdaccf492000f3143fa209481eb9db8c0a29da2b79ff5b7f6e84bb3ac7c8
```

**Artifact:**

![Question 01 Artifact](Artifacts/Malops-CTF-Singularity-Qs1.png)

---
Qs2. What is the name of the primary initialization function called when the module is loaded?

**Answer:**

```text
init_module
```

**Decompiled Pseudocode:**

```text
// Alternative name is 'init_module'
int _cdecl singularity_init()
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

```text
15
```


---
