.text
.globl _host_rdtsc
_host_rdtsc:
cpuid
rdtsc
shlq $32,%rdx
orq %rdx,%rax
ret
