.text
.globl _host_rdtsc
_host_rdtsc:
mov $1, %eax
cpuid
rdtsc
shlq $32,%rdx
orq %rdx,%rax
ret

.text
.globl _host_cpuid
_host_cpuid:
pushq %rbx
movl (%rdi), %eax
movq %rdx, %r8
movq %rcx, %r9
cpuid
movl %eax, (%rdi)
movl %ebx, (%rsi)
movl %ecx, (%r8)
movl %edx, (%r9)
popq %rbx
movq $0, %rax
ret
