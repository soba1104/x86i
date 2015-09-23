#include <stdint.h>

void *alloc_cpu();
void free_cpu(void *cpu);

void set_stack(void *cpu, void *stack);
void set_rip(void *cpu, uint64_t rip);
void set_rax(void *cpu, uint64_t rax);
void set_rdi(void *cpu, uint64_t rdi);
void set_rsi(void *cpu, uint64_t rsi);
void set_rdx(void *cpu, uint64_t rdx);
void set_rcx(void *cpu, uint64_t rcx);
void set_r8(void *cpu, uint64_t r8);
void set_r9(void *cpu, uint64_t r9);
uint64_t get_rip(void *cpu);
uint64_t get_rax(void *cpu);
uint64_t get_rbx(void *cpu);
uint64_t get_rcx(void *cpu);
uint64_t get_rdx(void *cpu);
uint64_t get_rdi(void *cpu);
uint64_t get_rsi(void *cpu);
uint64_t get_rbp(void *cpu);
uint64_t get_rsp(void *cpu);
uint64_t get_r8(void *cpu);
uint64_t get_r9(void *cpu);
uint64_t get_r10(void *cpu);
uint64_t get_r11(void *cpu);
uint64_t get_r12(void *cpu);
uint64_t get_r13(void *cpu);
uint64_t get_r14(void *cpu);
uint64_t get_r15(void *cpu);
uint32_t get_eflags(void *cpu);

void *alloc_insn();
void free_insn(void *insn);
void clear_insn(void *insn);
void step(void *cpu, void *insn);
int decode64(void *cpu, void *insn);

uint16_t get_opcode(void *insn);
const char *get_opcode_name(void *insn);
