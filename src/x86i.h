#include <stdint.h>

void *alloc_cpu();
void free_cpu(void *cpu);

void set_stack(void *cpu, void *stack);
void set_rip(void *cpu, uint64_t rip);
uint64_t get_rip(void *cpu);
uint64_t get_rax(void *cpu);

void *alloc_insn();
void free_insn(void *insn);
void clear_insn(void *insn);
void step(void *cpu, void *insn);
int decode64(void *cpu, void *insn);

uint16_t get_opcode(void *insn);
const char *get_opcode_name(void *insn);
