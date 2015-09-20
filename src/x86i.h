#include <stdint.h>

void *alloc_cpu();
void set_stack(void *cpu, void *stack);
void free_cpu(void *cpu);
void *alloc_insn();
void free_insn(void *insn);
void clear_insn(void *insn);
void run_insn(void *insn);
int decode(uint8_t **ipp, void *insn);
