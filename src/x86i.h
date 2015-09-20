#include <stdint.h>

void *alloc_cpu();
void free_cpu(void *cpu);

void set_stack(void *cpu, void *stack);
void set_ip(void *cpu, uint64_t ip);
uint64_t get_ip(void *cpu);

void *alloc_insn();
void free_insn(void *insn);
void clear_insn(void *insn);
void step(void *cpu, void *insn);
int decode(uint8_t **ipp, void *insn);
