#include <stdint.h>

void *alloc_insn();
void free_insn(void *insn);
void clear_insn(void *insn);
void run_insn(void *insn);
int decode(uint8_t **ipp, void *insn);
