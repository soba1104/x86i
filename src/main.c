#include "x86i.h"

#include <stdio.h>
#include <stdlib.h>

int main(void) {
  void *cpu, *insn;
  uint8_t *stack;
  uint8_t inputs[] = {
    0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10
  };
  uint64_t rip = (uint64_t)inputs, end = rip + sizeof(inputs);
  printf("hello\n");
  stack = malloc(0x1000000);
  cpu = alloc_cpu();
  set_stack(cpu, stack + 0x1000000);
  set_rip(cpu, rip);
  insn = alloc_insn();
  while(get_rip(cpu) < end) {
    clear_insn(insn);
    decode64(cpu, insn);
    step(cpu, insn);
  }
  free_insn(insn);
  free_cpu(cpu);
  free(stack);
  return 0;
}
