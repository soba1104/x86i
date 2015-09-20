#include "x86i.h"

#include <stdio.h>
#include <stdlib.h>

int main(void) {
  void *cpu, *insn, *stack;
  uint8_t inputs[] = {
    0x55, 0x48, 0x39, 0xe5, 0x48, 0x83, 0xec, 0x10
  };
  uint8_t *ip = inputs;
  printf("hello\n");
  stack = malloc(0x1000000);
  cpu = alloc_cpu();
  set_stack(cpu, stack);
  insn = alloc_insn();
  decode(&ip, insn);
  step(insn, cpu);
  free_insn(insn);
  free_cpu(cpu);
  free(stack);
  return 0;
}
