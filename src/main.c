#include "x86i.h"

#include <stdio.h>

int main(void) {
  void *insn;
  uint8_t inputs[] = {
    0x55, 0x48, 0x39, 0xe5, 0x48, 0x83, 0xec, 0x10
  };
  uint8_t *ip = inputs;
  printf("hello\n");
  insn = alloc_insn();
  decode(&ip, insn);
  run_insn(insn);
  free_insn(insn);
  return 0;
}
