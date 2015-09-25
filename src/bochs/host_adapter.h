extern "C" {
uint64_t host_rdtsc();
void host_cpuid(uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx);
void host_sidt(uint64_t addr);
}
