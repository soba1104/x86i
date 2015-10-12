EXECUTE_PROCESS(COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/../tool/opcode_gen"
                OUTPUT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/bochs/dummyfuncs.h")

INCLUDE_DIRECTORIES(bochs)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS_DEBUG} -O2 -g")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_DEBUG} -O2 -g")

SET(X86I_HEADERS x86i.h)
SET(BOCHS_SOURCES bochs/fetchdecode64.cc
                  bochs/arith8.cc
                  bochs/arith16.cc
                  bochs/arith32.cc
                  bochs/arith64.cc
                  bochs/bit.cc
                  bochs/bit16.cc
                  bochs/bit32.cc
                  bochs/bit64.cc
                  bochs/bmi64.cc
                  bochs/data_xfer8.cc
                  bochs/data_xfer16.cc
                  bochs/data_xfer32.cc
                  bochs/data_xfer64.cc
                  bochs/load.cc
                  bochs/logical8.cc
                  bochs/logical16.cc
                  bochs/logical32.cc
                  bochs/logical64.cc
                  bochs/mult32.cc
                  bochs/mult64.cc
                  bochs/shift8.cc
                  bochs/shift16.cc
                  bochs/shift32.cc
                  bochs/shift64.cc
                  bochs/sse.cc
                  bochs/sse_pfp.cc
                  bochs/sse_rcp.cc
                  bochs/avx/avx.cc
                  bochs/avx/avx2.cc
                  bochs/avx/avx512_move.cc
                  bochs/avx/avx_cvt.cc
                  bochs/avx/avx_pfp.cc
                  bochs/fpu/f2xm1.cc
                  bochs/fpu/ferr.cc
                  bochs/fpu/fpatan.cc
                  bochs/fpu/fprem.cc
                  bochs/fpu/fpu.cc
                  bochs/fpu/fpu_arith.cc
                  bochs/fpu/fpu_compare.cc
                  bochs/fpu/fpu_const.cc
                  bochs/fpu/fpu_load_store.cc
                  bochs/fpu/fpu_misc.cc
                  bochs/fpu/fpu_trans.cc
                  bochs/fpu/fsincos.cc
                  bochs/fpu/fyl2x.cc
                  bochs/fpu/poly.cc
                  bochs/fpu/softfloat.cc
                  bochs/fpu/softfloat16.cc
                  bochs/fpu/softfloatx80.cc
                  bochs/fpu/softfloat-muladd.cc
                  bochs/fpu/softfloat-round-pack.cc
                  bochs/fpu/softfloat-specialize.cc
                  bochs/globals.cc
                  bochs/host_adapter.s
                  bochs/utils.cc
                  bochs/funcs.cc)
SET(BOCHS_HEADERS bochs/bochs.h
                  bochs/config.h
                  bochs/cpu.h
                  bochs/cpuid.h
                  bochs/i387.h
                  bochs/xmm.h
                  bochs/simd_int.h
                  bochs/simd_pfp.h
                  bochs/simd_compare.h
                  bochs/scalar_arith.h
                  bochs/crregs.h
                  bochs/descriptor.h
                  bochs/lazy_flags.h
                  bochs/instr.h
                  bochs/ia_opcodes.h
                  bochs/fetchdecode.h
                  bochs/fetchdecode_x87.h
                  bochs/fetchdecode_sse.h
                  bochs/fetchdecode_xop.h
                  bochs/fetchdecode_avx.h
                  bochs/fpu/control_w.h
                  bochs/fpu/fpu_constant.h
                  bochs/fpu/softfloat.h
                  bochs/fpu/softfloatx80.h
                  bochs/fpu/softfloat-compare.h
                  bochs/fpu/softfloat-macros.h
                  bochs/fpu/softfloat-round-pack.h
                  bochs/fpu/softfloat-specialize.h
                  bochs/fpu/status_w.h
                  bochs/fpu/tag_w.h
                  bochs/host_adapter.h
                  bochs/dummyfuncs.h)
SET(X86I_SOURCES ${X86I_HEADERS} ${BOCHS_HEADERS} ${BOCHS_SOURCES} main.c)

SET(X86I_SHARED_LIBRARY x86i_shared_library)
SET(X86I_SHARED_LIBRARY_OUTPUT x86i)
ADD_LIBRARY(${X86I_SHARED_LIBRARY} SHARED ${X86I_SOURCES})
SET_TARGET_PROPERTIES(${X86I_SHARED_LIBRARY} PROPERTIES OUTPUT_NAME ${X86I_SHARED_LIBRARY_OUTPUT})
TARGET_LINK_LIBRARIES(${X86I_SHARED_LIBRARY})

SET(X86I_EXECUTABLE x86i_executable)
SET(X86I_EXECUTABLE_OUTPUT x86i)
ADD_EXECUTABLE(${X86I_EXECUTABLE} ${X86I_SOURCES})
SET_TARGET_PROPERTIES(${X86I_EXECUTABLE} PROPERTIES OUTPUT_NAME ${X86I_EXECUTABLE_OUTPUT})
TARGET_LINK_LIBRARIES(${X86I_EXECUTABLE})
