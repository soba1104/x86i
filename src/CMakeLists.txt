EXECUTE_PROCESS(COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/../tool/opcode_gen"
                OUTPUT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/bochs/dummyfuncs.h")

INCLUDE_DIRECTORIES(bochs)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS_DEBUG} -O0 -g")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g")

SET(X86I_HEADERS x86i.h)
SET(BOCHS_SOURCES bochs/fetchdecode64.cc
                  bochs/arith64.cc
                  bochs/data_xfer64.cc
                  bochs/logical8.cc
                  bochs/sse.cc
                  bochs/globals.cc
                  bochs/utils.cc
                  bochs/funcs.cc)
SET(BOCHS_HEADERS bochs/bochs.h
                  bochs/config.h
                  bochs/cpu.h
                  bochs/xmm.h
                  bochs/simd_int.h
                  bochs/simd_compare.h
                  bochs/crregs.h
                  bochs/descriptor.h
                  bochs/instr.h
                  bochs/ia_opcodes.h
                  bochs/fetchdecode.h
                  bochs/fetchdecode_x87.h
                  bochs/fetchdecode_sse.h
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
