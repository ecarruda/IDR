add_library(idr_disasm STATIC src/zydis_disassembler.cpp)
target_link_libraries(idr_disasm PUBLIC idr_common idr_pe PRIVATE Zydis)
add_subdirectory(tests)
