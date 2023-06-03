cmake_minimum_required(VERSION 3.19)
project(benchcat)

add_executable(bc main.cpp crt.cpp)
target_link_libraries(bc PRIVATE ShLwApi.Lib)
target_compile_features(bc PRIVATE cxx_std_20)

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(bc PRIVATE /GR- /EHs-c- /GS- /Gs9999999)
    target_link_options(bc PRIVATE /OPT:REF /OPT:ICF /NODEFAULTLIB /MANIFEST:NO)
    target_compile_definitions(bc PRIVATE NODEFAULTLIB)
endif ()
