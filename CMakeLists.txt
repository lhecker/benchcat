cmake_minimum_required(VERSION 3.19)
project(benchcat)

set(CMAKE_CXX_STANDARD 17)

add_executable(bc main.cpp)
target_compile_features(bc PRIVATE cxx_std_20)
target_compile_options(bc PRIVATE /arch:AVX2)
target_link_options(bc PRIVATE /OPT:REF /OPT:ICF)
set_target_properties(bc PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
