# CMakeList.txt : CMake project for LoadLibraryHook, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("LoadLibraryHook")

set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(PROJECT_BIN  ${PROJECT_ROOT}/bin)
set(PROJECT_LIB  ${PROJECT_ROOT}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY          ${PROJECT_BIN})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG    ${PROJECT_BIN})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE  ${PROJECT_BIN})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY          ${PROJECT_BIN})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG    ${PROJECT_BIN})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE  ${PROJECT_BIN})

find_package(PolyHook_2 CONFIG REQUIRED)

set(SOURCE_FILES
	"LoadLibraryHook.cpp"
	"LoadLibraryHook.h"	
)

add_executable (LoadLibraryHook ${SOURCE_FILES})

set_property(TARGET ${PROJECT_NAME} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

target_link_libraries(${PROJECT_NAME} PRIVATE PolyHook_2::PolyHook_2)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_auto_type)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)