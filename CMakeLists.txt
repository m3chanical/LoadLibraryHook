# CMakeList.txt : CMake project for LoadLibraryHook, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("LoadLibraryHook")

add_executable (LoadLibraryHook "LoadLibraryHook.cpp" "LoadLibraryHook.h")

get_filename_component(PLH_DIR "./" ABSOLUTE)
include_directories(${PLH_DIR})

if(MSVC)
  # force static lib
  set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        )
	foreach(CompilerFlag ${CompilerFlags})
		string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
	endforeach()
endif()

# TODO: Add tests and install targets if needed.
target_compile_options(${PROJECT_NAME} PRIVATE /std:c++latest)
target_link_libraries(${PROJECT_NAME} "F:\\vs_projects\\LoadLibraryHook\\Zydis.lib")
target_link_libraries(${PROJECT_NAME} "F:\\vs_projects\\LoadLibraryHook\\PolyHook_2.lib")
