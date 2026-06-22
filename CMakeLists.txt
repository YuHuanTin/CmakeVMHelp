
cmake_minimum_required(VERSION ${CMAKE_VERSION})

#set(VCPKG_HOST_TRIPLET "x64-mingw-dynamic")
#set(VCPKG_TARGET_TRIPLET "x64-mingw-dynamic")
set(XDBG_SDK_PATH "D:\\snapshot_2026-05-27_12-11\\pluginsdk")

project(CmakeVMHelp CXX)

set(CMAKE_VERBOSE_MAKEFILE ON CACHE BOOL "Detail output" FORCE)
set(CMAKE_CXX_STANDARD 26)

set(ENABLE_ASAN FALSE)

set(COMPILER_FILES
        src/_plugin_entry.cpp
        src/_plugin_entry.h
        src/GUI.cpp
        src/GUI.h
        src/Engine.cpp
        src/Engine.h
        src/CommandHandlers.cpp
        src/CommandHandlers.h
        src/utils/Dbg.cpp
        src/utils/Dbg.h
        src/pch.h
        src/utils/Uc.cpp
        src/utils/Uc.h
        src/utils/StructDef.h
        src/utils/CodeTraceLogger.cpp
        src/utils/CodeTraceLogger.h
)

add_compile_options(-Wall -Wextra -Wpedantic -Wconversion)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${XDBG_SDK_PATH})
link_directories(${XDBG_SDK_PATH})
add_library(${PROJECT_NAME} SHARED ${COMPILER_FILES})

### 3rd party library
find_package(capstone CONFIG REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE capstone::capstone)

find_package(PkgConfig REQUIRED)
pkg_check_modules(unicorn_ REQUIRED IMPORTED_TARGET unicorn)
target_link_libraries(${PROJECT_NAME} PRIVATE PkgConfig::unicorn_)

find_package(nlohmann_json CONFIG REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE nlohmann_json::nlohmann_json)

### library link
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_link_libraries(${PROJECT_NAME} PRIVATE x64dbg x64bridge)
elseif (CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_link_libraries(${PROJECT_NAME} PRIVATE x32dbg x32bridge)
endif ()
target_link_libraries(${PROJECT_NAME} PRIVATE pthread)

### precompiled header
target_precompile_headers(${PROJECT_NAME} PRIVATE src/pch.h)

add_custom_command(
        TARGET ${PROJECT_NAME}      # 关联的目标
        POST_BUILD                  # 指定在构建后执行
        COMMAND "${CMAKE_SOURCE_DIR}/cp.bat"
        # 指定工作目录，确保 .bat 里的相对路径 ".\cmake-build-debug" 依然有效
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Running post-build steps asynchronously..."
        VERBATIM                    # (推荐) 确保特殊字符被正确传递给 shell
)

if (ENABLE_ASAN AND MSVC)
    # https://learn.microsoft.com/en-us/cpp/sanitizers/error-container-overflow?view=msvc-170
    # 如果出现以下错误则启用以下定义
    # my_static.lib(my_code.obj) : error LNK2038: mismatch detected for 'annotate_vector': value '0' doesn't match value '1' in main.obj
    #target_compile_definitions(${PROJECT_NAME} PRIVATE _DISABLE_VECTOR_ANNOTATION _DISABLE_STRING_ANNOTATION)

    target_compile_options(${PROJECT_NAME} PRIVATE /fsanitize=address /Zi)
    target_link_options(${PROJECT_NAME} PRIVATE /INCREMENTAL:NO)

    cmake_path(GET CMAKE_CXX_COMPILER PARENT_PATH CMAKE_CXX_COMPILER_DIR)
    message(AUTHOR_WARNING "ASAN PATH >>> PATH=${CMAKE_CXX_COMPILER_DIR} <<<, Please add this directory to RuntimeEnv to use ASAN.")

    file(COPY ${CMAKE_CXX_COMPILER_DIR}/clang_rt.asan_dynamic-x86_64.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
    message(AUTHOR_WARNING "Auto Copy x64-windows.dll to ${CMAKE_CURRENT_BINARY_DIR}...")
endif ()