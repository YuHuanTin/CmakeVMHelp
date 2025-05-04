
cmake_minimum_required(VERSION ${CMAKE_VERSION})

#set(VCPKG_TARGET_TRIPLET "x64-windows-static")

project(CmakeVMHelp CXX)

set(CMAKE_VERBOSE_MAKEFILE ON CACHE BOOL "Detail output" FORCE)
set(CMAKE_CXX_STANDARD 26)

set(ENABLE_ASAN FALSE)
set(ENABLE_MODULES FALSE)

set(COMPILER_FILES
        ./gdt.cpp
        ./plugin.cpp
        ./Track.cpp
        ./Track.h
        main.hpp
)

add_compile_options(/utf-8)
link_directories(pluginsdk)
add_library(${PROJECT_NAME} SHARED ${COMPILER_FILES})

find_package(capstone CONFIG REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE capstone::capstone)

find_package(PkgConfig REQUIRED)
pkg_check_modules(unicorn_ REQUIRED IMPORTED_TARGET unicorn)
target_link_libraries(${PROJECT_NAME} PRIVATE PkgConfig::unicorn_)


target_link_libraries(${PROJECT_NAME} PRIVATE ntdll)

target_precompile_headers(${PROJECT_NAME} PRIVATE pch.h)

add_custom_command(
        TARGET ${PROJECT_NAME}       # 关联的目标
        POST_BUILD          # 指定在构建后执行
        COMMAND ${CMAKE_SOURCE_DIR}/cp.bat
        #        
        #        COMMAND sh -c "echo 'Running custom shell script...' && ./my_script.sh $<TARGET_FILE:my_app>" # 示例：运行脚本，传递目标路径
        #        # COMMAND cp $<TARGET_FILE:my_app> /path/to/deploy/ # 示例：复制文件
        #        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} # (可选) 命令执行的工作目录
        #        COMMENT "Running post-build steps for my_app..." # (可选) 构建时显示的消息
        VERBATIM # (推荐) 确保特殊字符被正确传递给 shell
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
if (ENABLE_MODULES AND MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /experimental:module /translateInclude)
    # get complier root path
    cmake_path(GET CMAKE_CXX_COMPILER PARENT_PATH CMAKE_CXX_COMPILER_DIR)
    cmake_path(GET CMAKE_CXX_COMPILER_DIR PARENT_PATH MODULE_ROOT_PATH)
    cmake_path(GET MODULE_ROOT_PATH PARENT_PATH MODULE_ROOT_PATH)
    cmake_path(GET MODULE_ROOT_PATH PARENT_PATH MODULE_ROOT_PATH)

    # find if 'module' directory exists
    if (EXISTS ${MODULE_ROOT_PATH}/modules)
        set(MODULE_ROOT_PATH ${MODULE_ROOT_PATH}/modules)
    endif ()
    message(AUTHOR_WARNING "Module root path: ${MODULE_ROOT_PATH}")

    target_sources(${PROJECT_NAME} PRIVATE
            FILE_SET CXX_MODULES
            # 导入模块目录和 CMakeLists.txt 所在目录
            BASE_DIRS ${MODULE_ROOT_PATH} ${CMAKE_SOURCE_DIR}
            # 导入标准库
            FILES
            ${MODULE_ROOT_PATH}/std.ixx
            ${MODULE_ROOT_PATH}/std.compat.ixx
            ${COMPILER_FILES}
    )
endif ()