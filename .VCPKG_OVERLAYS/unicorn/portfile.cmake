vcpkg_from_github(
        OUT_SOURCE_PATH SOURCE_PATH
        REPO unicorn-engine/unicorn
        REF "${VERSION}"
        SHA512 c9ae4230a20b77e0187cde33dbf4827b3504b6c24debd61fc79ec9c13fa2051335c834c101433cebbbc8e3baadae56212b79c5922bf37ea1f777d66d8e67b495
        HEAD_REF master
        PATCHES
        fix-build.patch
        fix-msvc-shared.patch
)

if (VCPKG_TARGET_IS_ANDROID)
    vcpkg_replace_string("${SOURCE_PATH}/CMakeLists.txt"
            "-lpthread"
            " "
    )
endif ()

if (VCPKG_TARGET_IS_WINDOWS)
    vcpkg_replace_string("${SOURCE_PATH}/CMakeLists.txt"
            "-lpthread -lm"
            " "
    )
    vcpkg_acquire_msys(MSYS_ROOT PACKAGES)
    vcpkg_add_to_path("${MSYS_ROOT}/usr/bin")
    vcpkg_replace_string("${SOURCE_PATH}/cmake/bundle_static.cmake"
            [=[COMMAND ${CMAKE_COMMAND} -E create_symlink "$<TARGET_FILE_NAME:${bundled_tgt_name}>" "$<TARGET_FILE_DIR:${bundled_tgt_name}>/$<TARGET_PROPERTY:${bundled_tgt_name},SYMLINK_NAME>"]=]
            [=[COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:${bundled_tgt_name}>" "$<TARGET_FILE_DIR:${bundled_tgt_name}>/$<TARGET_PROPERTY:${bundled_tgt_name},SYMLINK_NAME>"]=]
    )
endif ()

vcpkg_cmake_configure(
        SOURCE_PATH "${SOURCE_PATH}"
        OPTIONS
        -DUNICORN_BUILD_TESTS=OFF
        "-DCMAKE_C_FLAGS=-DCONFIG_INT128"
)

vcpkg_cmake_install()
vcpkg_fixup_pkgconfig()
vcpkg_copy_pdbs()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/share")

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/COPYING")
