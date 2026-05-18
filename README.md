# 编译

## 工具链

llvm-mingw

## 依赖

使用 vcpkg 管理依赖

- 如果使用 msvc 工具链编译依赖，则不用改动

- 如果需要使用 llvm-mingw 工具链编译依赖，则将 [.vcpkg-configuration.json](.vcpkg-configuration.json) 重命名为
  `vcpkg-configuration.json` 并解除
  ```cmake
  set(VCPKG_HOST_TRIPLET "x64-mingw-static")
  set(VCPKG_TARGET_TRIPLET "x64-mingw-static")
  ```

## 设置项

- XDBG_SDK_PATH 将该选项设置为 xdbg 目录下的 pluginsdk 目录