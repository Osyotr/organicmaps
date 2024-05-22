set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE static)
set(VCPKG_LIBRARY_LINKAGE static)

# New MSVC versions are ABI-compatible with previous versions.
# No need to rebuild packages after update.
set(VCPKG_DISABLE_COMPILER_TRACKING ON)
