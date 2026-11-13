# arm64-windows-static-md with the release optimization level forced to /O1.
#
# MSVC ARM64 miscompiles OpenSSL when it is built at /O2 /Gs0 (OpenSSL's own
# VC-WIN64-* configs add /Gs0): the prologue of tls_parse_all_extensions calls
# __chkstk before spilling x30, so the function returns into its own prologue
# and OrcaSlicer crashes during the Bambu cloud MQTT login
# (persano/open-bambu-networking-plugin#10, openssl/openssl#26239).
# Rebuilding OpenSSL at /O1 (with /Gs0 unchanged) produces a correct prologue.
#
# vcpkg appends this after its default "/O2 /Oi /Gy /DNDEBUG /Z7", and cl takes
# the last /O option, so /O1 wins. The whole triplet's release build runs at
# /O1 (plugin code included); that is the accepted cost of a working arm64 TLS.
set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
# vcpkg rejects C-flags-only: VCPKG_CXX_FLAGS_RELEASE must be set too.
set(VCPKG_C_FLAGS_RELEASE "/O1 /Ob2 /DNDEBUG")
set(VCPKG_CXX_FLAGS_RELEASE "/O1 /Ob2 /DNDEBUG")
