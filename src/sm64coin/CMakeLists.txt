# SM64COIN: proof-of-play. Builds the Rust crate pow/sm64pow (all consensus
# rules live there) and wraps it for the daemon. See sm64coin.h.

set(SM64POW_DIR "${CMAKE_SOURCE_DIR}/../pow" CACHE PATH "Path to the sm64coin Rust workspace")
set(SM64POW_LIB "${SM64POW_DIR}/target/release/libsm64pow.a")

# SM64COIN: every source of the crate and its perturbation crate triggers a rebuild (a stale
# library once linked an old codec into the daemon).
file(GLOB SM64POW_SOURCES CONFIGURE_DEPENDS "${SM64POW_DIR}/sm64pow/src/*.rs" "${SM64POW_DIR}/perturb/src/*.rs" "${SM64POW_DIR}/statecodec/src/*.rs" "${SM64POW_DIR}/sm64pow/Cargo.toml")

add_custom_command(
  OUTPUT "${SM64POW_LIB}"
  COMMAND cargo build --release -p sm64pow
  WORKING_DIRECTORY "${SM64POW_DIR}"
  DEPENDS ${SM64POW_SOURCES}
  COMMENT "Building the sm64pow Rust crate"
  VERBATIM)
add_custom_target(sm64pow_rust DEPENDS "${SM64POW_LIB}")

add_library(sm64pow STATIC IMPORTED GLOBAL)
set_target_properties(sm64pow PROPERTIES IMPORTED_LOCATION "${SM64POW_LIB}")
add_dependencies(sm64pow sm64pow_rust)

include_directories("${SM64POW_DIR}/sm64pow")
monero_add_library(sm64coin sm64coin.cpp sm64coin.h)
add_dependencies(sm64coin sm64pow_rust)
target_link_libraries(sm64coin
  PUBLIC
    cncrypto
    sm64pow)
# Platform libraries of the Rust static library (std, wasmer, getrandom ...).
if(WIN32)
  target_link_libraries(sm64coin PUBLIC ws2_32 userenv bcrypt ntdll advapi32 kernel32 shell32 ole32 psapi dbghelp synchronization)
elseif(APPLE)
  target_link_libraries(sm64coin PUBLIC "-framework CoreFoundation" "-framework Security" iconv resolv pthread m dl)
else()
  target_link_libraries(sm64coin PUBLIC gcc_s util rt pthread m dl)
endif()
