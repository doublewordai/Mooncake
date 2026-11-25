# Secure mode (DW-1288): built only with -DWITH_SECURE_KV=ON.

# Data path: KV crypto, the secure transport decorator, the staging pool and
# the secure P->D push. Compiled into transfer_engine (see ../CMakeLists.txt).
add_library(mooncake_secure OBJECT kv_crypto.cpp secure_transport.cpp
                                   staging_pool.cpp secure_push.cpp)
set_target_properties(mooncake_secure PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(mooncake_secure
                           PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
target_link_libraries(mooncake_secure PUBLIC glog::glog OpenSSL::Crypto
                                             JsonCpp::JsonCpp)
if(USE_CUDA)
  # Path B of the secure push: device <-> pinned host copies on the copy
  # engine.
  target_link_libraries(mooncake_secure PUBLIC CUDA::cudart)
endif()

# Control plane: key loading, HMAC tags and the replay cache; shared with the
# Store. See control_auth.h. The handshake framing hook (handshake_auth.cpp)
# is added to transfer_engine in ../CMakeLists.txt, after that target exists.
add_library(mooncake_control_auth STATIC control_auth.cpp)
set_target_properties(mooncake_control_auth
                      PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(mooncake_control_auth
                           PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(mooncake_control_auth PUBLIC OpenSSL::Crypto
                                                   glog::glog)

if(BUILD_UNIT_TESTS)
  add_subdirectory(tests)
endif()
