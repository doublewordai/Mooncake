# Secure mode (DW-1288): built only with -DWITH_SECURE_KV=ON.

# Each module that links the transfer engine and the store statically
# (engine.so, _store.so) carries its own hidden copy of the secure code
# (SECURE_KV.md, "One copy per module"). Shared libraries would split it
# across libraries, which hidden symbols cannot cross.
if(BUILD_SHARED_LIBS)
  message(FATAL_ERROR "WITH_SECURE_KV needs BUILD_SHARED_LIBS=OFF")
endif()
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

# Data path: KV crypto, the secure transport decorator, the staging pool and
# the secure P->D push. Compiled into transfer_engine (see ../CMakeLists.txt).
add_library(mooncake_secure OBJECT kv_crypto.cpp secure_transport.cpp
                                   staging_pool.cpp secure_push.cpp)
set_target_properties(mooncake_secure PROPERTIES POSITION_INDEPENDENT_CODE ON)
# Device <-> pinned host copies shared by the push and the store client.
target_sources(mooncake_secure PRIVATE device_copy.cpp)
target_include_directories(mooncake_secure
                           PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
target_link_libraries(mooncake_secure PUBLIC glog::glog OpenSSL::Crypto
                                             JsonCpp::JsonCpp)
if(USE_CUDA)
  # Path B of the secure push: device <-> pinned host copies on the copy
  # engine.
  target_link_libraries(mooncake_secure PUBLIC CUDA::cudart)
endif()

# Control plane: HMAC tags and the replay cache, plus the switch and key source
# both halves read (secure_env.cpp); shared with the Store and the master, which
# do not link the data path. See control_auth.h and secure_env.h. The
# handshake framing hook (handshake_auth.cpp) is added to transfer_engine in
# ../CMakeLists.txt, after that target exists.
add_library(mooncake_control_auth STATIC control_auth.cpp secure_env.cpp)
set_target_properties(mooncake_control_auth
                      PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(mooncake_control_auth
                           PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(mooncake_control_auth PUBLIC OpenSSL::Crypto
                                                   glog::glog)

if(BUILD_UNIT_TESTS)
  add_subdirectory(tests)
endif()
