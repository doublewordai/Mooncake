# Secure mode (DW-1288): built only with -DWITH_SECURE_KV=ON.
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
