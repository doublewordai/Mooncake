# Control-plane authentication (secure mode). Built only with WITH_SECURE_KV;
# see control_auth.h.
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# Key loading, HMAC tags and the replay cache; shared with the Store.
add_library(mooncake_control_auth STATIC control_auth.cpp)
set_target_properties(mooncake_control_auth
                      PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(mooncake_control_auth
                           PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(mooncake_control_auth PUBLIC OpenSSL::Crypto
                                                   glog::glog)

# The handshake framing hook (installed from TransferMetadata's constructor).
target_sources(transfer_engine
               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/handshake_auth.cpp)
target_link_libraries(transfer_engine PUBLIC mooncake_control_auth)

if(BUILD_UNIT_TESTS)
  add_subdirectory(tests)
endif()
