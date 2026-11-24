# Secure-mode authentication of coro_rpc requests. Built only with
# WITH_SECURE_KV; see rpc_auth.h.
add_library(mooncake_store_secure STATIC rpc_auth.cpp)
set_target_properties(mooncake_store_secure
                      PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(mooncake_store_secure
                           PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(
  mooncake_store_secure PUBLIC mooncake_control_auth glog::glog
                               yalantinglibs::yalantinglibs)

foreach(target mooncake_store_shared_objects mooncake_store_master_objects
               mooncake_store_client_objects)
  target_link_libraries(${target} PRIVATE mooncake_store_secure)
endforeach()
# PUBLIC: code that instantiates the seams (rpc_registrar.h) links it too.
target_link_libraries(mooncake_store_master PUBLIC mooncake_store_secure)
target_link_libraries(mooncake_store PUBLIC mooncake_store_secure)

if(BUILD_UNIT_TESTS)
  add_subdirectory(tests)
endif()
