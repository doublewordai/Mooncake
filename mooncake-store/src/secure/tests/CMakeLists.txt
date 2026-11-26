add_executable(rpc_auth_test ${CMAKE_CURRENT_SOURCE_DIR}/rpc_auth_test.cpp)
target_include_directories(rpc_auth_test
                           PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../tests)
target_link_libraries(
  rpc_auth_test
  PUBLIC mooncake_store
         transfer_engine
         cachelib_memory_allocator
         ${ETCD_WRAPPER_LIB}
         glog::glog
         ibverbs
         gtest
         gtest_main
         pthread)
add_test(NAME rpc_auth_test COMMAND rpc_auth_test)
