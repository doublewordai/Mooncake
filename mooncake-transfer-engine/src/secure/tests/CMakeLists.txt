foreach(name control_auth_test handshake_auth_test)
  add_executable(${name} ${CMAKE_CURRENT_SOURCE_DIR}/${name}.cpp)
  target_link_libraries(${name} PUBLIC transfer_engine mooncake_control_auth
                                       gtest gtest_main)
  add_test(NAME ${name} COMMAND ${name})
endforeach()
