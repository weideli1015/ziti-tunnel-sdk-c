project(tests)

add_executable(ziti-edge-tunnel-test ziti-edge-tunnel-test.c)
set_property(TARGET ziti-edge-tunnel-test PROPERTY C_STANDARD 11)

target_link_libraries(ziti-edge-tunnel-test
        PUBLIC ${tunnel_libuv_lib}
        )

install(TARGETS ziti-edge-tunnel-test
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        )