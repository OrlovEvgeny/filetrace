add_executable(ft_unit_tests
    unit/main.c
    unit/test_format.c
    unit/test_model.c
    unit/test_table.c
    unit/test_state.c
    unit/test_daemon.c
    unit/test_views.c
)
target_link_libraries(ft_unit_tests PRIVATE ft_cli)
target_include_directories(ft_unit_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME unit COMMAND ft_unit_tests)
set_tests_properties(unit PROPERTIES TIMEOUT 60)
