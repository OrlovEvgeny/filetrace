add_executable(ft_unit_tests
    unit/main.c
    unit/test_format.c
    unit/test_model.c
    unit/test_table.c
    unit/test_state.c
    unit/test_agent.c
    unit/test_config.c
    unit/test_views.c
)
target_link_libraries(ft_unit_tests PRIVATE ft_cli)
target_include_directories(ft_unit_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME unit COMMAND ft_unit_tests)
set_tests_properties(unit PROPERTIES TIMEOUT 60)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ft_workload integration/workload.c)
    target_link_libraries(ft_workload PRIVATE ft_build)
    foreach(probes auto kprobe)
        add_test(NAME integration-${probes}
            COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/integration/run.sh $<TARGET_FILE_DIR:filetrace>
                    $<TARGET_FILE:ft_workload> ${probes})
        set_tests_properties(integration-${probes} PROPERTIES
            SKIP_RETURN_CODE 77 TIMEOUT 120 RUN_SERIAL TRUE)
    endforeach()
endif()
