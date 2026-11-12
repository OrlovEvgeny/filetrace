add_executable(ft_unit_tests
    unit/main.c
    unit/test_format.c
    unit/test_grpc.c
    unit/test_model.c
    unit/test_otlp.c
    unit/test_process.c
    unit/test_scripts.c
    unit/test_table.c
    unit/test_state.c
    unit/test_agent.c
    unit/test_config.c
    unit/test_metrics.c
    unit/test_views.c
    unit/test_leaders.c
    unit/test_top_model.c
    unit/test_top_filter.c
    unit/test_tui.c
    unit/test_top_source.c
)
target_link_libraries(ft_unit_tests PRIVATE ft_cli)
set_property(SOURCE unit/test_agent.c unit/test_otlp.c
    APPEND PROPERTY COMPILE_DEFINITIONS FT_VERSION="${FT_VERSION_STRING}")
target_include_directories(ft_unit_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME unit COMMAND ft_unit_tests)
set_tests_properties(unit PROPERTIES TIMEOUT 60)

# The agent with made-up traffic in place of a kernel backend, for trying the
# commands on any system.
add_executable(ft_sim_agent sim/sim_agent.c sim/sim_backend.c)
target_link_libraries(ft_sim_agent PRIVATE ft_agent)
target_include_directories(ft_sim_agent PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ft_workload integration/workload.c)
    target_link_libraries(ft_workload PRIVATE ft_build)
    # A dynamic loader reads the C library just before the workload sends, and
    # on x86-64 it reads enough for the agent to count it as the source.
    if(NOT FILETRACE_STATIC AND NOT FILETRACE_SANITIZE)
        target_link_options(ft_workload PRIVATE -static)
    endif()
    foreach(probes auto kprobe)
        add_test(NAME integration-${probes}
            COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/integration/run.sh $<TARGET_FILE_DIR:filetrace>
                    $<TARGET_FILE:ft_workload> ${probes})
        set_tests_properties(integration-${probes} PROPERTIES
            SKIP_RETURN_CODE 77 TIMEOUT 120 RUN_SERIAL TRUE)
    endforeach()
endif()

add_test(NAME cli-help
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/cli/help_test.sh
            $<TARGET_FILE:filetrace> $<TARGET_FILE:filetrace-agent>)
set_tests_properties(cli-help PROPERTIES TIMEOUT 60)

add_test(NAME cli-arguments
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/cli/arguments_test.sh $<TARGET_FILE:filetrace>)
set_tests_properties(cli-arguments PROPERTIES TIMEOUT 60)

add_test(NAME cli-fallback
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/cli/fallback_test.sh $<TARGET_FILE:filetrace>)
set_tests_properties(cli-fallback PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 60)

add_test(NAME site-worker COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/site/worker_test.sh)
set_tests_properties(site-worker PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 60)

add_test(NAME release-version
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/release/version_test.sh
            ${CMAKE_SOURCE_DIR}/tools/release/version.sh)
set_tests_properties(release-version PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 60)

add_test(NAME release-formula
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/release/formula_test.sh
            ${CMAKE_SOURCE_DIR}/tools/release/formula.sh)
set_tests_properties(release-formula PROPERTIES TIMEOUT 60)
