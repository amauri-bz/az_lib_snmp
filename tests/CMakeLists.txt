
set(DOCTEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../external/)

add_executable(az_snmp_tests az_snmp_protocol_test.cpp)

target_include_directories(az_snmp_tests PUBLIC ${DOCTEST_INCLUDE_DIR})

enable_testing()
add_test(NAME run_snmp_tests COMMAND az_snmp_tests)
