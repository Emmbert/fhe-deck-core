find_package(GTest REQUIRED)

add_executable(mul_engine_test test_main.cpp mul_engine_test.cpp)
target_link_libraries(mul_engine_test PRIVATE fhe_deck GTest::gtest)
target_include_directories(mul_engine_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_test(NAME mul_engine_test COMMAND mul_engine_test)

add_executable(bench_ntt_engines bench_ntt_engines.cpp)
target_link_libraries(bench_ntt_engines PRIVATE fhe_deck)

if(NTT_ENGINE STREQUAL "Hexl")
    add_executable(cross_check_hexl cross_check_hexl.cpp)
    target_link_libraries(cross_check_hexl PRIVATE fhe_deck)
endif()