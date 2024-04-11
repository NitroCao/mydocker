include(GoogleTest)
find_package(GTest CONFIG REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/src)

add_executable(spec_test spec_test.cc)
target_link_libraries(spec_test PRIVATE GTest::gtest GTest::gtest_main GTest::gmock GTest::gmock_main)

gtest_discover_tests(spec_test)