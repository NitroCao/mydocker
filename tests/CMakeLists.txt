find_package(GTest CONFIG REQUIRED)
include(GoogleTest)

include_directories(${PROJECT_SOURCE_DIR}/src)

file(GLOB TEST_SOURCES *_test.cc)
foreach(TEST_SRC ${TEST_SOURCES})
    get_filename_component(TEST_SRC_EXENAME ${TEST_SRC} NAME_WE)
    string(REPLACE "_test" ".cc" TEST_DEP_SOURCE ${TEST_SRC_EXENAME})
    add_executable(${TEST_SRC_EXENAME} ${TEST_SRC} ${PROJECT_SOURCE_DIR}/src/${TEST_DEP_SOURCE})
    target_link_libraries(${TEST_SRC_EXENAME} PRIVATE GTest::gmock GTest::gtest GTest::gmock_main GTest::gtest_main)
    gtest_discover_tests(${TEST_SRC_EXENAME})
endforeach()

