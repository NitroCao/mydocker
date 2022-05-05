find_package(GTest CONFIG REQUIRED)
include(GoogleTest)

include_directories(${PROJECT_SOURCE_DIR}/src)

file(GLOB TEST_SOURCES *_test.cc)
foreach(TEST_SRC ${TEST_SOURCES})
    set(TEST_DEP_SOURCES "")
    get_filename_component(TEST_SRC_EXENAME ${TEST_SRC} NAME_WE)

    string(REPLACE "_test" ".cc" TEST_DEP_SOURCE ${TEST_SRC_EXENAME})
    if(EXISTS ${PROJECT_SOURCE_DIR}/src/${TEST_DEP_SOURCE})
        list(APPEND TEST_DEP_SOURCES ${PROJECT_SOURCE_DIR}/src/${TEST_DEP_SOURCE})
    endif()

    add_executable(${TEST_SRC_EXENAME} ${TEST_SRC} ${TEST_DEP_SOURCES})
    target_link_libraries(${TEST_SRC_EXENAME} PRIVATE GTest::gmock GTest::gtest GTest::gmock_main GTest::gtest_main)
    gtest_discover_tests(${TEST_SRC_EXENAME})
endforeach()

