file(GLOB SOURCES *.cc)

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} CLI11::CLI11 nlohmann_json nlohmann_json::nlohmann_json)
