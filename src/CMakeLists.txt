find_package(CLI11 REQUIRED)
find_package(spdlog REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(mydocker main.cc app.cc app.h
        run.cc
        run.h
        spec.h
        spec_app.cc)
target_link_libraries(mydocker PRIVATE spdlog::spdlog_header_only CLI11::CLI11 nlohmann_json::nlohmann_json)
