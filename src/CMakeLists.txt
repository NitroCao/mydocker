find_package(CLI11 REQUIRED)
find_package(spdlog REQUIRED)

add_executable(mydocker main.cc app.cc app.h
        run.cc
        run.h)
target_link_libraries(mydocker PRIVATE spdlog::spdlog_header_only CLI11::CLI11)
