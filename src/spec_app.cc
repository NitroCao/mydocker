#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "spec.h"
#include "spec_app.h"

using json = nlohmann::json;

std::function<void()> SpecApp::spec_callback(const SpecApp::spec_args &arg) {
    return [&]() {
        auto spec_filename = std::filesystem::path(arg.bundle) / spec::spec_config;
        if (std::filesystem::exists(spec_filename)) {
            spdlog::error("File {} exists. Remove it first", spec::spec_config);
            exit(EXIT_FAILURE);
        }

        std::ofstream spec_file(spec_filename);
        if (!spec_file.is_open()) {
            spdlog::error("Failed to create file");
            exit(EXIT_FAILURE);
        }
        spec::Spec default_spec{};
        json json_spec = default_spec;
        spec_file << json_spec.dump(1, '\t');
    };
}
