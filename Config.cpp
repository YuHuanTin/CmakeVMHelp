#include "Config.h"

#include <nlohmann/json.hpp>

Config::Config() {
    if (!std::filesystem::exists("../VMHelp.json")) {
        std::fstream file;
        file.open("../VMHelp.json", std::ios::out);

        nlohmann::json config;
        config["isDebug"]            = config_.isDebug;
        config["max_trace_num_once"] = config_.max_trace_num_once;
        config["trace_log_path"]     = config_.trace_log_path;
        file << config.dump(4);
        file.close();
    }

    std::fstream file;
    file.open("../VMHelp.json", std::ios::in);

    nlohmann::json config;
    file >> config;
    config_.isDebug            = config["isDebug"];
    config_.max_trace_num_once = config["max_trace_num_once"];
    config_.trace_log_path     = config["trace_log_path"];
    file.close();
}
