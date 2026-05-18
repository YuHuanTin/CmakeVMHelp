
#ifndef CONFIG_H
#define CONFIG_H


class Config {
public:
    struct ConfigType {
        bool        isDebug            = true;
        size_t      max_trace_num_once = 4000000; // 32bit max
        std::string trace_log_path     = "log.txt";
    };

    static Config &getInstance() {
        static Config instance;
        return instance;
    }

    [[nodiscard]] const ConfigType &getConfig() const {
        return config_;
    }

    Config(const Config &) = delete;

    Config &operator=(const Config &) = delete;

    Config(Config &&) = delete;

    Config &operator=(Config &&) = delete;

private:
    Config();

    ConfigType config_;
};


#endif //CONFIG_H
