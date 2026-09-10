#pragma once
#include "../common.hpp"

namespace gcad {

struct Signature {
    std::string              name;
    ThreatLevel              level;
    ThreatCategory           category;
    std::vector<uint8_t>     pattern;
    std::vector<uint8_t>     mask;
    int32_t                  offset{-1};
    std::string              description;
};

class SignatureDB {
    std::vector<Signature>     signatures_;
    mutable std::shared_mutex  mtx_;

    void load_builtin_signatures();

public:
    SignatureDB();

    void add(Signature sig);
    void load_from_file(const std::filesystem::path& path);
    size_t size() const;

    struct MatchResult {
        const Signature* sig;
        size_t           offset;
    };

    std::optional<MatchResult> scan(const uint8_t* data, size_t len) const;
    std::vector<MatchResult>   scan_all(const uint8_t* data, size_t len) const;
};

} // namespace gcad
