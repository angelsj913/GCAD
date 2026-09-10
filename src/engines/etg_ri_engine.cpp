#include "gcad/engines/etg_ri_engine.hpp"

namespace gcad {

ETGRIEngine::ETGRIEngine() = default;
ETGRIEngine::~ETGRIEngine() { stop(); }

ErrorCode ETGRIEngine::create_raw_socket() {
#ifdef GCAD_PLATFORM_WINDOWS
    raw_socket_ = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (raw_socket_ == INVALID_SOCKET) return ErrorCode::ERR_NET_SOCKET;
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    hostent* local = gethostbyname(hostname);
    if (!local) { closesocket(raw_socket_); raw_socket_ = INVALID_SOCKET; return ErrorCode::ERR_NET_BIND; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    std::memcpy(&addr.sin_addr, local->h_addr_list[0], local->h_length);
    if (bind(raw_socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        closesocket(raw_socket_); raw_socket_ = INVALID_SOCKET; return ErrorCode::ERR_NET_BIND;
    }
    DWORD rcvall = 1;
    DWORD bytes_returned = 0;
    WSAIoctl(raw_socket_, SIO_RCVALL, &rcvall, sizeof(rcvall), nullptr, 0, &bytes_returned, nullptr, nullptr);
#else
    raw_socket_ = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket_ < 0) return ErrorCode::ERR_NET_SOCKET;
    int one = 1;
    setsockopt(raw_socket_, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct timeval tv{};
    tv.tv_sec = 1;
    setsockopt(raw_socket_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    return ErrorCode::OK;
}

void ETGRIEngine::close_raw_socket() {
#ifdef GCAD_PLATFORM_WINDOWS
    if (raw_socket_ != INVALID_SOCKET) { closesocket(raw_socket_); raw_socket_ = INVALID_SOCKET; }
#else
    if (raw_socket_ >= 0) { close(raw_socket_); raw_socket_ = -1; }
#endif
}

ErrorCode ETGRIEngine::start() {
    if (running_.load()) return ErrorCode::OK;
    auto rc = create_raw_socket();
    if (rc != ErrorCode::OK) {
        GCAD_LOG(WARN, "ETG-RI: raw socket failed, running in passive mode");
    }
    running_.store(true);
    capture_thread_ = std::thread(&ETGRIEngine::capture_loop, this);
    GCAD_LOG(INFO, "ETG-RI engine started");
    return ErrorCode::OK;
}

ErrorCode ETGRIEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    close_raw_socket();
    if (capture_thread_.joinable()) capture_thread_.join();
    return ErrorCode::OK;
}

EngineStatus ETGRIEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void ETGRIEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void ETGRIEngine::capture_loop() {
    std::array<uint8_t, 65536> buf{};
    while (running_.load()) {
#ifdef GCAD_PLATFORM_WINDOWS
        if (raw_socket_ == INVALID_SOCKET) { std::this_thread::sleep_for(std::chrono::seconds(1)); continue; }
        int len = recv(raw_socket_, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
        if (len <= 0) { std::this_thread::sleep_for(std::chrono::milliseconds(10)); continue; }
#else
        if (raw_socket_ < 0) { std::this_thread::sleep_for(std::chrono::seconds(1)); continue; }
        ssize_t len = recv(raw_socket_, buf.data(), buf.size(), 0);
        if (len <= 0) { std::this_thread::sleep_for(std::chrono::milliseconds(10)); continue; }
#endif
        packets_captured_.fetch_add(1);
        analyze_packet(buf.data(), static_cast<size_t>(len));
    }
}

void ETGRIEngine::analyze_packet(const uint8_t* data, size_t len) {
    if (len < 20) return;

    uint8_t version = (data[0] >> 4) & 0x0F;
    if (version != 4) return;

    uint8_t ihl = (data[0] & 0x0F) * 4;
    if (ihl > len) return;

    uint32_t src_ip = (uint32_t(data[12])<<24)|(uint32_t(data[13])<<16)|(uint32_t(data[14])<<8)|data[15];
    uint32_t dst_ip = (uint32_t(data[16])<<24)|(uint32_t(data[17])<<16)|(uint32_t(data[18])<<8)|data[19];
    uint8_t  proto  = data[9];

    if (is_blocked(src_ip)) return;

    uint16_t sp = 0, dp = 0;
    const uint8_t* payload = data + ihl;
    size_t plen = len - ihl;

    if (proto == 6 && plen >= 4) { sp = (payload[0]<<8)|payload[1]; dp = (payload[2]<<8)|payload[3]; }
    else if (proto == 17 && plen >= 4) { sp = (payload[0]<<8)|payload[1]; dp = (payload[2]<<8)|payload[3]; }

    auto stats = compute_stats(payload, plen, src_ip, dst_ip, sp, dp, proto);
    events_processed_.fetch_add(1);

    {
        std::lock_guard lk(mtx_);
        sliding_window_.push_back(stats);
        if (sliding_window_.size() > WINDOW_SIZE)
            sliding_window_.erase(sliding_window_.begin());
    }

    auto ip_str = [](uint32_t ip) {
        return std::to_string((ip>>24)&0xFF) + "." + std::to_string((ip>>16)&0xFF) + "." +
               std::to_string((ip>>8)&0xFF)  + "." + std::to_string(ip&0xFF);
    };

    if (stats.shannon_entropy > ENTROPY_THRESH_HIGH && plen > 100) {
        emit_threat(ThreatCategory::ENTROPY_ANOMALY,
            "High entropy payload (" + std::format("{:.2f}", stats.shannon_entropy) +
            " bits) from " + ip_str(src_ip) + ":" + std::to_string(sp),
            ip_str(src_ip), sp);
    }

    if (stats.shannon_entropy < ENTROPY_THRESH_LOW && plen > 200) {
        emit_threat(ThreatCategory::ENTROPY_ANOMALY,
            "Suspiciously low entropy (" + std::format("{:.2f}", stats.shannon_entropy) +
            ") — possible structured attack from " + ip_str(src_ip),
            ip_str(src_ip), sp);
    }

    if (stats.chi_squared > CHI2_THRESH && plen > 64) {
        emit_threat(ThreatCategory::RAW_SOCKET_PROBE,
            "Chi-squared anomaly (" + std::format("{:.1f}", stats.chi_squared) +
            ") from " + ip_str(src_ip),
            ip_str(src_ip), sp);
    }

    if (is_flood(src_ip)) {
        emit_threat(ThreatCategory::SYN_FLOOD,
            "Flood detected from " + ip_str(src_ip) + " (" + std::to_string(FLOOD_THRESH) + "+ pkts/s)",
            ip_str(src_ip), sp);
        block_ip(src_ip);
    }
}

PacketStats ETGRIEngine::compute_stats(const uint8_t* payload, size_t len,
                                        uint32_t src, uint32_t dst,
                                        uint16_t sp, uint16_t dp, uint8_t proto) {
    PacketStats s{};
    s.shannon_entropy = shannon_entropy(payload, len);
    s.chi_squared = chi_squared(payload, len);
    s.src_ip = src; s.dst_ip = dst;
    s.src_port = sp; s.dst_port = dp;
    s.protocol = proto;
    s.payload_len = len;
    s.timestamp = std::chrono::steady_clock::now();
    return s;
}

bool ETGRIEngine::is_flood(uint32_t src_ip) {
    std::lock_guard lk(mtx_);
    auto now = std::chrono::steady_clock::now();
    auto& times = conn_tracker_[src_ip];
    times.push_back(now);
    while (!times.empty() && (now - times.front()) > FLOOD_WINDOW)
        times.erase(times.begin());
    return times.size() > FLOOD_THRESH;
}

bool ETGRIEngine::is_blocked(uint32_t ip) const {
    std::lock_guard lk(const_cast<std::mutex&>(mtx_));
    return std::find(blocked_ips_.begin(), blocked_ips_.end(), ip) != blocked_ips_.end();
}

void ETGRIEngine::block_ip(uint32_t ip) {
    std::lock_guard lk(mtx_);
    if (std::find(blocked_ips_.begin(), blocked_ips_.end(), ip) == blocked_ips_.end())
        blocked_ips_.push_back(ip);
}

void ETGRIEngine::unblock_ip(uint32_t ip) {
    std::lock_guard lk(mtx_);
    blocked_ips_.erase(std::remove(blocked_ips_.begin(), blocked_ips_.end(), ip), blocked_ips_.end());
}

std::vector<PacketStats> ETGRIEngine::recent_packets(size_t n) const {
    std::lock_guard lk(const_cast<std::mutex&>(mtx_));
    size_t start = sliding_window_.size() > n ? sliding_window_.size() - n : 0;
    return {sliding_window_.begin() + start, sliding_window_.end()};
}

std::vector<uint32_t> ETGRIEngine::get_blocked_ips() const {
    std::lock_guard lk(const_cast<std::mutex&>(mtx_));
    return blocked_ips_;
}

void ETGRIEngine::emit_threat(ThreatCategory cat, const std::string& desc, const std::string& src_ip_str, uint16_t port) {
    threats_detected_.fetch_add(1);
    if (threat_cb_) {
        ThreatEvent ev{};
        ev.level = ThreatLevel::HIGH;
        ev.category = cat;
        ev.description = desc;
        ev.source_ip = src_ip_str;
        ev.source_port = port;
        threat_cb_(std::move(ev));
    }
}

} // namespace gcad
