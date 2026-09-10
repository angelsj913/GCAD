#include "gcad/engines/zrgp_engine.hpp"

namespace gcad {

ZRGPEngine::ZRGPEngine() : rng_(std::random_device{}()) {
    init_default_banners();
}

ZRGPEngine::~ZRGPEngine() { stop(); }

void ZRGPEngine::init_default_banners() {
    banners_.push_back({22,   "ssh",   "OpenSSH_8.9p1", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"});
    banners_.push_back({21,   "ftp",   "vsftpd 3.0.5",  "220 (vsFTPd 3.0.5)\r\n"});
    banners_.push_back({25,   "smtp",  "Postfix",        "220 mail.example.local ESMTP Postfix\r\n"});
    banners_.push_back({80,   "http",  "Apache/2.4.57",  ""});
    banners_.push_back({443,  "https", "nginx/1.24.0",   ""});
    banners_.push_back({3306, "mysql", "MySQL 8.0.36",   ""});
    banners_.push_back({3389, "rdp",   "Microsoft RDP",  "\x03\x00\x00\x13\x0e\xd0\x00\x00\x12" "4\x00\x02\x01\x08\x00\x02\x00\x00\x00"});
    banners_.push_back({445,  "smb",   "Samba 4.18.6",   ""});
    banners_.push_back({8080, "http-proxy", "Squid/6.6",  ""});
    banners_.push_back({1433, "mssql", "MS SQL 2022",    ""});
    banners_.push_back({5432, "postgresql", "PostgreSQL 16.2", ""});
    banners_.push_back({6379, "redis", "Redis 7.2.4",    "-ERR unknown command\r\n"});
}

ErrorCode ZRGPEngine::start() {
    if (running_.load()) return ErrorCode::OK;
    running_.store(true);
    listener_thread_ = std::thread(&ZRGPEngine::listener_loop, this);
    GCAD_LOG(INFO, "ZRGP engine started with " + std::to_string(banners_.size()) + " honey banners");
    return ErrorCode::OK;
}

ErrorCode ZRGPEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
#ifdef GCAD_PLATFORM_WINDOWS
    for (auto s : listen_sockets_) { closesocket(s); }
#else
    for (auto s : listen_sockets_) { close(s); }
#endif
    listen_sockets_.clear();
    if (listener_thread_.joinable()) listener_thread_.join();
    return ErrorCode::OK;
}

EngineStatus ZRGPEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void ZRGPEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

std::string ZRGPEngine::randomize_version() {
    static const std::vector<std::string> patches = {
        "p1", "p2", "p3", "p4", "p5", "p6", "p7"
    };
    std::uniform_int_distribution<int> major(6, 9);
    std::uniform_int_distribution<int> minor(0, 9);
    std::uniform_int_distribution<size_t> pidx(0, patches.size()-1);
    return std::to_string(major(rng_)) + "." + std::to_string(minor(rng_)) + patches[pidx(rng_)];
}

std::string ZRGPEngine::generate_fake_http_response() {
    std::string body = "<html><head><title>Apache2 Ubuntu Default Page</title></head>"
                       "<body><h1>It works!</h1><p>Server version: Apache/" + randomize_version() +
                       " (Ubuntu)</p></body></html>\r\n";
    return "HTTP/1.1 200 OK\r\n"
           "Server: Apache/" + randomize_version() + " (Ubuntu)\r\n"
           "Content-Type: text/html\r\n"
           "Content-Length: " + std::to_string(body.size()) + "\r\n"
           "X-Powered-By: PHP/" + randomize_version() + "\r\n"
           "Connection: close\r\n\r\n" + body;
}

std::string ZRGPEngine::generate_fake_ssh_banner() {
    static const std::vector<std::string> variants = {
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
        "SSH-2.0-OpenSSH_9.3p1 Debian-1\r\n",
        "SSH-2.0-OpenSSH_8.4p1 Raspbian-5\r\n",
        "SSH-2.0-dropbear_2022.83\r\n",
    };
    std::uniform_int_distribution<size_t> d(0, variants.size()-1);
    return variants[d(rng_)];
}

std::string ZRGPEngine::generate_fake_ftp_banner() {
    return "220 (vsFTPd " + randomize_version() + ")\r\n";
}

std::string ZRGPEngine::generate_fake_smtp_banner() {
    return "220 mail-gw" + std::to_string(std::uniform_int_distribution<int>(1,99)(rng_)) +
           ".example.local ESMTP Postfix (Ubuntu)\r\n";
}

std::string ZRGPEngine::generate_fake_banner(uint16_t port) {
    switch (port) {
        case 22:   return generate_fake_ssh_banner();
        case 21:   return generate_fake_ftp_banner();
        case 25:   return generate_fake_smtp_banner();
        case 80: case 8080: case 443: return generate_fake_http_response();
        default: {
            std::lock_guard lk(mtx_);
            for (auto& b : banners_)
                if (b.port == port && !b.response_template.empty())
                    return b.response_template;
            return "220 Service ready\r\n";
        }
    }
}

void ZRGPEngine::add_delay_jitter() {
    std::uniform_int_distribution<int> d(50, RESPONSE_JITTER_MS);
    std::this_thread::sleep_for(std::chrono::milliseconds(d(rng_)));
}

void ZRGPEngine::listener_loop() {
    for (auto& banner : banners_) {
#ifdef GCAD_PLATFORM_WINDOWS
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) continue;
        int reuse = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(banner.port);
        if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            closesocket(s); continue;
        }
        if (listen(s, 8) != 0) { closesocket(s); continue; }
        u_long mode = 1;
        ioctlsocket(s, FIONBIO, &mode);
        listen_sockets_.push_back(s);
#else
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) continue;
        int reuse = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(banner.port);
        if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            ::close(s); continue;
        }
        if (listen(s, 8) != 0) { ::close(s); continue; }
        fcntl(s, F_SETFL, O_NONBLOCK);
        listen_sockets_.push_back(s);
#endif
        GCAD_LOG(INFO, "ZRGP: honey port " + std::to_string(banner.port) + " (" + banner.service_name + ")");
    }

    while (running_.load()) {
        for (size_t i = 0; i < listen_sockets_.size(); ++i) {
            sockaddr_in client_addr{};
#ifdef GCAD_PLATFORM_WINDOWS
            int addrlen = sizeof(client_addr);
            SOCKET client = accept(listen_sockets_[i], reinterpret_cast<sockaddr*>(&client_addr), &addrlen);
            if (client == INVALID_SOCKET) continue;
#else
            socklen_t addrlen = sizeof(client_addr);
            int client = accept(listen_sockets_[i], reinterpret_cast<sockaddr*>(&client_addr), &addrlen);
            if (client < 0) continue;
#endif
            uint32_t attacker_ip = ntohl(client_addr.sin_addr.s_addr);
            uint16_t port = banners_[i].port;
            auto ip_str = std::string(inet_ntoa(client_addr.sin_addr));

            events_processed_.fetch_add(1);
            emit_threat(ThreatCategory::NETWORK_SCAN,
                "Probe on honey port " + std::to_string(port) + " (" + banners_[i].service_name +
                ") from " + ip_str, ip_str, port);

            {
                std::lock_guard lk(mtx_);
                auto& stats = attacker_stats_[attacker_ip];
                stats.attacker_ip = attacker_ip;
                stats.target_port = port;
                stats.probes_received++;
                if (stats.first_seen == std::chrono::system_clock::time_point{})
                    stats.first_seen = std::chrono::system_clock::now();
                stats.last_seen = std::chrono::system_clock::now();
            }

            add_delay_jitter();
            std::string response = generate_fake_banner(port);
            send(client, response.c_str(), static_cast<int>(response.size()), 0);
            fake_responses_.fetch_add(1);

            char dummy[1024];
            recv(client, dummy, sizeof(dummy), 0);

#ifdef GCAD_PLATFORM_WINDOWS
            closesocket(client);
#else
            ::close(client);
#endif
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void ZRGPEngine::add_honey_port(uint16_t port, std::string_view service) {
    std::lock_guard lk(mtx_);
    banners_.push_back({port, std::string(service), randomize_version(), ""});
}

std::vector<DeceptionStats> ZRGPEngine::get_attacker_stats() const {
    std::lock_guard lk(const_cast<std::mutex&>(mtx_));
    std::vector<DeceptionStats> out;
    out.reserve(attacker_stats_.size());
    for (auto& [_, s] : attacker_stats_) out.push_back(s);
    return out;
}

void ZRGPEngine::emit_threat(ThreatCategory cat, const std::string& desc, const std::string& src_ip, uint16_t port) {
    threats_detected_.fetch_add(1);
    if (threat_cb_) {
        ThreatEvent ev{};
        ev.level = ThreatLevel::MEDIUM;
        ev.category = cat;
        ev.description = desc;
        ev.source_ip = src_ip;
        ev.source_port = port;
        threat_cb_(std::move(ev));
    }
}

} // namespace gcad
