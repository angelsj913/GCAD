#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <memory>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <chrono>
#include <functional>
#include <optional>
#include <variant>
#include <span>
#include <format>
#include <thread>
#include <condition_variable>
#include <queue>
#include <unordered_map>
#include <random>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <cassert>

#ifdef _WIN32
  #define GCAD_PLATFORM_WINDOWS 1
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <windows.h>
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #ifdef _MSC_VER
    #pragma comment(lib, "ws2_32.lib")
  #endif
#else
  #define GCAD_PLATFORM_LINUX 1
  #include <unistd.h>
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netinet/ip.h>
  #include <netinet/tcp.h>
  #include <netinet/udp.h>
  #include <netinet/ip_icmp.h>
  #include <net/if.h>
  #include <poll.h>
  #include <signal.h>
  #include <fcntl.h>
  #include <errno.h>
#endif

namespace gcad {

inline constexpr std::string_view VERSION = "1.0.0";
inline constexpr std::string_view PRODUCT_NAME = "GCAD";

enum class ErrorCode : uint32_t {
    OK                  = 0x0000,
    ERR_NOMEM           = 0x0001,
    ERR_INIT_FAIL       = 0x0002,
    ERR_ENGINE_START    = 0x0010,
    ERR_ENGINE_STOP     = 0x0011,
    ERR_SCAN_IO         = 0x0020,
    ERR_SCAN_ACCESS     = 0x0021,
    ERR_SCAN_CORRUPT    = 0x0022,
    ERR_NET_SOCKET      = 0x0030,
    ERR_NET_BIND        = 0x0031,
    ERR_NET_RECV        = 0x0032,
    ERR_CRYPTO_HASH     = 0x0040,
    ERR_QUARANTINE_FULL = 0x0050,
    ERR_ROLLBACK_FAIL   = 0x0051,
    ERR_NOT_FOUND          = 0x0052,
    ERR_INVALID_TRANSITION = 0x0053,
    ERR_QUARANTINE_DENIED  = 0x0054,
    ERR_PLATFORM        = 0x0060,
    ERR_SELF_DEFENSE    = 0x0070,
};

enum class ThreatLevel : uint8_t {
    SAFE     = 0,
    LOW      = 1,
    MEDIUM   = 2,
    HIGH     = 3,
    CRITICAL = 4,
};

enum class ThreatCategory : uint16_t {
    NONE              = 0x0000,
    MEMORY_INJECTION  = 0x0100,
    PROCESS_HOLLOW    = 0x0101,
    DLL_INJECTION     = 0x0102,
    APC_INJECTION     = 0x0103,
    REFLECTIVE_LOAD   = 0x0104,
    SHELLCODE         = 0x0105,
    NETWORK_SCAN      = 0x0200,
    SYN_FLOOD         = 0x0201,
    UDP_FLOOD         = 0x0202,
    DNS_TUNNEL        = 0x0203,
    ARP_POISON        = 0x0204,
    ICMP_COVERT       = 0x0205,
    RAW_SOCKET_PROBE  = 0x0206,
    RANSOMWARE        = 0x0300,
    FILE_ENCRYPT      = 0x0301,
    REGISTRY_TAMPER   = 0x0302,
    BACKDOOR_ACCOUNT  = 0x0303,
    EVASION_AMSI      = 0x0400,
    EVASION_ETW       = 0x0401,
    EVASION_UNHOOK    = 0x0402,
    DIRECT_SYSCALL    = 0x0403,
    PPID_SPOOF        = 0x0404,
    KERBEROS_ATTACK   = 0x0500,
    NTLM_COERCE       = 0x0501,
    CREDENTIAL_DUMP   = 0x0502,
    ENTROPY_ANOMALY   = 0x0600,
    SUSPICIOUS_BINARY = 0x0700,
    FILELESS_EXEC     = 0x0800,
    ANTI_FORENSIC     = 0x0900,
};

struct ThreatEvent {
    uint64_t                            id{0};
    std::chrono::system_clock::time_point timestamp{};
    ThreatLevel                         level{ThreatLevel::SAFE};
    ThreatCategory                      category{ThreatCategory::NONE};
    uint32_t                            process_id{0};
    std::string                         process_name;
    std::string                         file_path;
    std::string                         description;
    std::string                         source_ip;
    uint16_t                            source_port{0};
    bool                                quarantined{false};
    bool                                rolled_back{false};
};

struct ScanResult {
    std::string                         file_path;
    ThreatLevel                         level{ThreatLevel::SAFE};
    ThreatCategory                      category{ThreatCategory::NONE};
    std::string                         signature_name;
    double                              entropy{0.0};
    std::vector<uint8_t>                matched_bytes;
    std::string                         description;
};

struct EngineStatus {
    std::string   name;
    bool          running{false};
    uint64_t      events_processed{0};
    uint64_t      threats_detected{0};
    double        cpu_percent{0.0};
    size_t        memory_bytes{0};
};

class SpinLock {
    std::atomic_flag flag_ = ATOMIC_FLAG_INIT;
public:
    void lock() noexcept {
        while (flag_.test_and_set(std::memory_order_acquire))
            flag_.wait(true, std::memory_order_relaxed);
    }
    void unlock() noexcept {
        flag_.clear(std::memory_order_release);
        flag_.notify_one();
    }
};

inline void secure_zero(void* ptr, size_t len) noexcept {
    if (!ptr || len == 0) return;
#ifdef _WIN32
    SecureZeroMemory(ptr, len);
#else
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len--) *p++ = 0;
    std::atomic_signal_fence(std::memory_order_seq_cst);
#endif
}

inline double shannon_entropy(const uint8_t* data, size_t len) noexcept {
    if (!data || len == 0) return 0.0;
    std::array<uint64_t, 256> freq{};
    for (size_t i = 0; i < len; ++i)
        ++freq[data[i]];
    double ent = 0.0;
    const double n = static_cast<double>(len);
    for (auto f : freq) {
        if (f == 0) continue;
        double p = static_cast<double>(f) / n;
        ent -= p * std::log2(p);
    }
    return ent;
}

inline double chi_squared(const uint8_t* data, size_t len) noexcept {
    if (!data || len == 0) return 0.0;
    std::array<uint64_t, 256> freq{};
    for (size_t i = 0; i < len; ++i)
        ++freq[data[i]];
    double expected = static_cast<double>(len) / 256.0;
    double chi2 = 0.0;
    for (auto f : freq) {
        double diff = static_cast<double>(f) - expected;
        chi2 += (diff * diff) / expected;
    }
    return chi2;
}

class SHA256 {
    uint32_t state_[8]{};
    uint8_t  buffer_[64]{};
    uint64_t bitcount_{0};
    size_t   buflen_{0};

    static constexpr std::array<uint32_t, 64> K = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    static uint32_t rotr(uint32_t x, unsigned n) noexcept { return (x >> n) | (x << (32 - n)); }
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) noexcept { return (x & y) ^ (~x & z); }
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) noexcept { return (x & y) ^ (x & z) ^ (y & z); }
    static uint32_t ep0(uint32_t x) noexcept { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static uint32_t ep1(uint32_t x) noexcept { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static uint32_t sig0(uint32_t x) noexcept { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static uint32_t sig1(uint32_t x) noexcept { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    void transform(const uint8_t block[64]) noexcept {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(block[i*4])<<24)|(uint32_t(block[i*4+1])<<16)|
                   (uint32_t(block[i*4+2])<<8)|uint32_t(block[i*4+3]);
        for (int i = 16; i < 64; ++i)
            w[i] = sig1(w[i-2]) + w[i-7] + sig0(w[i-15]) + w[i-16];
        uint32_t a=state_[0],b=state_[1],c=state_[2],d=state_[3],
                 e=state_[4],f=state_[5],g=state_[6],h=state_[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + ep1(e) + ch(e,f,g) + K[i] + w[i];
            uint32_t t2 = ep0(a) + maj(a,b,c);
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        state_[0]+=a; state_[1]+=b; state_[2]+=c; state_[3]+=d;
        state_[4]+=e; state_[5]+=f; state_[6]+=g; state_[7]+=h;
    }

public:
    SHA256() { reset(); }

    void reset() noexcept {
        state_[0]=0x6a09e667; state_[1]=0xbb67ae85; state_[2]=0x3c6ef372; state_[3]=0xa54ff53a;
        state_[4]=0x510e527f; state_[5]=0x9b05688c; state_[6]=0x1f83d9ab; state_[7]=0x5be0cd19;
        bitcount_ = 0; buflen_ = 0;
        std::memset(buffer_, 0, sizeof(buffer_));
    }

    void update(const uint8_t* data, size_t len) noexcept {
        for (size_t i = 0; i < len; ++i) {
            buffer_[buflen_++] = data[i];
            if (buflen_ == 64) { transform(buffer_); bitcount_ += 512; buflen_ = 0; }
        }
    }

    std::array<uint8_t, 32> finalize() noexcept {
        uint64_t bits = bitcount_ + buflen_ * 8;
        buffer_[buflen_++] = 0x80;
        if (buflen_ > 56) {
            while (buflen_ < 64) buffer_[buflen_++] = 0;
            transform(buffer_); buflen_ = 0;
        }
        while (buflen_ < 56) buffer_[buflen_++] = 0;
        for (int i = 7; i >= 0; --i) buffer_[buflen_++] = uint8_t(bits >> (i * 8));
        transform(buffer_);
        std::array<uint8_t, 32> hash{};
        for (int i = 0; i < 8; ++i) {
            hash[i*4]   = uint8_t(state_[i]>>24);
            hash[i*4+1] = uint8_t(state_[i]>>16);
            hash[i*4+2] = uint8_t(state_[i]>>8);
            hash[i*4+3] = uint8_t(state_[i]);
        }
        return hash;
    }

    static std::string hex(const std::array<uint8_t, 32>& h) {
        static constexpr char digits[] = "0123456789abcdef";
        std::string out;
        out.reserve(64);
        for (auto b : h) { out += digits[b >> 4]; out += digits[b & 0xf]; }
        return out;
    }

    static std::string hash_bytes(const uint8_t* data, size_t len) {
        SHA256 ctx;
        ctx.update(data, len);
        return hex(ctx.finalize());
    }

    static std::string hash_file(const std::filesystem::path& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return {};
        SHA256 ctx;
        std::array<uint8_t, 8192> buf{};
        while (f.read(reinterpret_cast<char*>(buf.data()), buf.size()))
            ctx.update(buf.data(), static_cast<size_t>(f.gcount()));
        if (f.gcount() > 0)
            ctx.update(buf.data(), static_cast<size_t>(f.gcount()));
        return hex(ctx.finalize());
    }
};

// FIPS 180-4 SHA-384: the SHA-512 compression function (64-bit words, 80
// rounds) with SHA-384's distinct initial hash values, truncated to the
// first 384 bits (6 of 8 state words) of output. Needed alongside SHA256
// because real-world Authenticode certificate chains commonly mix digest
// algorithms across one chain -- e.g. a root signing an intermediate with
// sha384WithRSAEncryption while that intermediate signs the leaf with
// sha256WithRSAEncryption -- so verifying such a chain from scratch needs
// both.
class SHA384 {
    uint64_t state_[8]{};
    uint8_t  buffer_[128]{};
    uint64_t bitcount_{0}; // low 64 bits of the total bit length; sufficient for any input this codebase hashes
    size_t   buflen_{0};

    static constexpr std::array<uint64_t, 80> K = {
        0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
        0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
        0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
        0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL,
    };

    static uint64_t rotr(uint64_t x, unsigned n) noexcept { return (x >> n) | (x << (64 - n)); }
    static uint64_t ch(uint64_t x, uint64_t y, uint64_t z) noexcept { return (x & y) ^ (~x & z); }
    static uint64_t maj(uint64_t x, uint64_t y, uint64_t z) noexcept { return (x & y) ^ (x & z) ^ (y & z); }
    static uint64_t ep0(uint64_t x) noexcept { return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39); }
    static uint64_t ep1(uint64_t x) noexcept { return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41); }
    static uint64_t sig0(uint64_t x) noexcept { return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7); }
    static uint64_t sig1(uint64_t x) noexcept { return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6); }

    void transform(const uint8_t block[128]) noexcept {
        uint64_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = 0;
            for (int b = 0; b < 8; ++b) w[i] = (w[i] << 8) | block[i * 8 + b];
        }
        for (int i = 16; i < 80; ++i)
            w[i] = sig1(w[i-2]) + w[i-7] + sig0(w[i-15]) + w[i-16];
        uint64_t a=state_[0],b=state_[1],c=state_[2],d=state_[3],
                 e=state_[4],f=state_[5],g=state_[6],h=state_[7];
        for (int i = 0; i < 80; ++i) {
            uint64_t t1 = h + ep1(e) + ch(e,f,g) + K[i] + w[i];
            uint64_t t2 = ep0(a) + maj(a,b,c);
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        state_[0]+=a; state_[1]+=b; state_[2]+=c; state_[3]+=d;
        state_[4]+=e; state_[5]+=f; state_[6]+=g; state_[7]+=h;
    }

public:
    SHA384() { reset(); }

    void reset() noexcept {
        state_[0]=0xcbbb9d5dc1059ed8ULL; state_[1]=0x629a292a367cd507ULL;
        state_[2]=0x9159015a3070dd17ULL; state_[3]=0x152fecd8f70e5939ULL;
        state_[4]=0x67332667ffc00b31ULL; state_[5]=0x8eb44a8768581511ULL;
        state_[6]=0xdb0c2e0d64f98fa7ULL; state_[7]=0x47b5481dbefa4fa4ULL;
        bitcount_ = 0; buflen_ = 0;
        std::memset(buffer_, 0, sizeof(buffer_));
    }

    void update(const uint8_t* data, size_t len) noexcept {
        for (size_t i = 0; i < len; ++i) {
            buffer_[buflen_++] = data[i];
            if (buflen_ == 128) { transform(buffer_); bitcount_ += 1024; buflen_ = 0; }
        }
    }

    std::array<uint8_t, 48> finalize() noexcept {
        uint64_t bits = bitcount_ + buflen_ * 8;
        buffer_[buflen_++] = 0x80;
        if (buflen_ > 112) {
            while (buflen_ < 128) buffer_[buflen_++] = 0;
            transform(buffer_); buflen_ = 0;
        }
        while (buflen_ < 112) buffer_[buflen_++] = 0;
        for (int i = 0; i < 8; ++i) buffer_[buflen_++] = 0; // high 64 bits of the 128-bit length: always 0 here
        for (int i = 7; i >= 0; --i) buffer_[buflen_++] = uint8_t(bits >> (i * 8));
        transform(buffer_);
        std::array<uint8_t, 48> hash{};
        for (int i = 0; i < 6; ++i) {
            for (int b = 0; b < 8; ++b) hash[i*8+b] = uint8_t(state_[i] >> ((7-b)*8));
        }
        return hash;
    }

    static std::string hex(const std::array<uint8_t, 48>& h) {
        static constexpr char digits[] = "0123456789abcdef";
        std::string out;
        out.reserve(96);
        for (auto b : h) { out += digits[b >> 4]; out += digits[b & 0xf]; }
        return out;
    }

    static std::string hash_bytes(const uint8_t* data, size_t len) {
        SHA384 ctx;
        ctx.update(data, len);
        return hex(ctx.finalize());
    }
};

class ThreadPool {
    std::vector<std::thread>                workers_;
    std::queue<std::function<void()>>       tasks_;
    std::mutex                              mtx_;
    std::condition_variable                 cv_;
    std::condition_variable                 idle_cv_;
    std::atomic<bool>                       stop_{false};
    size_t                                  outstanding_{0}; // queued + running, guarded by mtx_

public:
    explicit ThreadPool(size_t n = std::max(2u, std::thread::hardware_concurrency())) {
        for (size_t i = 0; i < n; ++i) {
            workers_.emplace_back([this] {
                for (;;) {
                    std::function<void()> task;
                    {
                        std::unique_lock lk(mtx_);
                        cv_.wait(lk, [this]{ return stop_.load() || !tasks_.empty(); });
                        if (stop_.load() && tasks_.empty()) return;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    try { task(); } catch (...) {}
                    {
                        std::lock_guard lk(mtx_);
                        --outstanding_;
                        if (outstanding_ == 0) idle_cv_.notify_all();
                    }
                }
            });
        }
    }

    void enqueue(std::function<void()> task) {
        {
            std::lock_guard lk(mtx_);
            tasks_.push(std::move(task));
            ++outstanding_;
        }
        cv_.notify_one();
    }

    // Drop not-yet-started tasks. Running tasks are unaffected.
    void clear_queue() {
        std::lock_guard lk(mtx_);
        while (!tasks_.empty()) { tasks_.pop(); --outstanding_; }
        if (outstanding_ == 0) idle_cv_.notify_all();
    }

    // Block until every enqueued task has finished executing.
    void wait_idle() {
        std::unique_lock lk(mtx_);
        idle_cv_.wait(lk, [this]{ return outstanding_ == 0; });
    }

    ~ThreadPool() {
        stop_.store(true);
        cv_.notify_all();
        for (auto& w : workers_) if (w.joinable()) w.join();
    }
};

enum class LogLevel : uint8_t { DBG = 0, INFO = 1, WARN = 2, ERR = 3, CRIT = 4 };

class Logger {
    mutable std::mutex mtx_;
    LogLevel min_level_{LogLevel::INFO};
    std::vector<std::string> buffer_;

public:
    static Logger& instance() { static Logger l; return l; }

    void set_level(LogLevel lv) { min_level_ = lv; }

    void log(LogLevel lv, std::string_view msg) {
        if (lv < min_level_) return;
        auto now = std::chrono::system_clock::now();
        auto t   = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf{};
#ifdef _WIN32
        localtime_s(&tm_buf, &t);
#else
        localtime_r(&t, &tm_buf);
#endif
        char ts[32];
        std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);
        static constexpr const char* tags[] = {"DBG","INF","WRN","ERR","CRT"};
        std::string line = std::string("[") + ts + "][" + tags[static_cast<int>(lv)] + "] " + std::string(msg);
        std::lock_guard lk(mtx_);
        buffer_.push_back(std::move(line));
        if (buffer_.size() > 10000) buffer_.erase(buffer_.begin(), buffer_.begin() + 5000);
    }

    std::vector<std::string> recent(size_t n = 100) const {
        std::lock_guard lk(mtx_);
        size_t start = buffer_.size() > n ? buffer_.size() - n : 0;
        return {buffer_.begin() + start, buffer_.end()};
    }

    void clear() { std::lock_guard lk(mtx_); buffer_.clear(); }
};

#define GCAD_LOG(level, msg) gcad::Logger::instance().log(gcad::LogLevel::level, msg)

} // namespace gcad
