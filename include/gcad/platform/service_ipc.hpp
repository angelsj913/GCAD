#pragma once
#include "../common.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <cstdint>

namespace gcad::platform {

enum class IpcMsgType : uint16_t {
    PING            = 0x0001,
    PONG            = 0x0002,
    STATUS_REQ      = 0x0003,
    STATUS_RESP     = 0x0004,
    THREAT_EVENT    = 0x0005,
    COMMAND         = 0x0006,
};

#pragma pack(push, 1)
struct IpcHeader {
    uint32_t magic{0x47434144}; // 'GCAD'
    uint16_t type{0};
    uint32_t length{0};
};
#pragma pack(pop)

class ServiceIpc {
public:
    static constexpr std::string_view PIPE_NAME = "\\\\.\\pipe\\gcad_service_ipc";
    static constexpr uint32_t MAGIC = 0x47434144;

    static std::vector<uint8_t> serialize_packet(IpcMsgType type, std::string_view payload);
    static bool parse_packet(const uint8_t* data, size_t size, IpcHeader& out_hdr, std::string& out_payload);

    static std::string serialize_threat(const ThreatEvent& ev);
    static ThreatEvent deserialize_threat(std::string_view payload);
};

class ServiceIpcServer {
public:
    ServiceIpcServer();
    ~ServiceIpcServer();

    bool start();
    void stop();
    bool is_running() const noexcept { return running_.load(); }

    void broadcast_threat(const ThreatEvent& ev);
    void broadcast_status(std::string_view status_str);
    void on_command(std::function<void(std::string_view)> cb);

private:
    std::atomic<bool>                     running_{false};
    std::thread                           worker_thread_;
    mutable std::mutex                    clients_mtx_;
    std::vector<void*>                    client_pipes_; // HANDLE on Windows
    std::function<void(std::string_view)> cmd_cb_;

    void server_loop();
    void handle_client(void* pipe_handle);
};

class ServiceIpcClient {
public:
    ServiceIpcClient();
    ~ServiceIpcClient();

    bool connect(int timeout_ms = 1000);
    void disconnect();
    bool is_connected() const noexcept;

    bool ping();
    std::string request_status();
    void on_threat(std::function<void(ThreatEvent)> cb);

    static bool is_service_running();

private:
    void*                            pipe_handle_{nullptr}; // HANDLE on Windows
    std::atomic<bool>                connected_{false};
    std::thread                      listener_thread_;
    mutable std::mutex               io_mtx_;
    std::function<void(ThreatEvent)> threat_cb_;

    void listen_loop();
};

} // namespace gcad::platform
