#include "gcad/platform/service_ipc.hpp"
#include <sstream>
#include <algorithm>
#include <chrono>

namespace gcad::platform {

std::vector<uint8_t> ServiceIpc::serialize_packet(IpcMsgType type, std::string_view payload) {
    IpcHeader hdr;
    hdr.magic = MAGIC;
    hdr.type = static_cast<uint16_t>(type);
    hdr.length = static_cast<uint32_t>(payload.size());

    std::vector<uint8_t> buf(sizeof(IpcHeader) + payload.size());
    std::memcpy(buf.data(), &hdr, sizeof(IpcHeader));
    if (!payload.empty()) {
        std::memcpy(buf.data() + sizeof(IpcHeader), payload.data(), payload.size());
    }
    return buf;
}

bool ServiceIpc::parse_packet(const uint8_t* data, size_t size, IpcHeader& out_hdr, std::string& out_payload) {
    if (!data || size < sizeof(IpcHeader)) return false;
    std::memcpy(&out_hdr, data, sizeof(IpcHeader));
    if (out_hdr.magic != MAGIC) return false;
    if (size < sizeof(IpcHeader) + out_hdr.length) return false;

    if (out_hdr.length > 0) {
        out_payload.assign(reinterpret_cast<const char*>(data + sizeof(IpcHeader)), out_hdr.length);
    } else {
        out_payload.clear();
    }
    return true;
}

std::string ServiceIpc::serialize_threat(const ThreatEvent& ev) {
    std::ostringstream oss;
    oss << ev.id << '\t'
        << static_cast<int>(ev.level) << '\t'
        << static_cast<uint16_t>(ev.category) << '\t'
        << ev.process_id << '\t'
        << ev.process_name << '\t'
        << ev.file_path << '\t'
        << ev.description << '\t'
        << ev.source_ip << '\t'
        << ev.source_port << '\t'
        << (ev.quarantined ? 1 : 0) << '\t'
        << (ev.rolled_back ? 1 : 0);
    return oss.str();
}

ThreatEvent ServiceIpc::deserialize_threat(std::string_view payload) {
    ThreatEvent ev;
    std::string s(payload);
    std::vector<std::string> tokens;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, '\t')) {
        tokens.push_back(item);
    }

    if (tokens.size() >= 11) {
        try {
            ev.id = std::stoull(tokens[0]);
            ev.level = static_cast<ThreatLevel>(std::stoi(tokens[1]));
            ev.category = static_cast<ThreatCategory>(std::stoi(tokens[2]));
            ev.process_id = static_cast<uint32_t>(std::stoul(tokens[3]));
            ev.process_name = tokens[4];
            ev.file_path = tokens[5];
            ev.description = tokens[6];
            ev.source_ip = tokens[7];
            ev.source_port = static_cast<uint16_t>(std::stoul(tokens[8]));
            ev.quarantined = (tokens[9] == "1");
            ev.rolled_back = (tokens[10] == "1");
        } catch (...) {
            // Keep default-initialized values on parsing error
        }
    }
    ev.timestamp = std::chrono::system_clock::now();
    return ev;
}

#ifdef GCAD_PLATFORM_WINDOWS

ServiceIpcServer::ServiceIpcServer() = default;

ServiceIpcServer::~ServiceIpcServer() {
    stop();
}

bool ServiceIpcServer::start() {
    if (running_.load()) return true;
    running_.store(true);
    worker_thread_ = std::thread(&ServiceIpcServer::server_loop, this);
    return true;
}

void ServiceIpcServer::stop() {
    if (!running_.exchange(false)) return;

    // Trigger pipe to unblock ConnectNamedPipe
    HANDLE hDummy = CreateFileA(ServiceIpc::PIPE_NAME.data(), GENERIC_READ | GENERIC_WRITE,
                                0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDummy != INVALID_HANDLE_VALUE) {
        CloseHandle(hDummy);
    }

    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }

    std::lock_guard lk(clients_mtx_);
    for (void* p : client_pipes_) {
        if (p && p != INVALID_HANDLE_VALUE) {
            FlushFileBuffers(static_cast<HANDLE>(p));
            DisconnectNamedPipe(static_cast<HANDLE>(p));
            CloseHandle(static_cast<HANDLE>(p));
        }
    }
    client_pipes_.clear();
}

void ServiceIpcServer::broadcast_threat(const ThreatEvent& ev) {
    auto payload = ServiceIpc::serialize_threat(ev);
    auto pkt = ServiceIpc::serialize_packet(IpcMsgType::THREAT_EVENT, payload);

    std::lock_guard lk(clients_mtx_);
    std::vector<void*> active;
    for (void* p : client_pipes_) {
        HANDLE h = static_cast<HANDLE>(p);
        DWORD written = 0;
        if (WriteFile(h, pkt.data(), static_cast<DWORD>(pkt.size()), &written, NULL) && written == pkt.size()) {
            active.push_back(p);
        } else {
            DisconnectNamedPipe(h);
            CloseHandle(h);
        }
    }
    client_pipes_ = std::move(active);
}

void ServiceIpcServer::broadcast_status(std::string_view status_str) {
    auto pkt = ServiceIpc::serialize_packet(IpcMsgType::STATUS_RESP, status_str);

    std::lock_guard lk(clients_mtx_);
    std::vector<void*> active;
    for (void* p : client_pipes_) {
        HANDLE h = static_cast<HANDLE>(p);
        DWORD written = 0;
        if (WriteFile(h, pkt.data(), static_cast<DWORD>(pkt.size()), &written, NULL) && written == pkt.size()) {
            active.push_back(p);
        } else {
            DisconnectNamedPipe(h);
            CloseHandle(h);
        }
    }
    client_pipes_ = std::move(active);
}

void ServiceIpcServer::on_command(std::function<void(std::string_view)> cb) {
    std::lock_guard lk(clients_mtx_);
    cmd_cb_ = std::move(cb);
}

void ServiceIpcServer::server_loop() {
    while (running_.load()) {
        HANDLE hPipe = CreateNamedPipeA(
            ServiceIpc::PIPE_NAME.data(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            8192, 8192, 1000, NULL);

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!running_.load()) {
            CloseHandle(hPipe);
            break;
        }

        if (connected) {
            std::lock_guard lk(clients_mtx_);
            client_pipes_.push_back(hPipe);
        } else {
            CloseHandle(hPipe);
        }
    }
}

ServiceIpcClient::ServiceIpcClient() = default;

ServiceIpcClient::~ServiceIpcClient() {
    disconnect();
}

bool ServiceIpcClient::is_service_running() {
    return WaitNamedPipeA(ServiceIpc::PIPE_NAME.data(), 50) != FALSE;
}

bool ServiceIpcClient::connect(int timeout_ms) {
    if (connected_.load()) return true;

    if (!WaitNamedPipeA(ServiceIpc::PIPE_NAME.data(), static_cast<DWORD>(timeout_ms))) {
        return false;
    }

    HANDLE hPipe = CreateFileA(
        ServiceIpc::PIPE_NAME.data(),
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(hPipe, &mode, NULL, NULL)) {
        CloseHandle(hPipe);
        return false;
    }

    pipe_handle_ = hPipe;
    connected_.store(true);
    listener_thread_ = std::thread(&ServiceIpcClient::listen_loop, this);
    return true;
}

void ServiceIpcClient::disconnect() {
    if (!connected_.exchange(false)) return;

    if (pipe_handle_ && pipe_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(static_cast<HANDLE>(pipe_handle_));
        pipe_handle_ = nullptr;
    }

    if (listener_thread_.joinable()) {
        listener_thread_.join();
    }
}

bool ServiceIpcClient::is_connected() const noexcept {
    return connected_.load();
}

bool ServiceIpcClient::ping() {
    if (!connected_.load() || !pipe_handle_) return false;

    auto pkt = ServiceIpc::serialize_packet(IpcMsgType::PING, "PING");
    std::lock_guard lk(io_mtx_);
    DWORD written = 0;
    if (!WriteFile(static_cast<HANDLE>(pipe_handle_), pkt.data(), static_cast<DWORD>(pkt.size()), &written, NULL)) {
        return false;
    }
    return written == pkt.size();
}

std::string ServiceIpcClient::request_status() {
    if (!connected_.load() || !pipe_handle_) return {};

    auto pkt = ServiceIpc::serialize_packet(IpcMsgType::STATUS_REQ, "GET_STATUS");
    std::lock_guard lk(io_mtx_);
    DWORD written = 0;
    if (!WriteFile(static_cast<HANDLE>(pipe_handle_), pkt.data(), static_cast<DWORD>(pkt.size()), &written, NULL)) {
        return {};
    }
    return "REQUESTED";
}

void ServiceIpcClient::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(io_mtx_);
    threat_cb_ = std::move(cb);
}

void ServiceIpcClient::listen_loop() {
    std::vector<uint8_t> buf(16384);

    while (connected_.load()) {
        DWORD bytes_read = 0;
        BOOL ok = ReadFile(static_cast<HANDLE>(pipe_handle_), buf.data(), static_cast<DWORD>(buf.size()), &bytes_read, NULL);
        if (!ok || bytes_read == 0) {
            connected_.store(false);
            break;
        }

        IpcHeader hdr;
        std::string payload;
        if (ServiceIpc::parse_packet(buf.data(), bytes_read, hdr, payload)) {
            if (hdr.type == static_cast<uint16_t>(IpcMsgType::THREAT_EVENT)) {
                auto ev = ServiceIpc::deserialize_threat(payload);
                std::function<void(ThreatEvent)> cb;
                {
                    std::lock_guard lk(io_mtx_);
                    cb = threat_cb_;
                }
                if (cb) cb(ev);
            }
        }
    }
}

#else // !GCAD_PLATFORM_WINDOWS

ServiceIpcServer::ServiceIpcServer() = default;
ServiceIpcServer::~ServiceIpcServer() = default;
bool ServiceIpcServer::start() { running_.store(true); return true; }
void ServiceIpcServer::stop() { running_.store(false); }
void ServiceIpcServer::broadcast_threat(const ThreatEvent&) {}
void ServiceIpcServer::broadcast_status(std::string_view) {}
void ServiceIpcServer::on_command(std::function<void(std::string_view)> cb) { cmd_cb_ = std::move(cb); }
void ServiceIpcServer::server_loop() {}

ServiceIpcClient::ServiceIpcClient() = default;
ServiceIpcClient::~ServiceIpcClient() = default;
bool ServiceIpcClient::is_service_running() { return false; }
bool ServiceIpcClient::connect(int) { return false; }
void ServiceIpcClient::disconnect() { connected_.store(false); }
bool ServiceIpcClient::is_connected() const noexcept { return false; }
bool ServiceIpcClient::ping() { return false; }
std::string ServiceIpcClient::request_status() { return {}; }
void ServiceIpcClient::on_threat(std::function<void(ThreatEvent)> cb) { threat_cb_ = std::move(cb); }
void ServiceIpcClient::listen_loop() {}

#endif

} // namespace gcad::platform
