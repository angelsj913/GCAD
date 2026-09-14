#include "gcad/platform/service_ipc.hpp"
#include <functional>
#include <vector>
#include <iostream>
#include <chrono>

extern void register_test(const char* name, std::function<bool()> fn);

namespace {

void register_service_ipc_tests() {
    register_test("service_ipc_packet_serialization", [] {
        std::string payload = "Hello GCAD IPC Protocol";
        auto pkt = gcad::platform::ServiceIpc::serialize_packet(
            gcad::platform::IpcMsgType::PING, payload);

        gcad::platform::IpcHeader hdr;
        std::string parsed_payload;
        if (!gcad::platform::ServiceIpc::parse_packet(pkt.data(), pkt.size(), hdr, parsed_payload)) {
            return false;
        }

        if (hdr.magic != gcad::platform::ServiceIpc::MAGIC) return false;
        if (hdr.type != static_cast<uint16_t>(gcad::platform::IpcMsgType::PING)) return false;
        if (hdr.length != payload.size()) return false;
        if (parsed_payload != payload) return false;
        return true;
    });

    register_test("service_ipc_threat_serialization_roundtrip", [] {
        gcad::ThreatEvent ev;
        ev.id = 12345;
        ev.level = gcad::ThreatLevel::CRITICAL;
        ev.category = gcad::ThreatCategory::MALWARE_PACKER;
        ev.process_id = 9988;
        ev.process_name = "malware_test.exe";
        ev.file_path = "C:\\Windows\\Temp\\malware_test.exe";
        ev.description = "Packed UPX binary with W^X violation";
        ev.source_ip = "192.168.1.100";
        ev.source_port = 4444;
        ev.quarantined = true;
        ev.rolled_back = false;

        std::string serialized = gcad::platform::ServiceIpc::serialize_threat(ev);
        auto deserialized = gcad::platform::ServiceIpc::deserialize_threat(serialized);

        if (deserialized.id != ev.id) return false;
        if (deserialized.level != ev.level) return false;
        if (deserialized.category != ev.category) return false;
        if (deserialized.process_id != ev.process_id) return false;
        if (deserialized.process_name != ev.process_name) return false;
        if (deserialized.file_path != ev.file_path) return false;
        if (deserialized.description != ev.description) return false;
        if (deserialized.source_ip != ev.source_ip) return false;
        if (deserialized.source_port != ev.source_port) return false;
        if (deserialized.quarantined != ev.quarantined) return false;
        if (deserialized.rolled_back != ev.rolled_back) return false;
        return true;
    });

    register_test("service_ipc_rejects_corrupted_packet", [] {
        std::vector<uint8_t> corrupted = {0x00, 0x01, 0x02}; // Too short
        gcad::platform::IpcHeader hdr;
        std::string payload;
        if (gcad::platform::ServiceIpc::parse_packet(corrupted.data(), corrupted.size(), hdr, payload)) {
            return false;
        }

        // Corrupt magic
        auto valid = gcad::platform::ServiceIpc::serialize_packet(
            gcad::platform::IpcMsgType::PONG, "TEST");
        valid[0] = 0xFF; // Invalidate magic
        if (gcad::platform::ServiceIpc::parse_packet(valid.data(), valid.size(), hdr, payload)) {
            return false;
        }

        return true;
    });

    register_test("service_ipc_server_start_stop_lifecycle", [] {
        gcad::platform::ServiceIpcServer server;
        if (server.is_running()) return false;

        if (!server.start()) return false;
        if (!server.is_running()) return false;

        server.stop();
        if (server.is_running()) return false;
        return true;
    });

    register_test("service_ipc_client_query_offline_service", [] {
        // When server is stopped, is_service_running should return false
        return !gcad::platform::ServiceIpcClient::is_service_running();
    });
}

struct RegisterServiceIpcTests {
    RegisterServiceIpcTests() {
        register_service_ipc_tests();
    }
} g_register_service_ipc_tests;

} // namespace
