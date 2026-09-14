#include "gcad/engines/named_pipe_engine.hpp"
#include <functional>

extern void register_test(const char* name, std::function<bool()> fn);

void register_named_pipe_tests() {
    register_test("named_pipe_name_and_lifecycle", [] {
        gcad::NamedPipeEngine engine;
        if (engine.name() != "NamedPipe-Defense") return false;
        if (engine.running()) return false;
        if (engine.start() != gcad::ErrorCode::OK) return false;
        if (!engine.running()) return false;
        auto st = engine.status();
        if (st.name != "NamedPipe-Defense" || !st.running) return false;
        if (engine.stop() != gcad::ErrorCode::OK) return false;
        if (engine.running()) return false;
        return true;
    });

    register_test("named_pipe_detects_cobalt_strike", [] {
        std::string fw, reason;
        if (!gcad::NamedPipeEngine::is_c2_pipe("msagent_9876", fw, reason)) return false;
        if (fw != "Cobalt Strike") return false;

        if (!gcad::NamedPipeEngine::is_c2_pipe("\\\\.\\pipe\\status_123", fw, reason)) return false;
        if (fw != "Cobalt Strike") return false;

        if (!gcad::NamedPipeEngine::is_c2_pipe("mypipe-f_beacon", fw, reason)) return false;
        if (fw != "Cobalt Strike") return false;

        return true;
    });

    register_test("named_pipe_detects_metasploit", [] {
        std::string fw, reason;
        if (!gcad::NamedPipeEngine::is_c2_pipe("meterpreter_reverse_tcp", fw, reason)) return false;
        if (fw != "Metasploit") return false;

        if (!gcad::NamedPipeEngine::is_c2_pipe("metsrv_4444", fw, reason)) return false;
        if (fw != "Metasploit") return false;

        return true;
    });

    register_test("named_pipe_detects_sliver", [] {
        std::string fw, reason;
        if (!gcad::NamedPipeEngine::is_c2_pipe("sliver_lateral_pipe", fw, reason)) return false;
        if (fw != "Sliver C2") return false;

        if (!gcad::NamedPipeEngine::is_c2_pipe("slv_smb_transport", fw, reason)) return false;
        if (fw != "Sliver C2") return false;

        return true;
    });

    register_test("named_pipe_detects_psexec", [] {
        std::string fw, reason;
        if (!gcad::NamedPipeEngine::is_c2_pipe("psexec_svc_proc", fw, reason)) return false;
        if (fw != "PsExec") return false;

        if (!gcad::NamedPipeEngine::is_c2_pipe("paexec_remote_worker", fw, reason)) return false;
        if (fw != "PAExec") return false;

        return true;
    });

    register_test("named_pipe_allows_benign_system_pipes", [] {
        std::string fw, reason;
        if (gcad::NamedPipeEngine::is_c2_pipe("lsass", fw, reason)) return false;
        if (gcad::NamedPipeEngine::is_c2_pipe("winreg", fw, reason)) return false;
        if (gcad::NamedPipeEngine::is_c2_pipe("samr", fw, reason)) return false;
        if (gcad::NamedPipeEngine::is_c2_pipe("mojo.12345.67890", fw, reason)) return false;
        if (gcad::NamedPipeEngine::is_c2_pipe("chrome.sync.1122", fw, reason)) return false;
        return true;
    });
}
