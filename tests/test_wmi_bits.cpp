#include "gcad/engines/wmi_bits_engine.hpp"
#include <functional>

extern void register_test(const char* name, std::function<bool()> fn);

void register_wmi_bits_tests() {
    register_test("wmi_bits_name_and_lifecycle", [] {
        gcad::WmiBitsEngine engine;
        if (engine.name() != "WMI-BITS-Defense") return false;
        if (engine.running()) return false;
        if (engine.start() != gcad::ErrorCode::OK) return false;
        if (!engine.running()) return false;
        auto st = engine.status();
        if (st.name != "WMI-BITS-Defense" || !st.running) return false;
        if (engine.stop() != gcad::ErrorCode::OK) return false;
        if (engine.running()) return false;
        return true;
    });

    register_test("wmi_bits_evaluate_benign_wmi", [] {
        gcad::WmiSubscription sub;
        sub.filter_name = "DellHardwareMonitorFilter";
        sub.consumer_name = "DellHardwareMonitorConsumer";
        sub.consumer_type = "CommandLineEventConsumer";
        sub.command_or_script = "C:\\Program Files\\Dell\\SysMonitor.exe --notify";

        bool suspicious = gcad::WmiBitsEngine::evaluate_wmi_subscription(sub);
        return !suspicious && !sub.is_suspicious;
    });

    register_test("wmi_bits_evaluate_malicious_powershell_wmi", [] {
        gcad::WmiSubscription sub;
        sub.filter_name = "PersistenceFilter";
        sub.consumer_name = "BackdoorConsumer";
        sub.consumer_type = "CommandLineEventConsumer";
        sub.command_or_script = "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...";

        bool suspicious = gcad::WmiBitsEngine::evaluate_wmi_subscription(sub);
        return suspicious && sub.is_suspicious && !sub.reason.empty();
    });

    register_test("wmi_bits_evaluate_activescript_wmi", [] {
        gcad::WmiSubscription sub;
        sub.filter_name = "ScriptFilter";
        sub.consumer_name = "VbsConsumer";
        sub.consumer_type = "ActiveScriptEventConsumer";
        sub.command_or_script = "Set sh = CreateObject(\"WScript.Shell\"): sh.Run \"evil.exe\"";

        bool suspicious = gcad::WmiBitsEngine::evaluate_wmi_subscription(sub);
        return suspicious && sub.is_suspicious;
    });

    register_test("wmi_bits_evaluate_benign_bits_job", [] {
        gcad::BitsJobInfo job;
        job.job_id = "{11111111-2222-3333-4444-555555555555}";
        job.display_name = "SpotifyMusicCache";
        job.remote_url = "https://audio-ak.spotify.com/track.dat";
        job.local_file_path = "C:\\Users\\User\\AppData\\Roaming\\Spotify\\Storage\\track.dat";

        bool suspicious = gcad::WmiBitsEngine::evaluate_bits_job(job);
        return !suspicious && !job.is_suspicious;
    });

    register_test("wmi_bits_evaluate_malicious_bits_job", [] {
        gcad::BitsJobInfo job;
        job.job_id = "{99999999-8888-7777-6666-555555555555}";
        job.display_name = "WindowsUpdateService";
        job.remote_url = "http://45.33.32.156:8080/payload.exe";
        job.local_file_path = "C:\\Users\\User\\AppData\\Local\\Temp\\svchost_update.exe";

        bool suspicious = gcad::WmiBitsEngine::evaluate_bits_job(job);
        return suspicious && job.is_suspicious && !job.reason.empty();
    });
}
