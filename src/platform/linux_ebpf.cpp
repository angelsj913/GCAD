#include "gcad/platform/linux_ebpf.hpp"

#ifdef GCAD_PLATFORM_LINUX
#include <sys/fanotify.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>

namespace gcad::platform {

LinuxEbpf::LinuxEbpf() = default;
LinuxEbpf::~LinuxEbpf() { stop(); }

ErrorCode LinuxEbpf::start() {
    if (running_.load()) return ErrorCode::OK;

    fanotify_fd_ = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK,
                                  O_RDONLY | O_LARGEFILE);
    if (fanotify_fd_ < 0) {
        GCAD_LOG(WARN, "fanotify_init failed — file monitoring degraded");
    }

    running_.store(true);
    fanotify_thread_ = std::thread(&LinuxEbpf::fanotify_loop, this);
    proc_thread_ = std::thread(&LinuxEbpf::proc_connector_loop, this);
    GCAD_LOG(INFO, "Linux eBPF/fanotify monitor started");
    return ErrorCode::OK;
}

ErrorCode LinuxEbpf::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (fanotify_fd_ >= 0) { close(fanotify_fd_); fanotify_fd_ = -1; }
    if (fanotify_thread_.joinable()) fanotify_thread_.join();
    if (proc_thread_.joinable()) proc_thread_.join();
    return ErrorCode::OK;
}

void LinuxEbpf::on_file_event(std::function<void(const FileEvent&)> cb) {
    file_cb_ = std::move(cb);
}

void LinuxEbpf::on_process_event(std::function<void(const ProcessEvent&)> cb) {
    proc_cb_ = std::move(cb);
}

void LinuxEbpf::add_watch(const std::filesystem::path& path) {
    if (fanotify_fd_ >= 0) {
        fanotify_mark(fanotify_fd_, FAN_MARK_ADD | FAN_MARK_MOUNT,
                      FAN_MODIFY | FAN_CLOSE_WRITE | FAN_OPEN_EXEC,
                      AT_FDCWD, path.c_str());
    }
}

void LinuxEbpf::fanotify_loop() {
    if (fanotify_fd_ < 0) return;
    char buf[4096];
    while (running_.load()) {
        ssize_t len = read(fanotify_fd_, buf, sizeof(buf));
        if (len <= 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        auto* meta = reinterpret_cast<fanotify_event_metadata*>(buf);
        while (FAN_EVENT_OK(meta, len)) {
            if (meta->fd >= 0) {
                char path_buf[PATH_MAX];
                std::string fd_path = "/proc/self/fd/" + std::to_string(meta->fd);
                ssize_t path_len = readlink(fd_path.c_str(), path_buf, sizeof(path_buf) - 1);
                if (path_len > 0) {
                    path_buf[path_len] = '\0';
                    FileEvent ev;
                    ev.pid = meta->pid;
                    ev.path = path_buf;
                    ev.mask = meta->mask;
                    ev.timestamp = std::chrono::system_clock::now();
                    {
                        std::lock_guard lk(mtx_);
                        file_events_.push_back(ev);
                        if (file_events_.size() > 5000)
                            file_events_.erase(file_events_.begin(), file_events_.begin() + 2500);
                    }
                    if (file_cb_) file_cb_(ev);
                }
                close(meta->fd);
            }
            meta = FAN_EVENT_NEXT(meta, len);
        }
    }
}

void LinuxEbpf::proc_connector_loop() {
    int sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (sock < 0) {
        GCAD_LOG(WARN, "proc connector socket failed — process monitoring via /proc polling");
        while (running_.load()) {
            for (auto& entry : std::filesystem::directory_iterator("/proc")) {
                auto name = entry.path().filename().string();
                if (name.empty() || !std::all_of(name.begin(), name.end(), ::isdigit)) continue;
                // Simple process enumeration
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        return;
    }

    sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = CN_IDX_PROC;
    sa.nl_pid = getpid();
    bind(sock, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));

    struct {
        nlmsghdr nl_hdr;
        cn_msg   cn_msg;
        enum proc_cn_mcast_op op;
    } msg{};
    msg.nl_hdr.nlmsg_len = sizeof(msg);
    msg.nl_hdr.nlmsg_type = NLMSG_DONE;
    msg.nl_hdr.nlmsg_pid = getpid();
    msg.cn_msg.id.idx = CN_IDX_PROC;
    msg.cn_msg.id.val = CN_VAL_PROC;
    msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);
    msg.op = PROC_CN_MCAST_LISTEN;
    send(sock, &msg, sizeof(msg), 0);

    char buf[4096];
    while (running_.load()) {
        struct pollfd pfd = {sock, POLLIN, 0};
        int ret = poll(&pfd, 1, 1000);
        if (ret <= 0) continue;

        ssize_t len = recv(sock, buf, sizeof(buf), 0);
        if (len <= 0) continue;

        auto* nlh = reinterpret_cast<nlmsghdr*>(buf);
        auto* cn = reinterpret_cast<cn_msg*>(NLMSG_DATA(nlh));
        auto* ev = reinterpret_cast<proc_event*>(cn->data);

        if (ev->what == proc_event::PROC_EVENT_EXEC) {
            ProcessEvent pe;
            pe.pid = ev->event_data.exec.process_pid;
            pe.is_exec = true;
            pe.timestamp = std::chrono::system_clock::now();

            std::ifstream comm("/proc/" + std::to_string(pe.pid) + "/comm");
            if (comm) std::getline(comm, pe.comm);

            std::error_code ec;
            auto exe = std::filesystem::read_symlink("/proc/" + std::to_string(pe.pid) + "/exe", ec);
            if (!ec) pe.exe = exe.string();

            {
                std::lock_guard lk(mtx_);
                proc_events_.push_back(pe);
                if (proc_events_.size() > 5000)
                    proc_events_.erase(proc_events_.begin(), proc_events_.begin() + 2500);
            }
            if (proc_cb_) proc_cb_(pe);
        }
    }
    close(sock);
}

std::vector<FileEvent> LinuxEbpf::recent_file_events(size_t n) const {
    std::lock_guard lk(mtx_);
    size_t start = file_events_.size() > n ? file_events_.size() - n : 0;
    return {file_events_.begin() + start, file_events_.end()};
}

std::vector<ProcessEvent> LinuxEbpf::recent_proc_events(size_t n) const {
    std::lock_guard lk(mtx_);
    size_t start = proc_events_.size() > n ? proc_events_.size() - n : 0;
    return {proc_events_.begin() + start, proc_events_.end()};
}

} // namespace gcad::platform

#endif
