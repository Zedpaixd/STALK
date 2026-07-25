#ifndef EDR_HASHER_H
#define EDR_HASHER_H
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct FileId {
    std::uint64_t ino = 0;
    std::uint64_t size = 0;
    std::uint64_t mtime_ns = 0;
    std::uint32_t dev_major = 0;
    std::uint32_t dev_minor = 0;
    bool valid() const { return ino != 0; }
    std::string key() const;
};

class BinHasher {
public:
    using Callback = std::function<void(const FileId &, const std::string &, const std::string &)>;
    explicit BinHasher(std::size_t workers = 2, std::size_t cache_cap = 8192);
    ~BinHasher();
    static int open_verified(std::uint32_t pid, const FileId &want, std::string &path_out);
    static int open_path_verified(const std::string &path, const FileId &want);
    bool lookup(const FileId &id, std::string &hash_out) const;
    void submit(int fd, const FileId &id, const std::string &path);
    bool wait_for(const FileId &id, std::string &hash_out, int timeout_ms);
    void set_callback(Callback cb) { cb_ = std::move(cb); }
    void stop();
    std::size_t cached() const;
private:
    static bool identity_matches(int fd, const FileId &want);
    struct Job { int fd; FileId id; std::string path; };
    void worker();
    mutable std::mutex m_;
    std::condition_variable cv_;
    std::condition_variable done_cv_;
    std::deque<Job> q_;
    std::unordered_map<std::string, std::string> cache_;
    std::unordered_set<std::string> inflight_;
    std::vector<std::thread> threads_;
    std::atomic<bool> stop_{false};
    std::size_t cap_;
    Callback cb_;
};
#endif