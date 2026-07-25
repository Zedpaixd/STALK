#include "hasher.h"
#include "sha256.h"
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

std::string FileId::key() const {
    char b[96];
    std::snprintf(b, sizeof(b), "%u:%u:%llu:%llu:%llu", dev_major, dev_minor,
                  (unsigned long long)ino, (unsigned long long)size,
                  (unsigned long long)mtime_ns);
    return b;
}

static std::string hash_fd(int fd) {
    if (::lseek(fd, 0, SEEK_SET) < 0) return std::string();
    Sha256 s;
    std::uint8_t buf[65536];
    for (;;) {
        ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n == 0) break;
        if (n < 0) { if (errno == EINTR) continue; return std::string(); }
        s.update(buf, (std::size_t)n);
    }
    return s.hex();
}

bool BinHasher::identity_matches(int fd, const FileId &want) {
    if (!want.valid()) return true;
    struct stat st;
    if (::fstat(fd, &st) != 0) return false;
    if ((std::uint64_t)st.st_ino != want.ino) return false;
    if ((std::uint64_t)st.st_size != want.size) return false;
    if ((std::uint32_t)major(st.st_dev) != want.dev_major) return false;
    if ((std::uint32_t)minor(st.st_dev) != want.dev_minor) return false;
    std::uint64_t mt = (std::uint64_t)st.st_mtim.tv_sec * 1000000000ULL
                     + (std::uint64_t)st.st_mtim.tv_nsec;
    if (want.mtime_ns != 0 && mt != want.mtime_ns)
        std::fprintf(stderr, "[HASH] mtime drift on ino=%llu (fs timestamp fidelity); accepting\n",
                     (unsigned long long)want.ino);
    return true;
}

int BinHasher::open_verified(std::uint32_t pid, const FileId &want, std::string &path_out) {
    path_out.clear();
    if (pid == 0) return -1;
    char link[64];
    std::snprintf(link, sizeof(link), "/proc/%u/exe", pid);
    char tgt[4096];
    ssize_t n = ::readlink(link, tgt, sizeof(tgt) - 1);
    if (n > 0) {
        tgt[n] = 0;
        std::string p(tgt);
        static const std::string del = " (deleted)";
        if (p.size() > del.size() && p.compare(p.size() - del.size(), del.size(), del) == 0)
            p.erase(p.size() - del.size());
        path_out = p;
    }
    int fd = ::open(link, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { path_out.clear(); return -1; }
    if (!identity_matches(fd, want)) {
        std::fprintf(stderr, "[HASH] identity mismatch via /proc/%u/exe; refusing\n", pid);
        ::close(fd);
        path_out.clear();
        return -1;
    }
    return fd;
}

int BinHasher::open_path_verified(const std::string &path, const FileId &want) {
    if (path.empty() || path[0] != '/') return -1;
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    if (!identity_matches(fd, want)) {
        ::close(fd);
        return -1;
    }
    return fd;
}

BinHasher::BinHasher(std::size_t workers, std::size_t cache_cap) : cap_(cache_cap) {
    if (workers == 0) workers = 1;
    for (std::size_t i = 0; i < workers; i++) threads_.emplace_back(&BinHasher::worker, this);
}

BinHasher::~BinHasher() {
    stop();
    for (auto &t : threads_) if (t.joinable()) t.join();
    std::lock_guard<std::mutex> lk(m_);
    for (auto &j : q_) if (j.fd >= 0) ::close(j.fd);
    q_.clear();
}

void BinHasher::stop() {
    stop_.store(true);
    cv_.notify_all();
    done_cv_.notify_all();
}

bool BinHasher::lookup(const FileId &id, std::string &hash_out) const {
    if (!id.valid()) return false;
    std::lock_guard<std::mutex> lk(m_);
    auto it = cache_.find(id.key());
    if (it == cache_.end()) return false;
    hash_out = it->second;
    return true;
}

void BinHasher::submit(int fd, const FileId &id, const std::string &path) {
    if (fd < 0) return;
    if (!id.valid()) { ::close(fd); return; }
    std::string k = id.key();
    {
        std::lock_guard<std::mutex> lk(m_);
        if (cache_.count(k) || inflight_.count(k)) { ::close(fd); return; }
        if (q_.size() > 1024) { ::close(fd); return; }
        inflight_.insert(k);
        q_.push_back(Job{fd, id, path});
    }
    cv_.notify_one();
}

bool BinHasher::wait_for(const FileId &id, std::string &hash_out, int timeout_ms) {
    if (!id.valid()) return false;
    std::string k = id.key();
    std::unique_lock<std::mutex> lk(m_);
    done_cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                      [&] { return cache_.count(k) > 0 || inflight_.count(k) == 0 || stop_.load(); });
    auto it = cache_.find(k);
    if (it == cache_.end()) return false;
    hash_out = it->second;
    return true;
}

std::size_t BinHasher::cached() const {
    std::lock_guard<std::mutex> lk(m_);
    return cache_.size();
}

void BinHasher::worker() {
    for (;;) {
        Job j{-1, FileId{}, std::string()};
        {
            std::unique_lock<std::mutex> lk(m_);
            cv_.wait(lk, [&] { return stop_.load() || !q_.empty(); });
            if (q_.empty()) return;
            j = q_.front();
            q_.pop_front();
        }
        std::string h = hash_fd(j.fd);
        ::close(j.fd);
        {
            std::lock_guard<std::mutex> lk(m_);
            inflight_.erase(j.id.key());
            if (!h.empty()) {
                if (cache_.size() >= cap_) cache_.clear();
                cache_[j.id.key()] = h;
            }
        }
        done_cv_.notify_all();
        if (!h.empty() && cb_) cb_(j.id, h, j.path);
    }
}