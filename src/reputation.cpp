#include "reputation.h"
#include "sha256.h"
#include "json.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/fs.h>

using nlohmann::json;

static std::string rep_now_str() {
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t t = system_clock::to_time_t(now);
    std::tm tmv;
    localtime_r(&t, &tmv);
    char b[48];
    std::snprintf(b, sizeof(b), "%04d-%02d-%02d %02d:%02d:%02d",
        tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
        tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    return b;
}

Reputation::Reputation(std::string store_path) : path_(std::move(store_path)) {}

std::string Reputation::key(std::uint8_t kind, const std::string &hash) const {
    return std::to_string((int)kind) + ":" + hash;
}

bool Reputation::set_immutable(bool on) const {
    int fd = ::open(path_.c_str(), O_RDONLY | O_NONBLOCK);
    if (fd < 0) return false;
    int attr = 0;
    bool ok = false;
    if (ioctl(fd, FS_IOC_GETFLAGS, &attr) == 0) {
        int want = on ? (attr | FS_IMMUTABLE_FL) : (attr & ~FS_IMMUTABLE_FL);
        if (want == attr) ok = true;
        else ok = (ioctl(fd, FS_IOC_SETFLAGS, &want) == 0);
    }
    ::close(fd);
    return ok;
}

std::string Reputation::compute_checksum() const {
    std::vector<std::string> keys;
    for (auto &kv : entries_) {
        auto &e = kv.second;
        keys.push_back(std::to_string((int)e.kind) + "|" + e.hash + "|" +
                       (e.paused ? "1" : "0"));
    }
    std::sort(keys.begin(), keys.end());
    std::string blob;
    for (auto &k : keys) { blob += k; blob += "\n"; }
    return Sha256::bytes_hex(blob.data(), blob.size());
}

std::string Reputation::resolve_exe(std::uint32_t pid) const {
    char link[64];
    std::snprintf(link, sizeof(link), "/proc/%u/exe", pid);
    char target[4096];
    ssize_t n = ::readlink(link, target, sizeof(target) - 1);
    if (n <= 0) return std::string();
    target[n] = 0;
    return std::string(target);
}

std::string Reputation::hash_of_pid(std::uint32_t pid, bool &ok) {
    ok = false;
    if (pid == 0) return std::string();
    char link[64];
    std::snprintf(link, sizeof(link), "/proc/%u/exe", pid);
    return Sha256::file_hex(link, ok);
}

std::string Reputation::hash_of_file(const std::string &path, bool &ok) {
    ok = false;
    if (path.empty()) return std::string();
    return Sha256::file_hex(path.c_str(), ok);
}

void Reputation::load() {
    std::lock_guard<std::mutex> lk(mtx_);
    entries_.clear();
    tamper_ = false;

    {
        int fd = ::open(path_.c_str(), O_RDONLY);
        if (fd >= 0) {
            int attr = 0;
            immutable_supported_ = (ioctl(fd, FS_IOC_GETFLAGS, &attr) == 0);
            ::close(fd);
        }
    }

    std::ifstream ifs(path_);
    if (!ifs.is_open()) return;
    std::stringstream buf; buf << ifs.rdbuf();
    json j = json::parse(buf.str(), nullptr, false, true);
    if (j.is_discarded()) { tamper_ = true; return; }
    std::string stored_ck;
    if (j.contains("checksum")) stored_ck = j["checksum"].get<std::string>();
    if (j.contains("entries")) {
        for (auto &item : j["entries"]) {
            RepEntry e;
            if (item.contains("hash")) e.hash = item["hash"].get<std::string>();
            if (item.contains("name")) e.name = item["name"].get<std::string>();
            if (item.contains("path")) e.path = item["path"].get<std::string>();
            if (item.contains("added")) e.added_tstr = item["added"].get<std::string>();
            if (item.contains("kind")) e.kind = (std::uint8_t)item["kind"].get<int>();
            if (item.contains("paused")) e.paused = item["paused"].get<bool>();
            if (e.hash.empty()) continue;
            entries_[key(e.kind, e.hash)] = e;
        }
    }
    if (!stored_ck.empty()) {
        std::string actual = compute_checksum();
        if (actual != stored_ck) tamper_ = true;
    }
}

bool Reputation::save() {
    std::lock_guard<std::mutex> lk(mtx_);
    bool cleared = set_immutable(false);

    json j;
    j["version"] = 1;
    j["checksum"] = compute_checksum();
    json arr = json::array();
    for (auto &kv : entries_) {
        auto &e = kv.second;
        json o;
        o["hash"] = e.hash;
        o["name"] = e.name;
        o["path"] = e.path;
        o["added"] = e.added_tstr;
        o["kind"] = (int)e.kind;
        o["paused"] = e.paused;
        arr.push_back(o);
    }
    j["entries"] = arr;
    std::string dumped = j.dump(2);

    std::string tmp = path_ + ".tmp";
    bool wrote = false;
    std::string why;

    {
        std::ofstream ofs(tmp, std::ios::trunc);
        if (ofs.is_open()) {
            ofs << dumped;
            ofs.flush();
            if (ofs) {
                ofs.close();
                ::chmod(tmp.c_str(), 0600);
                if (::rename(tmp.c_str(), path_.c_str()) == 0) wrote = true;
                else { why = std::string("rename: ") + std::strerror(errno); ::unlink(tmp.c_str()); }
            } else {
                why = "tmp write failed";
                ofs.close();
                ::unlink(tmp.c_str());
            }
        } else {
            why = std::string("tmp open: ") + std::strerror(errno);
        }
    }

    if (!wrote) {
        std::ofstream ofs(path_, std::ios::trunc);
        if (ofs.is_open()) {
            ofs << dumped;
            ofs.flush();
            wrote = (bool)ofs;
            if (!wrote) why += " | direct write failed";
        } else {
            why += std::string(" | direct open: ") + std::strerror(errno);
        }
    }

    if (!wrote) {
        std::fprintf(stderr, "[REP-SAVE-FAIL] path=%s cleared_immutable=%d reason=%s\n",
                     path_.c_str(), (int)cleared, why.c_str());
    }

    ::chmod(path_.c_str(), 0600);
    if (wrote && cleared) set_immutable(true);
    return wrote;
}

bool Reputation::is_blacklisted(const std::string &hash) const {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = entries_.find(key(REP_BLACKLIST, hash));
    return it != entries_.end() && !it->second.paused;
}

bool Reputation::is_whitelisted(const std::string &hash) const {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = entries_.find(key(REP_WHITELIST, hash));
    return it != entries_.end() && !it->second.paused;
}

bool Reputation::add(std::uint8_t kind, const std::string &hash,
                     const std::string &name, const std::string &path) {
    if (hash.empty()) {
        std::fprintf(stderr, "[REP-ADD-REJECT] empty hash (name='%s' path='%s')\n",
                     name.c_str(), path.c_str());
        return false;
    }
    {
        std::lock_guard<std::mutex> lk(mtx_);
        RepEntry e;
        e.hash = hash; e.name = name; e.path = path;
        e.added_tstr = rep_now_str();
        e.kind = kind; e.paused = false;
        entries_[key(kind, hash)] = e;
    }
    bool ok = save();
    std::fprintf(stderr, "[REP-ADD] kind=%d hash=%.12s name='%s' saved=%d\n",
                 (int)kind, hash.c_str(), name.c_str(), (int)ok);
    return ok;
}

bool Reputation::remove(const std::string &hash, std::uint8_t kind) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = entries_.find(key(kind, hash));
        if (it == entries_.end()) return false;
        entries_.erase(it);
    }
    return save();
}

bool Reputation::set_paused(const std::string &hash, std::uint8_t kind, bool paused) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = entries_.find(key(kind, hash));
        if (it == entries_.end()) return false;
        it->second.paused = paused;
    }
    return save();
}

std::vector<RepEntry> Reputation::list() const {
    std::lock_guard<std::mutex> lk(mtx_);
    std::vector<RepEntry> out;
    out.reserve(entries_.size());
    for (auto &kv : entries_) out.push_back(kv.second);
    std::sort(out.begin(), out.end(), [](const RepEntry &a, const RepEntry &b) {
        if (a.kind != b.kind) return a.kind < b.kind;
        return a.added_tstr > b.added_tstr;
    });
    return out;
}

std::size_t Reputation::count() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return entries_.size();
}