#include "ui.h"
#include "ui_common.h"
#include "seccomp_filter.h"
#include <ftxui/component/component.hpp>
#include <ftxui/component/component_base.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/mouse.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/color.hpp>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace ftxui;
using uic::risk_color;
using uic::fmt_pct;
using uic::hclip;
using uic::wrap_indent;

enum ActiveModal { AM_NONE = 0, AM_SECCOMP, AM_EBPF, AM_REPMAN, AM_LAUNCH, AM_SUPOUT };

struct FlatRow {
    int depth;
    std::uint32_t pid;
    std::string comm;
    double risk_pct;
    double badge_risk;
    bool is_dead;
    bool is_new;
    bool is_anchor;
    bool exempt;
    bool frozen;
    bool blocked;
    bool supervised;
};

Ui::Ui(std::shared_ptr<Tracker> t, std::shared_ptr<SeccompSupervisor> sup, Keymap km)
    : tr_(std::move(t)), sup_(std::move(sup)), km_(std::move(km)) {}
void Ui::stop() { stop_.store(true); }

static void collapse_walk(const SnapNode &n, int depth, bool parent_exempt,
                          bool anchor_used, std::vector<FlatRow> &out) {
    if (!n.exempt) {
        out.push_back({depth, n.pid, n.comm, n.risk_pct, n.badge_risk,
                       n.is_dead, n.is_new, false, false, n.frozen, n.blocked, n.supervised});
        for (auto &c : n.children) collapse_walk(c, depth + 1, false, anchor_used, out);
    } else {
        bool anchor = (!anchor_used && !parent_exempt);
        if (anchor) {
            out.push_back({depth, n.pid, n.comm, n.risk_pct, 0.0,
                           n.is_dead, n.is_new, true, true, false, false, n.supervised});
            for (auto &c : n.children) collapse_walk(c, depth + 1, true, true, out);
        } else {
            for (auto &c : n.children) collapse_walk(c, depth, true, anchor_used, out);
        }
    }
}

static void newonly_walk(const SnapNode &n, std::vector<FlatRow> &out) {
    if (n.is_new && !n.exempt)
        out.push_back({0, n.pid, n.comm, n.risk_pct, n.badge_risk,
                       n.is_dead, true, false, false, n.frozen, n.blocked, n.supervised});
    for (auto &c : n.children) newonly_walk(c, out);
}

static std::vector<FlatRow> build_flat(const Snapshot &snap, bool new_only) {
    std::vector<FlatRow> rows;
    if (new_only) for (auto &r : snap.roots) newonly_walk(r, rows);
    else          for (auto &r : snap.roots) collapse_walk(r, 0, false, false, rows);
    return rows;
}

static Element make_row(const FlatRow &r, bool selected, int hoff) {
    std::string prefix(r.depth * 2, ' ');
    prefix += r.is_new ? "* " : "  ";
    std::string label = prefix + "[" + std::to_string(r.pid) + "] " + r.comm
                        + " - " + fmt_pct(r.risk_pct);
    if (r.supervised) label += " (WATCHED)";
    else if (r.blocked) label += " (BLOCKED)";
    else if (r.frozen) label += " (FROZEN)";
    else if (r.is_dead) label += " (dead)";
    if (r.is_anchor) label += "  <shell>";
    Color c;
    if (r.supervised)     c = Color::CyanLight;
    else if (r.blocked)   c = Color::Magenta;
    else if (r.frozen)    c = Color::Cyan;
    else if (r.is_dead)   c = r.risk_pct >= 0.20 ? Color::Red : Color::GrayDark;
    else if (r.is_anchor) c = Color::GrayDark;
    else if (r.exempt)    c = Color::GrayLight;
    else                  c = risk_color(r.risk_pct);

    Elements parts;
    Element base = text(hclip(label, hoff)) | color(c);
    if (r.frozen || r.blocked || r.supervised) base = base | bold;
    parts.push_back(base);
    if (r.badge_risk > 0.05) {
        std::string chip = " sub " + fmt_pct(r.badge_risk) + " ";
        Element ce = text(chip) | bgcolor(risk_color(r.badge_risk)) | color(Color::Black) | bold;
        if (r.is_dead) ce = ce | dim;
        parts.push_back(ce);
    }
    Element el = hbox(std::move(parts));
    if (selected) el = el | inverted | focus;
    return el;
}

static Element build_legend() {
    auto sw = [](const char *lbl, Color c) {
        return hbox({ text(" \u25A0 ") | color(c), text(lbl) | color(Color::GrayLight) });
    };
    return window(text(" Legend ") | bold,
        vbox({
            hbox({ sw("low <20%", Color::Green), sw("med", Color::Yellow), sw("high >75%", Color::Red) }),
            hbox({ sw("watched(seccomp)", Color::CyanLight), sw("blocked", Color::Magenta), sw("frozen", Color::Cyan) }),
            hbox({ sw("exempt/trusted", Color::GrayLight), sw("dead", Color::GrayDark) }),
            text(" * = new process   sub = riskiest child   [?] all keybinds") | dim,
        }));
}

static Element build_tree_pane(const Snapshot &snap, int &sel, bool new_only, int hoff, bool focused) {
    std::vector<FlatRow> rows = build_flat(snap, new_only);
    std::string title = focused ? " Lineage & State  [FOCUSED] " : " Lineage & State ";
    if (rows.empty()) {
        Element w = window(text(title) | bold,
                      vbox({ text(" (no processes match filter) ") | dim | center | flex }));
        return focused ? (w | color(Color::White)) : w;
    }
    if (sel < 0) sel = 0;
    if (sel >= (int)rows.size()) sel = (int)rows.size() - 1;
    Elements list;
    list.reserve(rows.size());
    for (int i = 0; i < (int)rows.size(); i++) list.push_back(make_row(rows[i], i == sel && focused, hoff));
    char meta[240];
    std::snprintf(meta, sizeof(meta),
        " %s | row %d/%zu | live=%zu new=%zu frozen=%zu watched=%zu ",
        new_only ? "NEW ONLY (a: all)" : "ALL (n: new only)",
        sel + 1, rows.size(), snap.live_nodes, snap.new_nodes,
        snap.frozen_count, snap.supervised_count);
    Element w = window(text(title) | bold,
                  vbox({ text(meta) | dim, separator(),
                         vbox(std::move(list)) | vscroll_indicator | yframe | flex }));
    return focused ? (w | color(Color::White)) : w;
}

static Element build_gauges_pane(const Snapshot &snap, int width) {
    Elements g;
    for (std::size_t i = 0; i < 3; i++) {
        if (i < snap.top3.size()) {
            auto &e = snap.top3[i];
            std::string org = (e.origin == e.comm) ? std::string() : (" <" + e.origin + ">");
            std::string lbl = "[" + std::to_string(e.pid) + "] " + e.comm + org + " " + fmt_pct(e.risk_pct);
            Color c = risk_color(e.risk_pct);
            g.push_back(wrap_indent(lbl, width, 2, c, false));
            g.push_back(gauge(static_cast<float>(e.risk_pct)) | color(c));
        } else {
            g.push_back(text(" (idle) ") | dim);
            g.push_back(gauge(0.0f) | color(Color::GrayDark));
        }
    }
    return window(text(" Threat Gauges (highest live risk) ") | bold, vbox(std::move(g)));
}

static Element build_watchlist_pane(const Snapshot &snap, int width) {
    Elements w;
    if (snap.watchlist.empty()) {
        w.push_back(text(" (empty; a process is listed once its risk peaks >= 40%) ") | dim);
    } else {
        std::size_t limit = std::min<std::size_t>(8, snap.watchlist.size());
        for (std::size_t i = 0; i < limit; i++) {
            auto &e = snap.watchlist[i];
            std::string org = (e.origin == e.comm) ? std::string("self") : e.origin;
            std::string head = e.first_tstr + (e.is_dead ? " x " : "   ")
                + "[" + std::to_string(e.pid) + "] ";
            std::string body = e.comm + " from:" + org
                + " peak=" + fmt_pct(e.peak_risk_pct)
                + " now=" + fmt_pct(e.current_risk_pct)
                + " kids=" + std::to_string(e.child_count)
                + " stages=" + (e.stages.empty() ? std::string("-") : e.stages);
            Color c = e.is_dead ? Color::GrayDark : risk_color(e.peak_risk_pct);
            int indent = (int)head.size();
            w.push_back(wrap_indent(head + body, width, indent, c, false));
        }
    }
    return window(text(" Watchlist [time | from:launcher | stages L/X/M/P/E/C] ") | bold,
                  vbox(std::move(w)) | vscroll_indicator | yframe);
}

static Element build_masq_pane(const Snapshot &snap, int width) {
    Elements m;
    if (snap.masq_events.empty()) {
        m.push_back(text(" (no process-rename events seen) ") | dim);
    } else {
        for (auto &e : snap.masq_events) {
            std::string head = e.tstr + " [" + std::to_string(e.pid) + "] ";
            std::string body = "'" + e.old_comm + "' -> '" + e.new_comm + "'"
                + (e.suspicious ? "  (suspicious!)" : "");
            Color c = e.suspicious ? Color::Magenta : Color::GrayLight;
            int indent = (int)head.size();
            m.push_back(wrap_indent(head + body, width, indent, c, e.suspicious));
        }
    }
    return window(text(" Process Rename / Masquerade Log ") | bold,
                  vbox(std::move(m)) | vscroll_indicator | yframe);
}

static Color alert_color(const std::string &s) {
    if (s.find("[SECCOMP]") != std::string::npos) return Color::CyanLight;
    if (s.find("[BURST]") != std::string::npos) return Color::Red;
    if (s.find("REP-BLOCK") != std::string::npos) return Color::Red;
    if (s.find("REP-ALLOW") != std::string::npos) return Color::Green;
    if (s.find("[BLACKLIST]") != std::string::npos) return Color::Red;
    if (s.find("[WHITELIST+]") != std::string::npos) return Color::Green;
    if (s.find("LSM-DENY") != std::string::npos) return Color::Magenta;
    if (s.find("[BLOCK]") != std::string::npos) return Color::Magenta;
    if (s.find("[REP]") != std::string::npos) return Color::Cyan;
    if (s.find("[LSM]") != std::string::npos) return Color::Cyan;
    if (s.find("KILL") != std::string::npos) return Color::Red;
    if (s.find("FREEZE") != std::string::npos) return Color::Cyan;
    if (s.find("RESUME") != std::string::npos) return Color::Green;
    if (s.find("WHITELIST") != std::string::npos) return Color::Green;
    if (s.find("MASQUERADE") != std::string::npos) return Color::Magenta;
    if (s.find("[hook]") != std::string::npos) return Color::Cyan;
    return Color::Yellow;
}

static Element build_audit_pane(const std::vector<std::string> &lines, int width,
                                int &focus_row) {
    int n = (int)lines.size();
    Elements a;
    if (n == 0) {
        a.push_back(text(" (no alerts yet) ") | dim);
        focus_row = 0;
    } else {
        if (focus_row < 0) focus_row = 0;
        if (focus_row >= n) focus_row = n - 1;
        for (int i = 0; i < n; i++) {
            Element e = wrap_indent(lines[i], width, 2, alert_color(lines[i]), false);
            if (i == focus_row) e = e | ftxui::focus;
            a.push_back(e);
        }
    }
    char title[80];
    std::snprintf(title, sizeof(title), " Audit Log — %d/%d (PgUp/PgDn, End=live) ",
                  n ? focus_row + 1 : 0, n);
    return window(text(title) | bold,
                  vbox(std::move(a)) | vscroll_indicator | yframe | flex);
}

static Element kv_line(const char *k, const std::string &v, Color vc) {
    return hbox({ text(std::string("  ") + k) | color(Color::GrayLight),
                  text(v) | color(vc) | bold });
}

static Element build_ebpf_modal(const PromptReq &p, const Keymap &km, int width) {
    std::string org = (p.origin == p.comm) ? std::string() : (" (from " + p.origin + ")");
    int inner = width - 6;
    if (inner < 24) inner = 24;
    std::string banner = p.from_burst
        ? "  BURST AUTO-BLOCKED — CONFIRM OR OVERRIDE  "
        : "  eBPF THREAT — PROCESS SUSPENDED  ";
    Elements v;
    v.push_back(text(banner) | bold | color(Color::Black) | bgcolor(Color::Red) | center);
    v.push_back(text(""));
    v.push_back(wrap_indent("Process: [" + std::to_string(p.pid) + "] " + p.comm + org,
                            inner, 9, Color::White, true));
    v.push_back(kv_line("Risk:    ", fmt_pct(p.risk), risk_color(p.risk)));
    if (!p.path.empty())
        v.push_back(wrap_indent("Binary:  " + p.path, inner, 9, Color::GrayLight, false));
    v.push_back(wrap_indent("Reason:  it tried to " + p.doing, inner, 9, Color::Yellow, false));
    if (p.from_burst)
        v.push_back(text("           kernel already blocked it; your choice overrides") | dim);
    else
        v.push_back(text("           that action ran; it is suspended before the next one") | dim);
    v.push_back(text(""));
    v.push_back(separator());
    v.push_back(text(" WHAT DO YOU WANT TO DO?") | bold | color(Color::White));
    auto opt = [&](KmAction a, const char *desc, Color c) {
        return hbox({ text("  [" + km.key_for(a) + "] ") | color(c) | bold,
                      text(desc) | color(Color::GrayLight) });
    };
    v.push_back(opt(KM_ALLOW, "Allow — let it continue running", Color::Green));
    v.push_back(opt(KM_DENY, "Deny — keep it suspended, do nothing", Color::Yellow));
    v.push_back(opt(KM_BLOCK, "Block — resume, but deny its risky syscalls (kernel)", Color::Magenta));
    v.push_back(opt(KM_KILL, "Kill — terminate the whole process group", Color::Red));
    v.push_back(separator());
    v.push_back(text(" REMEMBER THIS BINARY (by hash, saved to disk):") | bold | color(Color::White));
    v.push_back(opt(KM_BLACKLIST, "Blacklist — always auto-block this binary in future", Color::Red));
    v.push_back(opt(KM_WHITELIST, "Whitelist — always trust this binary in future", Color::Green));
    v.push_back(opt(KM_SESSION_WL, "Session-allow — trust only until EDR restarts", Color::Cyan));
    v.push_back(text("  [Esc] Dismiss (leave it suspended, decide later)") | dim);
    return window(text(" DECISION REQUIRED ") | bold | color(Color::Red),
                  vbox(std::move(v)) | vscroll_indicator | yframe)
           | size(WIDTH, EQUAL, width) | bgcolor(Color::Black) | clear_under;
}

static Element build_seccomp_modal(const SeccompPrompt &p, const Keymap &km, int width) {
    int inner = width - 6;
    if (inner < 24) inner = 24;
    Elements v;
    v.push_back(text("  SUPERVISED SYSCALL — FROZEN IN KERNEL  ")
                | bold | color(Color::Black) | bgcolor(Color::CyanLight) | center);
    v.push_back(text(""));
    v.push_back(wrap_indent("Process: [" + std::to_string(p.pid) + "] "
                            + (p.comm.empty() ? std::string("?") : p.comm),
                            inner, 9, Color::White, true));
    if (!p.exe_path.empty())
        v.push_back(wrap_indent("Path:    " + p.exe_path, inner, 9, Color::GrayLight, false));
    v.push_back(wrap_indent("Syscall: " + p.syscall_label, inner, 9, Color::CyanLight, true));
    char args[96];
    std::snprintf(args, sizeof(args), "arg0=0x%llx arg1=0x%llx arg2=0x%llx",
                  (unsigned long long)p.args[0], (unsigned long long)p.args[1],
                  (unsigned long long)p.args[2]);
    v.push_back(wrap_indent(std::string("Args:    ") + args, inner, 9, Color::GrayLight, false));
    v.push_back(text(""));

    std::string riskline;
    Color rc = Color::GrayLight;
    const char *who = p.has_parent ? "worker " : "eBPF confidence: ";
    if (!p.risk_known) {
        riskline = std::string(who) + "— (not yet in eBPF model)";
    } else if (p.scores_ebpf) {
        riskline = std::string(who) + fmt_pct(p.risk_current)
                 + "  ->  " + fmt_pct(p.risk_predicted) + " if allowed";
        rc = risk_color(p.risk_predicted);
    } else {
        riskline = std::string(who) + fmt_pct(p.risk_current)
                 + "  ->  " + fmt_pct(p.risk_current) + "  | Unmonitored syscall";
        rc = risk_color(p.risk_current);
    }
    v.push_back(wrap_indent(riskline, inner, 0, rc, true));
    if (p.has_parent) {
        std::string pcomm = p.parent_comm.empty() ? std::string("subtree") : p.parent_comm;
        std::string pline = "subtree (" + pcomm + "): " + fmt_pct(p.parent_current)
                          + "  ->  " + fmt_pct(p.parent_predicted);
        v.push_back(wrap_indent(pline, inner, 0, risk_color(p.parent_current), true));
    }
    v.push_back(text("  (held in-kernel until you decide)") | dim);
    v.push_back(text(""));
    v.push_back(separator());
    v.push_back(text(" ALLOW THIS SYSCALL TO RUN?") | bold | color(Color::White));
    auto opt = [&](KmAction a, const char *desc, Color c) {
        return hbox({ text("  [" + km.key_for(a) + "] ") | color(c) | bold,
                      text(desc) | color(Color::GrayLight) });
    };
    v.push_back(opt(KM_ALLOW, "Allow — the syscall proceeds normally", Color::Green));
    v.push_back(opt(KM_DENY, "Deny — the syscall returns EPERM (it fails)", Color::Yellow));
    v.push_back(opt(KM_KILL, "Kill — deny and terminate the process", Color::Red));
    v.push_back(separator());
    v.push_back(text(" REMEMBER THIS BINARY (by hash, saved to disk):") | bold | color(Color::White));
    v.push_back(opt(KM_BLACKLIST, "Blacklist — deny now; auto-block system-wide in future", Color::Red));
    v.push_back(opt(KM_WHITELIST, "Whitelist — allow now; auto-trust system-wide in future", Color::Green));
    return window(text(" SUPERVISED — DECISION REQUIRED ") | bold | color(Color::CyanLight),
                  vbox(std::move(v)) | vscroll_indicator | yframe)
           | size(WIDTH, EQUAL, width) | bgcolor(Color::Black) | clear_under;
}

static Element build_launch_modal(const std::string &buf, int width) {
    int inner = width - 6;
    if (inner < 24) inner = 24;
    Elements v;
    v.push_back(text("  LAUNCH A PROCESS UNDER SUPERVISION  ")
                | bold | color(Color::Black) | bgcolor(Color::CyanLight) | center);
    v.push_back(text(""));
    v.push_back(wrap_indent(" Type a command to run under the seccomp harness. Every risky"
                            " syscall it makes will freeze for your approval.", inner, 1,
                            Color::GrayLight, false));
    v.push_back(text(""));
    v.push_back(wrap_indent(" > " + buf + "_", inner, 3, Color::White, true));
    v.push_back(text(""));
    v.push_back(separator());
    v.push_back(text("  [Enter] launch    [Esc] cancel") | color(Color::GrayLight));
    v.push_back(text("  stdout is captured — press [o] to read it") | dim);
    v.push_back(text("  e.g.  ./bin/flood_trigger /tmp/fp.txt 1") | dim);
    return window(text(" SUPERVISE ") | bold | color(Color::CyanLight),
                  vbox(std::move(v)))
           | size(WIDTH, EQUAL, width) | bgcolor(Color::Black) | clear_under;
}

static Element build_supout_modal(const std::vector<std::string> &lines,
                                  const std::string &inbuf, bool input_mode,
                                  bool live, bool skip_on, std::uint32_t pid,
                                  std::uint64_t gated, std::uint64_t autoa,
                                  const Keymap &km, int width, int height) {
    int inner = width - 6;
    if (inner < 32) inner = 32;

    Elements body;
    if (lines.empty()) {
        body.push_back(text(" (no output captured yet) ") | dim | center);
    } else {
        for (std::size_t i = 0; i < lines.size(); i++) {
            Element e = wrap_indent(lines[i], inner, 2, Color::GrayLight, false);
            if (i + 1 == lines.size()) e = e | ftxui::focus;
            body.push_back(e);
        }
    }

    char meta[224];
    std::snprintf(meta, sizeof(meta),
        " %s | pid %u | gated: %llu | auto-allowed: %llu | skip-unmonitored: %s ",
        live ? "RUNNING" : "not running", pid,
        (unsigned long long)gated, (unsigned long long)autoa,
        skip_on ? "ON" : "off");

    Elements v;
    v.push_back(wrap_indent(meta, inner, 1, Color::GrayLight, false) | dim);
    v.push_back(separator());
    v.push_back(vbox(std::move(body)) | vscroll_indicator | yframe | flex);
    v.push_back(separator());

    if (input_mode) {
        v.push_back(wrap_indent(" > " + inbuf + "_", inner, 3, Color::White, true));
        v.push_back(text("  [Enter] send    [Esc] leave input mode") | color(Color::GrayLight));
    } else {
        std::string hint = "  [" + km.key_for(KM_SUP_INPUT) + "] stdin    ["
                         + km.key_for(KM_SUP_SKIP) + "] skip-unmonitored    ["
                         + km.key_for(KM_SUP_VIEW) + "] / [Esc] close";
        v.push_back(wrap_indent(hint, inner, 2, Color::GrayLight, false));
        if (!live) v.push_back(text("  (process exited — stdin closed)") | dim);
    }

    Color hdr = live ? Color::CyanLight : Color::GrayDark;
    return window(text(" Supervised Process Output ") | bold | color(hdr),
                  vbox(std::move(v)))
           | size(WIDTH, EQUAL, width) | size(HEIGHT, EQUAL, height)
           | bgcolor(Color::Black) | clear_under;
}

static std::vector<std::string> split_cmd(const std::string &s) {
    std::vector<std::string> out;
    std::istringstream iss(s);
    std::string tok;
    while (iss >> tok) out.push_back(tok);
    return out;
}

void Ui::run() {
    auto screen = ScreenInteractive::Fullscreen();
    int sel = 0;
    bool new_only = false;
    bool paused = false;
    ActiveModal modal = AM_NONE;
    bool repman_dirty = true;
    int repman_sel = 0;
    bool show_keys = false;
    int keys_scroll = 0;
    PromptReq ebpf_active;
    SeccompPrompt sec_active;
    std::string launch_buf;
    std::string sup_buf;
    bool sup_input = false;
    int arow = 0;
    bool afollow = true;
    int hoff_l = 0;

    Snapshot fsnap;
    std::vector<std::string> falerts;
    std::uint64_t prev_ev = 0;
    double prev_t = 0.0, ema_rate = 0.0;

    auto renderer = Renderer([&]() {
        if (modal == AM_NONE || modal == AM_SUPOUT) {
            SeccompPrompt sp;
            if (sup_ && sup_->peek_prompt(sp)) {
                sec_active = sp; modal = AM_SECCOMP; sup_input = false;
            } else if (modal == AM_NONE && tr_->prompts_enabled()) {
                auto p = tr_->take_prompt();
                if (p) { ebpf_active = *p; modal = AM_EBPF; }
            }
        }

        bool hold = (paused && modal == AM_NONE);
        Snapshot snap = hold ? fsnap : tr_->snapshot();
        std::vector<std::string> all = hold ? falerts : tr_->tail_alerts(999);

        {
            using namespace std::chrono;
            double nowt = duration<double>(steady_clock::now().time_since_epoch()).count();
            std::uint64_t ev = tr_->ev_count();
            if (prev_t > 0.0 && nowt > prev_t) {
                double inst = (double)(ev - prev_ev) / (nowt - prev_t);
                ema_rate = ema_rate * 0.7 + inst * 0.3;
            }
            prev_ev = ev; prev_t = nowt;
        }

        int atotal = (int)all.size();
        if (afollow) arow = std::max(0, atotal - 1);

        double wr = tr_->warmup_remaining();
        char armed[32];
        if (wr > 0.0) std::snprintf(armed, sizeof(armed), "WARMUP %.0fs", wr);
        else          std::snprintf(armed, sizeof(armed), "ARMED");

        std::string sup_state = "off";
        if (sup_ && sup_->active())
            sup_state = "pid " + std::to_string(sup_->child_pid());

        int right_w = std::max(44, std::min(62, screen.dimx() / 3));

        char status[560];
        std::snprintf(status, sizeof(status),
            " EDR | ev=%llu %.0f/s | kills=%llu burst=%llu rep=%llu deny=%llu | watch=%zu frozen=%zu blk=%zu | supervise:%s | ENF:%s | %s | %s | [%s]launch [%s]output [%s]rep [%s]keys [%s]quit ",
            (unsigned long long)tr_->ev_count(), ema_rate,
            (unsigned long long)tr_->kills_issued(),
            (unsigned long long)tr_->burst_trips(),
            (unsigned long long)tr_->rep_blocks(),
            (unsigned long long)tr_->denies(),
            snap.watch_count, snap.frozen_count, tr_->blocks_active(),
            sup_state.c_str(),
            tr_->enforcement_on() ? "on" : "OFF",
            armed, new_only ? "NEW" : "ALL",
            km_.key_for(KM_LAUNCH).c_str(), km_.key_for(KM_SUP_VIEW).c_str(),
            km_.key_for(KM_REPMAN).c_str(),
            km_.key_for(KM_KEYPANE).c_str(), km_.key_for(KM_QUIT).c_str());

        Color barcol = (modal == AM_SECCOMP) ? Color::CyanLight
                     : (modal == AM_EBPF) ? Color::Red
                     : (modal == AM_SUPOUT) ? Color::CyanLight
                     : (modal != AM_NONE) ? Color::Red
                     : (paused ? Color::Magenta : Color::Blue);

        int rw_inner = right_w - 6;
        auto right = vbox({
            build_gauges_pane(snap, rw_inner)     | size(HEIGHT, EQUAL, 9),
            build_watchlist_pane(snap, rw_inner)  | size(HEIGHT, EQUAL, 13),
            build_masq_pane(snap, rw_inner)       | size(HEIGHT, EQUAL, 10),
            build_audit_pane(all, rw_inner, arow) | flex
        });

        Element bview = vbox({
            wrap_indent(status, screen.dimx(), 0, Color::White, true) | bgcolor(barcol),
            hbox({
                build_tree_pane(snap, sel, new_only, hoff_l, modal == AM_NONE) | flex_grow,
                right | size(WIDTH, EQUAL, right_w)
            }) | flex,
            build_legend()
        });

        int mw = std::min(84, std::max(40, screen.dimx() - 4));

        if (modal == AM_SECCOMP)
            return dbox({ bview | dim, build_seccomp_modal(sec_active, km_, mw) | center });
        if (modal == AM_EBPF)
            return dbox({ bview | dim, build_ebpf_modal(ebpf_active, km_, mw) | center });
        if (modal == AM_LAUNCH)
            return dbox({ bview | dim, build_launch_modal(launch_buf, mw) | center });
        if (modal == AM_SUPOUT) {
            int ow = std::min(screen.dimx() - 4, std::max(50, screen.dimx() * 4 / 5));
            int oh = std::max(12, screen.dimy() - 6);
            std::vector<std::string> lines;
            bool live = false, skip_on = false;
            std::uint32_t cpid = 0;
            std::uint64_t gated = 0, autoa = 0;
            if (sup_) {
                lines = sup_->output_lines(400);
                live = sup_->active();
                skip_on = sup_->skip_unmonitored();
                cpid = sup_->child_pid();
                gated = sup_->gated_count();
                autoa = sup_->auto_allowed();
            }
            return dbox({ bview | dim,
                          build_supout_modal(lines, sup_buf, sup_input, live, skip_on,
                                             cpid, gated, autoa, km_, ow, oh) | center });
        }
        if (modal == AM_REPMAN) {
            int rw = std::min(screen.dimx() - 4, std::max(50, screen.dimx() * 3 / 4));
            return dbox({ bview | dim,
                          build_repman_view(tr_, rw, repman_sel, repman_dirty) | center });
        }
        if (show_keys) {
            int kw = std::min(72, std::max(40, screen.dimx() - 4));
            int kh = std::max(10, screen.dimy() - 6);
            return dbox({ bview | dim, build_keybind_modal(km_, kw, kh, keys_scroll) | center });
        }
        return bview;
    });

    auto with_keys = CatchEvent(renderer, [&](Event e) {
        if (modal == AM_SECCOMP) {
            SeccompDecision d = SD_PENDING;
            if (km_.matches(e, KM_ALLOW)) d = SD_ALLOW;
            else if (km_.matches(e, KM_DENY)) d = SD_DENY;
            else if (km_.matches(e, KM_KILL)) d = SD_KILL;
            else if (km_.matches(e, KM_BLACKLIST)) d = SD_BLACKLIST;
            else if (km_.matches(e, KM_WHITELIST)) d = SD_WHITELIST;
            else if (e == Event::Escape) return true;
            if (d != SD_PENDING) {
                if (sup_) sup_->resolve(sec_active.token, d);
                if (d == SD_BLACKLIST || d == SD_WHITELIST) repman_dirty = true;
                modal = AM_NONE;
            }
            return true;
        }
        if (modal == AM_EBPF) {
            char dec = 0;
            if (km_.matches(e, KM_ALLOW)) dec = 'y';
            else if (km_.matches(e, KM_DENY)) dec = 'n';
            else if (km_.matches(e, KM_BLOCK)) dec = 'b';
            else if (km_.matches(e, KM_BLACKLIST)) { dec = 'd'; repman_dirty = true; }
            else if (km_.matches(e, KM_WHITELIST)) { dec = 'l'; repman_dirty = true; }
            else if (km_.matches(e, KM_KILL)) dec = 'k';
            else if (km_.matches(e, KM_SESSION_WL)) dec = 'w';
            else if (e == Event::Escape) dec = 'x';
            if (dec) { tr_->resolve_prompt(ebpf_active.uid, ebpf_active.pgid, dec); modal = AM_NONE; }
            return true;
        }
        if (modal == AM_SUPOUT) {
            if (sup_input) {
                if (e == Event::Escape) { sup_input = false; return true; }
                if (e == Event::Return) {
                    if (sup_ && sup_->active()) sup_->write_stdin(sup_buf);
                    sup_buf.clear();
                    return true;
                }
                if (e == Event::Backspace) {
                    if (!sup_buf.empty()) sup_buf.pop_back();
                    return true;
                }
                if (e.is_character()) {
                    std::string ch = e.character();
                    if (!ch.empty() && (unsigned char)ch[0] >= 0x20) sup_buf += ch;
                    return true;
                }
                return true;
            }
            if (e == Event::Escape || km_.matches(e, KM_SUP_VIEW)) {
                modal = AM_NONE; sup_buf.clear(); return true;
            }
            if (km_.matches(e, KM_SUP_INPUT)) {
                if (sup_ && sup_->active()) sup_input = true;
                return true;
            }
            if (km_.matches(e, KM_SUP_SKIP)) {
                if (sup_) sup_->set_skip_unmonitored(!sup_->skip_unmonitored());
                return true;
            }
            return true;
        }
        if (modal == AM_REPMAN) {
            bool close_req = false;
            repman_handle_key(tr_, e, km_, repman_sel, close_req);
            if (close_req || e == Event::Escape) modal = AM_NONE;
            return true;
        }
        if (modal == AM_LAUNCH) {
            if (e == Event::Escape) { modal = AM_NONE; launch_buf.clear(); return true; }
            if (e == Event::Return) {
                auto argv = split_cmd(launch_buf);
                modal = AM_NONE;
                std::string lb = launch_buf;
                launch_buf.clear();
                if (!argv.empty() && sup_) {
                    SeccompGates g;
                    std::string err;
                    if (sup_->launch(argv, g, err)) {
                        tr_->register_supervised(sup_->child_pid());
                        tr_->push_alert("[SECCOMP] launched under supervision: " + lb);
                        sup_buf.clear();
                        sup_input = false;
                        modal = AM_SUPOUT;
                    } else {
                        tr_->push_alert("[SECCOMP] launch failed: " + err);
                    }
                }
                return true;
            }
            if (e == Event::Backspace) {
                if (!launch_buf.empty()) launch_buf.pop_back();
                return true;
            }
            if (e.is_character()) {
                std::string ch = e.character();
                if (!ch.empty() && (unsigned char)ch[0] >= 0x20) launch_buf += ch;
                return true;
            }
            return true;
        }
        if (show_keys) {
            int n = keybind_row_count();
            if (e == Event::ArrowDown || km_.matches(e, KM_SEL_DOWN)) { keys_scroll = std::min(n - 1, keys_scroll + 1); return true; }
            if (e == Event::ArrowUp || km_.matches(e, KM_SEL_UP)) { keys_scroll = std::max(0, keys_scroll - 1); return true; }
            if (e == Event::PageDown) { keys_scroll = std::min(n - 1, keys_scroll + 10); return true; }
            if (e == Event::PageUp) { keys_scroll = std::max(0, keys_scroll - 10); return true; }
            if (e == Event::Home) { keys_scroll = 0; return true; }
            if (e == Event::End) { keys_scroll = n - 1; return true; }
            if (e.is_mouse()) {
                auto m = e.mouse();
                if (m.button == Mouse::WheelUp) { keys_scroll = std::max(0, keys_scroll - 2); return true; }
                if (m.button == Mouse::WheelDown) { keys_scroll = std::min(n - 1, keys_scroll + 2); return true; }
                return true;
            }
            if (e == Event::Escape || km_.matches(e, KM_KEYPANE)) { show_keys = false; keys_scroll = 0; return true; }
            return true;
        }

        Snapshot snap = paused ? fsnap : tr_->snapshot();
        auto rows = build_flat(snap, new_only);
        int max_sel = std::max(0, (int)rows.size() - 1);
        int atotal = (int)tr_->tail_alerts(999).size();
        int amax = std::max(0, atotal - 1);

        if (km_.matches(e, KM_QUIT)) {
            stop_.store(true); tr_->stop(); if (sup_) sup_->stop();
            screen.ExitLoopClosure()(); return true;
        }
        if (km_.matches(e, KM_LAUNCH)) { modal = AM_LAUNCH; launch_buf.clear(); return true; }
        if (km_.matches(e, KM_SUP_VIEW)) { modal = AM_SUPOUT; sup_input = false; sup_buf.clear(); return true; }
        if (km_.matches(e, KM_REPMAN)) { modal = AM_REPMAN; repman_dirty = true; repman_sel = 0; return true; }
        if (km_.matches(e, KM_KEYPANE)) { show_keys = true; keys_scroll = 0; return true; }
        if (km_.matches(e, KM_PAUSE)) {
            paused = !paused;
            if (paused) { fsnap = tr_->snapshot(); falerts = tr_->tail_alerts(999); }
            return true;
        }

        if (e == Event::PageUp)   { afollow = false; arow = std::max(0, arow - 10); return true; }
        if (e == Event::PageDown) { arow = std::min(amax, arow + 10); afollow = (arow >= amax); return true; }
        if (e == Event::Home)     { afollow = false; arow = 0; return true; }
        if (e == Event::End)      { afollow = true; return true; }

        if (e == Event::ArrowUp || km_.matches(e, KM_SEL_UP)) { sel = std::max(0, sel - 1); return true; }
        if (e == Event::ArrowDown || km_.matches(e, KM_SEL_DOWN)) { sel = std::min(max_sel, sel + 1); return true; }
        if (km_.matches(e, KM_SEL_TOP)) { sel = 0; return true; }
        if (km_.matches(e, KM_SEL_BOTTOM)) { sel = max_sel; return true; }
        if (km_.matches(e, KM_NEWONLY)) { new_only = true; sel = 0; return true; }
        if (km_.matches(e, KM_ALL)) { new_only = false; sel = 0; return true; }
        if (km_.matches(e, KM_RESET_H)) { hoff_l = 0; return true; }
        if (km_.matches(e, KM_ENFORCE)) { tr_->set_enforcement(!tr_->enforcement_on()); return true; }
        if (km_.matches(e, KM_CLEAR)) { tr_->flush_blocks(); return true; }
        if (km_.matches(e, KM_PURGE)) { tr_->purge_dead(false); return true; }

        if (e.is_mouse()) {
            auto m = e.mouse();
            if (m.button != Mouse::WheelUp && m.button != Mouse::WheelDown) return false;
            bool up = (m.button == Mouse::WheelUp);
            int right_w = std::max(44, std::min(62, screen.dimx() / 3));
            bool over_right = (m.x >= screen.dimx() - right_w);
            if (over_right) {
                if (up) { afollow = false; arow = std::max(0, arow - 2); }
                else    { arow = std::min(amax, arow + 2); afollow = (arow >= amax); }
            } else {
                if (m.shift) hoff_l = up ? std::max(0, hoff_l - 4) : hoff_l + 4;
                else         sel    = up ? std::max(0, sel - 1)    : std::min(max_sel, sel + 1);
            }
            return true;
        }
        return false;
    });

    std::thread refresh([&]() {
        while (!stop_.load() && tr_->running()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(120));
            screen.PostEvent(Event::Custom);
        }
    });
    screen.Loop(with_keys);
    stop_.store(true);
    if (sup_) sup_->stop();
    if (refresh.joinable()) refresh.join();
}