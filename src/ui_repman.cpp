#include "ui.h"
#include "ui_common.h"
#include "reputation.h"
#include "keymap.h"
#include <ftxui/component/event.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/color.hpp>
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

using namespace ftxui;

static std::vector<RepEntry> g_repview;
static std::vector<SessionEntry> g_sessview;

struct KBRow { const char *label; KmAction action; const char *desc; bool header; };

static std::vector<KBRow> keybind_rows() {
    return {
        { "DASHBOARD", KM_COUNT, "", true },
        { nullptr, KM_SEL_DOWN, "move selection down", false },
        { nullptr, KM_SEL_UP, "move selection up", false },
        { nullptr, KM_SEL_TOP, "jump to top", false },
        { nullptr, KM_SEL_BOTTOM, "jump to bottom", false },
        { nullptr, KM_NEWONLY, "show new processes only", false },
        { nullptr, KM_ALL, "show all processes", false },
        { nullptr, KM_PAUSE, "pause / resume view", false },
        { nullptr, KM_ENFORCE, "toggle kernel enforcement", false },
        { nullptr, KM_CLEAR, "clear all active blocks", false },
        { nullptr, KM_PURGE, "purge dead processes from tree", false },
        { nullptr, KM_LAUNCH, "launch a supervised process", false },
        { nullptr, KM_SUP_VIEW, "view supervised output", false },
        { nullptr, KM_REPMAN, "open reputation manager", false },
        { nullptr, KM_KEYPANE, "toggle this help", false },
        { nullptr, KM_RESET_H, "reset horizontal scroll", false },
        { nullptr, KM_QUIT, "quit", false },

        { "AUDIT LOG (right pane)", KM_COUNT, "", true },
        { "   PgUp / PgDn   scroll through history", KM_COUNT, "", true },
        { "   Home / End    oldest / live tail", KM_COUNT, "", true },
        { "   wheel         scroll (hover right pane)", KM_COUNT, "", true },

        { "eBPF DECISION MODAL", KM_COUNT, "", true },
        { nullptr, KM_ALLOW, "allow (resume)", false },
        { nullptr, KM_DENY, "deny (keep suspended)", false },
        { nullptr, KM_BLOCK, "block risky syscalls (kernel)", false },
        { nullptr, KM_KILL, "kill process group", false },
        { nullptr, KM_BLACKLIST, "blacklist binary (hash)", false },
        { nullptr, KM_WHITELIST, "whitelist binary (hash)", false },
        { nullptr, KM_SESSION_WL, "session-only allow", false },

        { "SUPERVISED (seccomp) MODAL", KM_COUNT, "", true },
        { nullptr, KM_ALLOW, "allow this syscall", false },
        { nullptr, KM_DENY, "deny this syscall (EPERM)", false },
        { nullptr, KM_KILL, "deny and kill", false },
        { nullptr, KM_BLACKLIST, "blacklist binary (hash)", false },
        { nullptr, KM_WHITELIST, "whitelist binary (hash)", false },

        { "SUPERVISED OUTPUT VIEW", KM_COUNT, "", true },
        { nullptr, KM_SUP_INPUT, "type into its stdin", false },
        { nullptr, KM_SUP_SKIP, "toggle skip-unmonitored syscalls", false },
        { nullptr, KM_SUP_VIEW, "close the output view", false },

        { "REPUTATION MANAGER", KM_COUNT, "", true },
        { nullptr, KM_REP_PAUSE, "pause / resume a rule", false },
        { nullptr, KM_REP_REMOVE, "remove a rule", false },

        { "Esc always cancels / closes.", KM_COUNT, "", true },
    };
}

int keybind_row_count() { return (int)keybind_rows().size(); }

ftxui::Element build_keybind_modal(const Keymap &km, int width, int height, int scroll) {
    auto rows = keybind_rows();
    int n = (int)rows.size();
    if (scroll < 0) scroll = 0;
    if (scroll >= n) scroll = n - 1;

    int inner = width - 4;
    if (inner < 24) inner = 24;

    Elements v;
    for (int i = 0; i < n; i++) {
        auto &r = rows[i];
        Element e;
        if (r.header) {
            e = uic::wrap_indent(std::string(" ") + r.label, inner, 1, Color::Cyan, true);
        } else {
            std::string key = km.key_for(r.action);
            if (key == " ") key = "spc";
            std::string line = " [" + key + "]";
            while (line.size() < 8) line += ' ';
            line += r.desc;
            e = uic::wrap_indent(line, inner, 8, Color::GrayLight, false);
        }
        if (i == scroll) e = e | focus;
        v.push_back(e);
    }

    char title[80];
    std::snprintf(title, sizeof(title), " Keybinds — %d/%d — j/k or arrows, Esc closes ",
                  scroll + 1, n);

    return window(text(title) | bold | color(Color::Cyan),
                  vbox(std::move(v)) | vscroll_indicator | yframe | flex)
           | size(WIDTH, EQUAL, width) | size(HEIGHT, EQUAL, height)
           | bgcolor(Color::Black) | clear_under;
}

ftxui::Element build_repman_view(const std::shared_ptr<Tracker> &tr,
                                 int width, int &sel, bool &dirty) {
    auto rep = tr->reputation();
    if (dirty) {
        g_repview = rep ? rep->list() : std::vector<RepEntry>();
        g_sessview = tr->session_list();
        dirty = false;
    }
    int np = (int)g_repview.size();
    int ns = (int)g_sessview.size();
    int total = np + ns;
    int inner = width - 6;
    if (inner < 32) inner = 32;
    if (total > 0) {
        if (sel < 0) sel = 0;
        if (sel >= total) sel = total - 1;
    } else {
        sel = 0;
    }
    Elements rows;
    if (np == 0) {
        rows.push_back(text(" (no saved binaries yet — blacklist or whitelist one from a decision modal) ")
                       | dim);
    } else {
        for (int i = 0; i < np; i++) {
            auto &e = g_repview[i];
            const char *kind = (e.kind == REP_BLACKLIST) ? "BLOCK" : "TRUST";
            const char *st = e.paused ? "PAUSED" : "active";
            std::string head = std::string(" ") + kind + " " + st + "  ";
            std::string body = (e.name.empty() ? std::string("?") : e.name)
                + "  " + uic::short_hash(e.hash)
                + "  " + (e.path.empty() ? std::string("<path?>") : e.path)
                + "  (added " + e.added_tstr + ")";
            Color c;
            if (e.paused) c = Color::GrayDark;
            else if (e.kind == REP_BLACKLIST) c = Color::Red;
            else c = Color::Green;
            int indent = (int)head.size();
            Element row = uic::wrap_indent(head + body, inner, indent, c, (i == sel));
            if (i == sel) row = row | inverted | focus;
            rows.push_back(row);
        }
    }
    rows.push_back(separator());
    rows.push_back(text(" SESSION ALLOW — in memory only, cleared on restart ")
                   | bold | color(Color::Cyan));
    if (ns == 0) {
        rows.push_back(text(" (none — press [w] at a decision modal to trust a binary for this session) ")
                       | dim);
    } else {
        for (int i = 0; i < ns; i++) {
            auto &e = g_sessview[i];
            int idx = np + i;
            const char *st = e.paused ? "PAUSED" : "active";
            std::string head = std::string(" SESSION ") + st + "  ";
            std::string body = (e.name.empty() ? std::string("?") : e.name)
                + "  " + e.key
                + "  " + (e.path.empty() ? std::string("<path?>") : e.path)
                + "  (added " + e.added_tstr + ")";
            Color c = e.paused ? Color::GrayDark : Color::CyanLight;
            int indent = (int)head.size();
            Element row = uic::wrap_indent(head + body, inner, indent, c, (idx == sel));
            if (idx == sel) row = row | inverted | focus;
            rows.push_back(row);
        }
    }
    char meta[240];
    std::snprintf(meta, sizeof(meta),
        " saved=%d | session=%d | sel %d/%d | [p] pause/resume  [x] remove  [Esc] close ",
        np, ns, total ? sel + 1 : 0, total);
    Element tamper = rep && rep->tamper_flagged()
        ? (text(" ! reputation store checksum MISMATCH — possible tampering ! ")
           | bold | color(Color::Black) | bgcolor(Color::Red))
        : (text("") | dim);
    return window(text(" Reputation Manager — saved binary verdicts ") | bold | color(Color::Cyan),
                  vbox({ tamper, text(meta) | dim, separator(),
                         vbox(std::move(rows)) | vscroll_indicator | yframe | flex }))
           | size(WIDTH, EQUAL, width) | bgcolor(Color::Black) | clear_under;
}

bool repman_handle_key(const std::shared_ptr<Tracker> &tr,
                       const ftxui::Event &e, const Keymap &km,
                       int &sel, bool &close_req) {
    close_req = false;
    int np = (int)g_repview.size();
    int ns = (int)g_sessview.size();
    int n = np + ns;
    if (e == Event::Escape || km.matches(e, KM_REPMAN)) { close_req = true; return true; }
    if (e == Event::ArrowDown || km.matches(e, KM_SEL_DOWN)) { if (n > 0) sel = std::min(n - 1, sel + 1); return true; }
    if (e == Event::ArrowUp || km.matches(e, KM_SEL_UP)) { if (n > 0) sel = std::max(0, sel - 1); return true; }
    if (km.matches(e, KM_SEL_TOP)) { sel = 0; return true; }
    if (km.matches(e, KM_SEL_BOTTOM)) { sel = std::max(0, n - 1); return true; }
    if (e.is_mouse()) {
        ftxui::Event me = e;
        auto m = me.mouse();
        if (m.button == Mouse::WheelUp)   { if (n > 0) sel = std::max(0, sel - 1); return true; }
        if (m.button == Mouse::WheelDown) { if (n > 0) sel = std::min(n - 1, sel + 1); return true; }
        return true;
    }
    if (n == 0 || sel < 0 || sel >= n) return true;
    if (sel < np) {
        auto rep = tr->reputation();
        if (!rep) return true;
        RepEntry cur = g_repview[sel];
        if (km.matches(e, KM_REP_PAUSE)) {
            rep->set_paused(cur.hash, cur.kind, !cur.paused);
            if (cur.kind == REP_BLACKLIST) {
                if (!cur.paused) tr->unblock_hash_live(cur.hash);
                else             tr->reblock_from_reputation(cur.hash);
            }
            g_repview = rep->list();
            return true;
        }
        if (km.matches(e, KM_REP_REMOVE)) {
            rep->remove(cur.hash, cur.kind);
            if (cur.kind == REP_BLACKLIST) tr->unblock_hash_live(cur.hash);
            g_repview = rep->list();
            np = (int)g_repview.size();
            if (sel >= np + ns) sel = std::max(0, np + ns - 1);
            return true;
        }
        return true;
    }
    SessionEntry cur = g_sessview[sel - np];
    if (km.matches(e, KM_REP_PAUSE)) {
        tr->session_set_paused(cur.key, !cur.paused);
        g_sessview = tr->session_list();
        return true;
    }
    if (km.matches(e, KM_REP_REMOVE)) {
        tr->session_remove(cur.key);
        g_sessview = tr->session_list();
        ns = (int)g_sessview.size();
        if (sel >= np + ns) sel = std::max(0, np + ns - 1);
        return true;
    }
    return true;
}