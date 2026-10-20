/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "config.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdlib>
#include <deque>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach/mach.h>
#endif

#include "console_tui.h"

#include "configfile.h"
#include "datasourcetracker.h"
#include "devicetracker.h"
#include "globalregistry.h"
#include "kis_datasource.h"
#include "kis_net_beast_httpd.h"
#include "messagebus.h"
#include "util.h"
#include "version.h"

namespace {
    // Messages kept for the display, and printed when it stops
    constexpr size_t max_messages = 500;

    // Samples kept per graph; each braille character shows two
    constexpr size_t max_history = 1024;

    constexpr unsigned int min_message_rows = 5;

    struct tui_message {
        time_t ts;
        unsigned int flags;
        std::string text;
    };

    // History of one datasource; sources are matched by UUID between samples
    struct tui_source {
        std::string name;
        std::string type;
        bool running = false;
        bool error = false;
        bool paused = false;
        bool remote = false;
        uint64_t total = 0;
        bool have_total = false;
        double rate = 0;
        std::deque<double> rates;
        unsigned int last_seen = 0;
    };

    struct tui_state {
        std::mutex mutex;
        std::condition_variable cv;

        std::deque<tui_message> messages;

        std::atomic<bool> active{false};
        bool stopping = false;
        bool dirty = true;

        std::thread thread;

        bool utf8 = true;

        // Source order is the order sources were first seen
        std::vector<std::string> source_order;
        std::map<std::string, tui_source> sources;
        unsigned int sample_gen = 0;

        std::deque<double> devices;
        std::deque<double> memory;
        uint64_t last_devices = 0;
        uint64_t last_memory_kb = 0;

        time_t start_time = 0;
    };

    tui_state& state() {
        static tui_state s;
        return s;
    }

    void push_sample(std::deque<double>& d, double v) {
        d.push_back(v);
        while (d.size() > max_history)
            d.pop_front();
    }

    // Replace control characters (which could inject terminal escapes) and invalid UTF-8;
    // message text includes names and SSIDs from the air
    std::string sanitize(const std::string& in) {
        std::string out;
        out.reserve(in.size());

        size_t i = 0;
        while (i < in.size()) {
            auto c = (unsigned char) in[i];

            if (c == '\t') {
                out += ' ';
                i++;
                continue;
            }

            if (c < 0x20 || c == 0x7F) {
                out += '?';
                i++;
                continue;
            }

            if (c < 0x80) {
                out += (char) c;
                i++;
                continue;
            }

            size_t len = 0;
            uint32_t cp = 0;

            if ((c & 0xE0) == 0xC0) {
                len = 2;
                cp = c & 0x1F;
            } else if ((c & 0xF0) == 0xE0) {
                len = 3;
                cp = c & 0x0F;
            } else if ((c & 0xF8) == 0xF0) {
                len = 4;
                cp = c & 0x07;
            }

            bool valid = len != 0 && i + len <= in.size();

            for (size_t k = 1; valid && k < len; k++) {
                auto cc = (unsigned char) in[i + k];
                if ((cc & 0xC0) != 0x80)
                    valid = false;
                else
                    cp = (cp << 6) | (cc & 0x3F);
            }

            // Overlong forms, surrogates, out of range, and C1 controls
            if (valid && ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) ||
                        (len == 4 && cp < 0x10000) || cp > 0x10FFFF ||
                        (cp >= 0xD800 && cp <= 0xDFFF) || (cp >= 0x80 && cp < 0xA0)))
                valid = false;

            if (!valid) {
                out += '?';
                i++;
                continue;
            }

            out.append(in, i, len);
            i += len;
        }

        return out;
    }

    // Byte length of a sanitized UTF-8 character
    size_t char_len(const std::string& s, size_t pos) {
        auto c = (unsigned char) s[pos];
        if (c < 0x80)
            return 1;
        if ((c & 0xE0) == 0xC0)
            return 2;
        if ((c & 0xF0) == 0xE0)
            return 3;
        return 4;
    }

    size_t display_width(const std::string& s) {
        size_t w = 0;
        for (size_t i = 0; i < s.size(); i += char_len(s, i))
            w++;
        return w;
    }

    // Truncate a sanitized string to width columns, padding with spaces if pad is set
    std::string fit(const std::string& s, size_t width, bool pad) {
        std::string out;
        size_t w = 0, i = 0;

        while (i < s.size() && w < width) {
            auto l = char_len(s, i);
            out.append(s, i, l);
            i += l;
            w++;
        }

        if (pad && w < width)
            out.append(width - w, ' ');

        return out;
    }

    // Word wrap a sanitized string to width columns; continuation lines are indented
    std::vector<std::string> wrap(const std::string& s, size_t width, size_t indent) {
        std::vector<std::string> lines;

        if (width <= indent + 4) {
            lines.push_back(fit(s, width, false));
            return lines;
        }

        std::string line;
        size_t line_w = 0;
        size_t i = 0;
        size_t avail = width;

        while (i < s.size()) {
            // Next word, with the spaces before it
            size_t j = i, word_w = 0;
            while (j < s.size() && s[j] == ' ') {
                j++;
                word_w++;
            }
            while (j < s.size() && s[j] != ' ') {
                j += char_len(s, j);
                word_w++;
            }

            std::string word = s.substr(i, j - i);

            if (line_w + word_w > avail && line_w > 0) {
                lines.push_back(line);
                line = std::string(indent, ' ');
                line_w = indent;

                // Drop the spaces which ended the previous line
                size_t k = 0;
                while (k < word.size() && word[k] == ' ')
                    k++;
                word = word.substr(k);
                word_w -= k;
            }

            // Words longer than a line are split
            while (line_w + word_w > avail) {
                auto part = fit(word, avail - line_w, false);
                line += part;
                lines.push_back(line);
                word = word.substr(part.size());
                word_w -= display_width(part);
                line = std::string(indent, ' ');
                line_w = indent;
            }

            line += word;
            line_w += word_w;
            i = j;
        }

        if (line_w > 0 || lines.empty())
            lines.push_back(line);

        return lines;
    }

    // One line graph of the newest samples, two per character, scaled to the largest
    // visible sample; braille dots, or ASCII when the terminal isn't UTF-8
    std::string graph(const std::deque<double>& hist, size_t width, bool utf8,
            const char *color) {
        std::string out;

        if (width == 0)
            return out;

        size_t nsamples = std::min(hist.size(), width * 2);
        size_t start = hist.size() - nsamples;

        double max = 0;
        for (size_t i = start; i < hist.size(); i++)
            max = std::max(max, hist[i]);

        // Samples right aligned, so the newest is at the right edge
        size_t blank = (width * 2) - nsamples;

        auto level = [&](size_t slot) -> int {
            if (slot < blank)
                return -1;
            double v = hist[start + (slot - blank)];
            if (v <= 0 || max <= 0)
                return 0;
            return std::max(1, std::min(4, (int) std::ceil(v / max * 4)));
        };

        // Dots filled from the bottom of the left and right braille columns
        static const unsigned int left_dots[5] = { 0x00, 0x40, 0x44, 0x46, 0x47 };
        static const unsigned int right_dots[5] = { 0x00, 0x80, 0xA0, 0xB0, 0xB8 };
        static const char ascii_levels[5] = { '_', '.', ':', '|', '#' };

        bool colored = false;

        for (size_t c = 0; c < width; c++) {
            int l = level(c * 2), r = level(c * 2 + 1);

            if (l < 0 && r < 0) {
                if (colored) {
                    out += "\x1b[0m";
                    colored = false;
                }
                out += ' ';
                continue;
            }

            if (!colored) {
                out += color;
                colored = true;
            }

            if (!utf8) {
                out += ascii_levels[std::max(l, r) < 0 ? 0 : std::max(l, r)];
                continue;
            }

            // An idle stretch shows as a baseline
            unsigned int bits = 0;
            bits |= l <= 0 ? (l == 0 ? 0x40 : 0) : left_dots[l];
            bits |= r <= 0 ? (r == 0 ? 0x80 : 0) : right_dots[r];

            unsigned int cp = 0x2800 + bits;
            out += (char) (0xE0 | (cp >> 12));
            out += (char) (0x80 | ((cp >> 6) & 0x3F));
            out += (char) (0x80 | (cp & 0x3F));
        }

        if (colored)
            out += "\x1b[0m";

        return out;
    }

    std::string human_count(double v) {
        if (v >= 1e9)
            return fmt::format("{:.1f}G", v / 1e9);
        if (v >= 1e6)
            return fmt::format("{:.1f}M", v / 1e6);
        if (v >= 1e4)
            return fmt::format("{:.1f}k", v / 1e3);
        return fmt::format("{}", (uint64_t) v);
    }

    std::string human_kb(uint64_t kb) {
        if (kb >= 1024 * 1024)
            return fmt::format("{:.1f} GB", kb / (1024.0 * 1024.0));
        if (kb >= 1024)
            return fmt::format("{:.1f} MB", kb / 1024.0);
        return fmt::format("{} kB", kb);
    }

    std::string uptime_str(time_t secs) {
        if (secs < 0)
            secs = 0;
        if (secs >= 86400)
            return fmt::format("{}d{:02}h", secs / 86400, (secs % 86400) / 3600);
        if (secs >= 3600)
            return fmt::format("{}h{:02}m", secs / 3600, (secs % 3600) / 60);
        return fmt::format("{}m{:02}s", secs / 60, secs % 60);
    }

    // Resident memory of the server
    uint64_t resident_kb() {
#if defined(__linux__)
        FILE *f = fopen("/proc/self/statm", "r");
        if (f != nullptr) {
            unsigned long size = 0, resident = 0;
            int n = fscanf(f, "%lu %lu", &size, &resident);
            fclose(f);
            if (n == 2)
                return (uint64_t) resident * (uint64_t) sysconf(_SC_PAGESIZE) / 1024;
        }
        return 0;
#elif defined(__APPLE__)
        mach_task_basic_info_data_t info;
        mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
        if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t) &info, &count) == KERN_SUCCESS)
            return info.resident_size / 1024;
        return 0;
#else
        // Peak, not current, but the closest portable value
        struct rusage ru;
        if (getrusage(RUSAGE_SELF, &ru) == 0)
            return (uint64_t) ru.ru_maxrss;
        return 0;
#endif
    }

    bool terminal_utf8() {
        for (auto var : { "LC_ALL", "LC_CTYPE", "LANG" }) {
            auto v = getenv(var);
            if (v == nullptr || v[0] == 0)
                continue;
            auto s = str_lower(std::string(v));
            return s.find("utf-8") != std::string::npos || s.find("utf8") != std::string::npos;
        }
        return false;
    }

    // Where to point a browser, from the httpd once it exists and the config before then
    std::string web_url() {
        auto config = Globalreg::globalreg->kismet_config;
        auto httpd = Globalreg::fetch_global_as<kis_net_beast_httpd>();

        unsigned int port = 2501;
        bool ssl = false;
        std::string bind = "0.0.0.0", prefix;

        if (config != nullptr) {
            port = config->fetch_opt_as<unsigned short>("httpd_port", 2501);
            ssl = config->fetch_opt_bool("httpd_ssl", false);
            bind = config->fetch_opt_dfl("httpd_bind_address", "0.0.0.0");
            prefix = config->fetch_opt("httpd_uri_prefix");
        }

        if (httpd != nullptr) {
            port = httpd->fetch_port();
            ssl = httpd->fetch_using_ssl();
        }

        std::string host = bind;

        // Listening everywhere; show the first non-loopback address
        if (bind == "0.0.0.0" || bind == "::" || bind.empty()) {
            host = "localhost";

            struct ifaddrs *ifa = nullptr;
            if (getifaddrs(&ifa) == 0) {
                for (auto i = ifa; i != nullptr; i = i->ifa_next) {
                    if (i->ifa_addr == nullptr || i->ifa_addr->sa_family != AF_INET)
                        continue;

                    char buf[INET_ADDRSTRLEN];
                    auto sin = reinterpret_cast<struct sockaddr_in *>(i->ifa_addr);

                    if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) == nullptr)
                        continue;

                    if (strncmp(buf, "127.", 4) == 0)
                        continue;

                    host = buf;
                    break;
                }

                freeifaddrs(ifa);
            }
        } else if (bind.find(':') != std::string::npos) {
            host = "[" + bind + "]";
        }

        while (!prefix.empty() && prefix.back() == '/')
            prefix.pop_back();

        return fmt::format("{}://{}:{}{}/", ssl ? "https" : "http", host, port, prefix);
    }

    // Collects datasource state outside of the display lock
    struct source_sample {
        std::string uuid, name, type;
        bool running, error, paused, remote;
        uint64_t total;
    };

    class source_collector : public datasource_tracker_worker {
    public:
        std::vector<source_sample> samples;

        virtual void handle_datasource(std::shared_ptr<kis_datasource> src) override {
            source_sample s;

            s.uuid = src->get_source_uuid().as_string();
            s.name = src->get_source_name();

            auto builder = src->get_source_builder();
            s.type = builder != nullptr ? builder->get_source_type() : "";

            s.running = src->get_source_running();
            s.error = src->get_source_error();
            s.paused = src->get_source_paused();
            s.remote = src->get_source_remote();
            s.total = src->get_source_num_packets();

            samples.push_back(s);
        }
    };

    void sample() {
        auto& st = state();

        // Never hold the display lock while calling into the trackers
        source_collector collector;
        auto dst = Globalreg::fetch_global_as<datasource_tracker>();
        if (dst != nullptr)
            dst->iterate_datasources(&collector);

        int64_t num_devices = -1;
        auto devicetracker = Globalreg::fetch_global_as<device_tracker>();
        if (devicetracker != nullptr)
            num_devices = devicetracker->fetch_num_devices();

        auto mem_kb = resident_kb();

        std::lock_guard<std::mutex> lk(st.mutex);

        st.sample_gen++;

        for (const auto& s : collector.samples) {
            auto i = st.sources.find(s.uuid);

            if (i == st.sources.end()) {
                i = st.sources.emplace(s.uuid, tui_source()).first;
                st.source_order.push_back(s.uuid);
            }

            auto& src = i->second;

            src.name = sanitize(s.name);
            src.type = sanitize(s.type);
            src.running = s.running;
            src.error = s.error;
            src.paused = s.paused;
            src.remote = s.remote;

            // A re-opened source can restart its count
            double rate = 0;
            if (src.have_total && s.total >= src.total)
                rate = (double) (s.total - src.total);

            src.total = s.total;
            src.have_total = true;
            src.rate = rate;
            push_sample(src.rates, rate);

            src.last_seen = st.sample_gen;
        }

        // Forget removed sources
        for (auto i = st.source_order.begin(); i != st.source_order.end(); ) {
            auto s = st.sources.find(*i);
            if (s == st.sources.end() || s->second.last_seen != st.sample_gen) {
                if (s != st.sources.end())
                    st.sources.erase(s);
                i = st.source_order.erase(i);
            } else {
                ++i;
            }
        }

        if (num_devices >= 0) {
            st.last_devices = (uint64_t) num_devices;
            push_sample(st.devices, (double) num_devices);
        }

        if (mem_kb > 0) {
            st.last_memory_kb = mem_kb;
            push_sample(st.memory, (double) mem_kb);
        }

        st.dirty = true;
    }

    const char *message_color(unsigned int flags) {
        if (flags & MSGFLAG_FATAL)
            return "\x1b[1;31m";
        if (flags & MSGFLAG_ERROR)
            return "\x1b[31m";
        if (flags & MSGFLAG_ALERT)
            return "\x1b[33m";
        if (flags & MSGFLAG_DEBUG)
            return "\x1b[2m";
        return "";
    }

    const char *message_tag(unsigned int flags) {
        if (flags & MSGFLAG_FATAL)
            return "FATAL";
        if (flags & MSGFLAG_ERROR)
            return "ERROR";
        if (flags & MSGFLAG_ALERT)
            return "ALERT";
        if (flags & MSGFLAG_DEBUG)
            return "DEBUG";
        if (flags & MSGFLAG_LOCAL)
            return "LOCAL";
        return "INFO";
    }

    std::string section(const std::string& title, size_t width, bool utf8) {
        std::string out = "\x1b[1;34m";
        std::string rule = utf8 ? "─" : "-";

        out += rule + " " + title + " ";
        size_t used = display_width(title) + 3;

        for (size_t i = used; i < width; i++)
            out += rule;

        out += "\x1b[0m";
        return out;
    }

    // Build a full frame; called with the display lock held
    std::string frame(unsigned int rows, unsigned int cols, const std::string& url) {
        auto& st = state();

        // Stay out of the last column so a full line never wraps or scrolls
        size_t width = cols > 1 ? cols - 1 : 1;

        std::vector<std::string> lines;

        // Banner
        auto uptime = uptime_str(time(0) - st.start_time);
        std::string left = fmt::format(" KISMET {}.{}.{}  Web UI: {}", VERSION_MAJOR,
                VERSION_MINOR, VERSION_TINY, url);
        std::string right = fmt::format("up {} ", uptime);

        // On a narrow terminal the address matters more than the name
        if (display_width(left) > width)
            left = " " + url;

        std::string banner = left;
        if (display_width(left) + display_width(right) + 1 <= width)
            banner += std::string(width - display_width(left) - display_width(right), ' ') + right;

        lines.push_back("\x1b[1;7m" + fit(banner, width, true) + "\x1b[0m");

        // Space for everything above the messages, keeping at least min_message_rows for them
        unsigned int top_avail = rows > min_message_rows + 2 ? rows - min_message_rows - 2 : 0;

        // name, type, graph, rate, total
        size_t name_w = 16, type_w = 12, rate_w = 8, total_w = 8;
        bool show_type = width >= 70;
        size_t fixed = 4 + name_w + (show_type ? type_w + 1 : 0) + 1 + rate_w + 1 + total_w;
        size_t graph_w = width > fixed + 4 ? width - fixed : 0;

        std::vector<std::string> top;

        // Too short or too narrow for the graphs leaves just the messages
        if (top_avail >= 4 && graph_w >= 4) {
            top.push_back(section(fmt::format("Data sources ({})", st.source_order.size()),
                        width, st.utf8));

            // Two rows for the system graphs and their heading, one for the messages heading
            size_t src_rows = top_avail > 5 ? top_avail - 4 : 1;

            if (st.source_order.empty()) {
                top.push_back(fit("  No data sources; add them in the web UI, or with source= in "
                            "the Kismet config", width, false));
            }

            for (size_t i = 0; i < st.source_order.size(); i++) {
                if (top.size() - 1 >= src_rows) {
                    top.back() = fit(fmt::format("  ... {} more sources",
                                st.source_order.size() - i + 1), width, false);
                    break;
                }

                const auto& s = st.sources[st.source_order[i]];

                std::string dot = st.utf8 ? "●" : "*";
                const char *dot_color = "\x1b[2m";
                if (s.error)
                    dot_color = "\x1b[31m";
                else if (s.paused)
                    dot_color = "\x1b[33m";
                else if (s.running)
                    dot_color = "\x1b[32m";

                std::string line = fmt::format("  {}{}\x1b[0m ", dot_color, dot);
                line += fit(s.name, name_w, true);

                if (show_type)
                    line += " \x1b[2m" + fit(s.type, type_w, true) + "\x1b[0m";

                line += " ";

                if (s.error)
                    line += "\x1b[31m" + fit(" error", graph_w, true) + "\x1b[0m";
                else if (!s.running && !s.remote)
                    line += "\x1b[2m" + fit(" opening", graph_w, true) + "\x1b[0m";
                else
                    line += graph(s.rates, graph_w, st.utf8, "\x1b[32m");

                auto rate = human_count(s.rate) + "/s";
                line += " " + std::string(rate_w > rate.size() ? rate_w - rate.size() : 0, ' ') + rate;

                auto total = human_count((double) s.total);
                line += " " + std::string(total_w > total.size() ? total_w - total.size() : 0, ' ') + total;

                top.push_back(line);
            }

            top.push_back(section("System", width, st.utf8));

            auto dev = human_count((double) st.last_devices);
            top.push_back("  " + fit("Devices", name_w + 2 + (show_type ? type_w + 1 : 0), true) +
                    graph(st.devices, graph_w, st.utf8, "\x1b[36m") + " " +
                    std::string(rate_w + total_w + 1 > dev.size() ? rate_w + total_w + 1 - dev.size() : 0, ' ') + dev);

            auto mem = st.last_memory_kb > 0 ? human_kb(st.last_memory_kb) : std::string("-");
            top.push_back("  " + fit("Memory", name_w + 2 + (show_type ? type_w + 1 : 0), true) +
                    graph(st.memory, graph_w, st.utf8, "\x1b[35m") + " " +
                    std::string(rate_w + total_w + 1 > mem.size() ? rate_w + total_w + 1 - mem.size() : 0, ' ') + mem);
        }

        for (const auto& l : top)
            lines.push_back(l);

        lines.push_back(section("Messages", width, st.utf8));

        // The newest messages which fit, wrapped, oldest first
        size_t msg_rows = rows > lines.size() ? rows - lines.size() : 0;
        std::deque<std::string> msg_lines;

        for (auto m = st.messages.rbegin(); m != st.messages.rend() && msg_lines.size() < msg_rows; ++m) {
            struct tm tm;
            localtime_r(&m->ts, &tm);

            auto tag = message_tag(m->flags);
            auto prefix = fmt::format("{:02}:{:02}:{:02} {:<5} ", tm.tm_hour, tm.tm_min, tm.tm_sec, tag);
            auto wrapped = wrap(prefix + m->text, width, prefix.size());
            auto color = message_color(m->flags);

            for (auto w = wrapped.rbegin(); w != wrapped.rend() && msg_lines.size() < msg_rows; ++w) {
                if (color[0] != 0)
                    msg_lines.push_front(color + *w + "\x1b[0m");
                else
                    msg_lines.push_front(*w);
            }
        }

        for (const auto& l : msg_lines)
            lines.push_back(l);

        // Overwrite in place, clearing what's left of each line and anything below
        std::string out = "\x1b[H";

        for (size_t i = 0; i < lines.size() && i < rows; i++) {
            out += lines[i];
            out += "\x1b[K";
            if (i + 1 < rows)
                out += "\r\n";
        }

        if (lines.size() < rows)
            out += "\x1b[J";

        return out;
    }

    void write_all(const std::string& s) {
        size_t off = 0;

        while (off < s.size()) {
            auto r = write(STDOUT_FILENO, s.data() + off, s.size() - off);

            if (r < 0) {
                if (errno == EINTR)
                    continue;
                return;
            }

            off += (size_t) r;
        }
    }

    void terminal_size(unsigned int& rows, unsigned int& cols) {
        struct winsize ws;

        rows = 24;
        cols = 80;

        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0 && ws.ws_col > 0) {
            rows = ws.ws_row;
            cols = ws.ws_col;
        }
    }

    void restore_terminal() {
        // Show the cursor and drop any scroll region
        write_all("\x1b[?25h\x1b[r");
    }

    void run() {
        auto& st = state();

        auto next_sample = std::chrono::steady_clock::now();
        auto last_draw = std::chrono::steady_clock::time_point();
        unsigned int last_rows = 0, last_cols = 0;
        std::string url;
        auto next_url = std::chrono::steady_clock::now();

        while (true) {
            {
                std::unique_lock<std::mutex> lk(st.mutex);
                st.cv.wait_for(lk, std::chrono::milliseconds(100));

                if (st.stopping)
                    return;
            }

            auto now = std::chrono::steady_clock::now();

            if (now >= next_sample) {
                sample();
                next_sample += std::chrono::seconds(1);
                if (next_sample < now)
                    next_sample = now + std::chrono::seconds(1);
            }

            // The address can change as the httpd and interfaces come up
            if (now >= next_url) {
                url = web_url();
                next_url = now + std::chrono::seconds(10);
            }

            unsigned int rows, cols;
            terminal_size(rows, cols);

            std::string out;

            {
                std::lock_guard<std::mutex> lk(st.mutex);

                if (rows != last_rows || cols != last_cols) {
                    st.dirty = true;
                    last_rows = rows;
                    last_cols = cols;
                }

                // Redraw on changes, at most 10 times a second, and every second regardless
                // so stray output from other programs on the terminal is painted over
                if ((st.dirty && now - last_draw >= std::chrono::milliseconds(100)) ||
                        now - last_draw >= std::chrono::seconds(1)) {
                    out = frame(rows, cols, url);
                    st.dirty = false;
                    last_draw = now;
                }
            }

            if (!out.empty())
                write_all(out);
        }
    }
}

namespace console_tui {
    bool start() {
        auto& st = state();

        if (!isatty(STDOUT_FILENO))
            return false;

        std::lock_guard<std::mutex> lk(st.mutex);

        if (st.active)
            return true;

        st.utf8 = terminal_utf8();
        st.start_time = Globalreg::globalreg->start_time != 0 ?
            Globalreg::globalreg->start_time : time(0);
        st.stopping = false;
        st.dirty = true;

        std::atexit(restore_terminal);

        // Hide the cursor and clear the screen
        write_all("\x1b[?25l\x1b[2J\x1b[H");

        st.active = true;
        st.thread = std::thread(run);

        return true;
    }

    void stop() {
        auto& st = state();

        {
            std::lock_guard<std::mutex> lk(st.mutex);

            if (!st.active)
                return;

            st.stopping = true;
        }

        st.cv.notify_all();

        if (st.thread.joinable())
            st.thread.join();

        std::lock_guard<std::mutex> lk(st.mutex);

        st.active = false;

        unsigned int rows, cols;
        terminal_size(rows, cols);

        // Leave the recent messages on the terminal, as the plain console would have
        std::string out = "\x1b[2J\x1b[H\x1b[?25h\x1b[r";

        size_t keep = rows > 4 ? rows - 4 : rows;
        size_t first = st.messages.size() > keep ? st.messages.size() - keep : 0;

        for (size_t i = first; i < st.messages.size(); i++)
            out += fmt::format("{}: {}\n", message_tag(st.messages[i].flags), st.messages[i].text);

        write_all(out);
    }

    bool active() {
        return state().active;
    }

    void add_message(unsigned int flags, const std::string& msg) {
        auto& st = state();

        {
            std::lock_guard<std::mutex> lk(st.mutex);

            st.messages.push_back(tui_message{time(0), flags, sanitize(msg)});

            while (st.messages.size() > max_messages)
                st.messages.pop_front();

            st.dirty = true;
        }

        st.cv.notify_one();
    }
}
