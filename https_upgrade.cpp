// https_upgrade.cpp - give it an http:// website URL, get back the same URL on https://,
// unchanged apart from the scheme, after verifying the site really serves HTTPS.
//
// Build:  g++ -std=c++17 -O2 -Wall -o https_upgrade https_upgrade.cpp -lssl -lcrypto
//
// Usage:  ./https_upgrade http://example.com/some/page?id=7#top
//         ./https_upgrade example.com            (no scheme = treated as http://)
//         ./https_upgrade --no-check http://example.com/x     (convert only, no network)
//         ./https_upgrade url1 url2 url3 ...
//
// What "without altering" means here: userinfo, host, path, query and fragment are copied
// byte-for-byte. Only the scheme changes, and an explicit ":80" is dropped (https uses 443).
// Any other port is kept as-is.
//
// Exit code: 0 = all URLs upgraded and verified, 1 = bad input, 2 = at least one HTTPS check failed.

#include <cctype>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

struct Url {
    std::string userinfo;  // without trailing '@'
    std::string host;      // as written (IPv6 keeps its [brackets])
    std::string port;      // empty if none
    std::string rest;      // path + query + fragment, verbatim (may be empty)
};

static bool ci_prefix(const std::string& s, const char* p) {
    size_t n = std::strlen(p);
    if (s.size() < n) return false;
    for (size_t i = 0; i < n; ++i)
        if (std::tolower(static_cast<unsigned char>(s[i])) != p[i]) return false;
    return true;
}

static bool parse(std::string in, Url& u, bool& already_https, std::string& err) {
    already_https = false;
    // trim surrounding whitespace only
    size_t a = in.find_first_not_of(" \t\r\n"), b = in.find_last_not_of(" \t\r\n");
    if (a == std::string::npos) { err = "empty input"; return false; }
    in = in.substr(a, b - a + 1);

    if (ci_prefix(in, "http://")) in.erase(0, 7);
    else if (ci_prefix(in, "https://")) { in.erase(0, 8); already_https = true; }
    else if (in.find("://") != std::string::npos) { err = "unsupported scheme (only http/https)"; return false; }
    // else: bare "example.com/..." -> treat as http

    for (unsigned char c : in)
        if (c < 0x21 || c == 0x7f) { err = "URL contains spaces or control characters"; return false; }

    size_t end = in.find_first_of("/?#");
    std::string auth = in.substr(0, end);
    u.rest = (end == std::string::npos) ? "" : in.substr(end);

    size_t at = auth.rfind('@');
    if (at != std::string::npos) { u.userinfo = auth.substr(0, at); auth.erase(0, at + 1); }

    if (!auth.empty() && auth[0] == '[') {
        size_t rb = auth.find(']');
        if (rb == std::string::npos) { err = "bad IPv6 address"; return false; }
        u.host = auth.substr(0, rb + 1);
        if (rb + 1 < auth.size()) {
            if (auth[rb + 1] != ':') { err = "bad authority"; return false; }
            u.port = auth.substr(rb + 2);
        }
    } else {
        size_t colon = auth.find(':');
        u.host = auth.substr(0, colon);
        if (colon != std::string::npos) u.port = auth.substr(colon + 1);
    }
    if (u.host.empty()) { err = "missing host"; return false; }
    for (unsigned char c : u.port)
        if (!std::isdigit(c)) { err = "bad port"; return false; }
    return true;
}

static std::string build_https(const Url& u) {
    std::string s = "https://";
    if (!u.userinfo.empty()) s += u.userinfo + "@";
    s += u.host;
    if (!u.port.empty() && u.port != "80") s += ":" + u.port;  // drop :80, keep anything else
    s += u.rest;
    return s;
}

// ---------------------------------------------------------------- HTTPS check --

struct CheckResult {
    bool ok = false;
    std::string message;
};

static CheckResult check_https_with(const Url& u, const char* method) {
    CheckResult r;
    std::string host = u.host;
    bool v6 = !host.empty() && host[0] == '[';
    if (v6) host = host.substr(1, host.size() - 2);
    std::string port = (u.port.empty() || u.port == "80") ? "443" : u.port;

    addrinfo hints{}, *res = nullptr;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) {
        r.message = "DNS lookup failed";
        return r;
    }

    int fd = -1;
    for (addrinfo* p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        timeval tv{8, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) { r.message = "could not connect on port " + port + " (HTTPS not offered?)"; return r; }

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_default_verify_paths(ctx);  // honors SSL_CERT_FILE / SSL_CERT_DIR too
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);

    unsigned char tmp[sizeof(in6_addr)];
    bool is_ip = inet_pton(AF_INET, host.c_str(), tmp) == 1 || inet_pton(AF_INET6, host.c_str(), tmp) == 1;
    if (is_ip) {
        X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), host.c_str());
    } else {
        SSL_set_tlsext_host_name(ssl, host.c_str());
        SSL_set1_host(ssl, host.c_str());  // certificate must match this hostname
    }

    auto cleanup = [&]() { SSL_free(ssl); SSL_CTX_free(ctx); close(fd); };

    if (SSL_connect(ssl) != 1) {
        long vr = SSL_get_verify_result(ssl);
        if (vr != X509_V_OK) r.message = std::string("certificate problem: ") + X509_verify_cert_error_string(vr);
        else r.message = "TLS handshake failed";
        cleanup();
        return r;
    }

    // Plain HEAD request to see that a real web server answers, and whether it bounces back to http://
    std::string path = u.rest.empty() || u.rest[0] == '#' ? "/" : u.rest;
    size_t hash = path.find('#');
    if (hash != std::string::npos) path.erase(hash);  // fragments are never sent to servers
    if (path[0] == '?') path = "/" + path;
    std::string req = std::string(method) + " " + path + " HTTP/1.1\r\nHost: " + u.host +
                      (u.port.empty() || u.port == "80" || u.port == "443" ? "" : ":" + u.port) +
                      "\r\nUser-Agent: https_upgrade/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    SSL_write(ssl, req.data(), static_cast<int>(req.size()));

    std::string resp;
    char buf[4096];
    int n;
    while (resp.find("\r\n\r\n") == std::string::npos && resp.size() < 16384 &&
           (n = SSL_read(ssl, buf, sizeof buf)) > 0)
        resp.append(buf, static_cast<size_t>(n));
    SSL_shutdown(ssl);
    cleanup();

    if (resp.compare(0, 5, "HTTP/") != 0) { r.message = "TLS works but no HTTP response"; return r; }
    std::string status = resp.substr(0, resp.find("\r\n"));
    r.ok = true;
    r.message = "TLS certificate valid, server replied: " + status.substr(status.find(' ') + 1);

    // Warn if the https URL redirects back to plain http (downgrade loop)
    size_t loc = std::string::npos;
    for (size_t i = 0; i + 9 < resp.size(); ++i)
        if ((i == 0 || resp[i - 1] == '\n') && ci_prefix(resp.substr(i, 10), "location: ")) { loc = i + 10; break; }
    if (loc != std::string::npos) {
        std::string l = resp.substr(loc, resp.find("\r\n", loc) - loc);
        if (ci_prefix(l, "http://")) {
            r.ok = false;
            r.message += "; BUT it redirects back to plain http: " + l;
        }
    }
    return r;
}

// Try HEAD first; some servers don't answer it, so fall back to GET (only headers are read).
static CheckResult check_https(const Url& u) {
    CheckResult r = check_https_with(u, "HEAD");
    if (!r.ok && r.message == "TLS works but no HTTP response") r = check_https_with(u, "GET");
    return r;
}

// ------------------------------------------------------------------------ main --

int main(int argc, char** argv) {
    bool check = true;
    std::vector<std::string> urls;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--no-check") check = false;
        else if (a == "-h" || a == "--help") { urls.clear(); break; }
        else urls.push_back(a);
    }
    if (urls.empty()) {
        std::cerr << "Usage: " << argv[0] << " [--no-check] <http-url> [more urls...]\n";
        return 1;
    }

    int exit_code = 0;
    for (const std::string& in : urls) {
        Url u;
        bool was_https;
        std::string err;
        if (!parse(in, u, was_https, err)) {
            std::cerr << "error: " << in << " -> " << err << "\n";
            exit_code = 1;
            continue;
        }
        std::string out = build_https(u);
        std::cout << out << "\n";
        if (was_https) std::cerr << "  (already https)\n";
        if (check) {
            CheckResult r = check_https(u);
            std::cerr << (r.ok ? "  [OK] " : "  [FAILED] ") << r.message << "\n";
            if (!r.ok && exit_code == 0) exit_code = 2;
        }
    }
    return exit_code;
}
