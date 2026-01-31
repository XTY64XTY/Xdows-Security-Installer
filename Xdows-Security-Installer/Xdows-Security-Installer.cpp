// Xdows-Security-Installer.cpp
// Build: MSVC /std:c++17
// Links: wininet.lib shell32.lib ole32.lib

#include <windows.h>
#include <wininet.h>
#include <shlobj.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <iomanip>
#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <algorithm>
#include <optional>

namespace fs = std::filesystem;

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

// ------------------------- Helpers -------------------------

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (len <= 0) return L"";
    std::wstring w(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), len);
    return w;
}

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), len, nullptr, nullptr);
    return s;
}

static std::wstring EscapeForPowerShellSingleQuoted(const std::wstring& text) {
    // PowerShell single-quoted string escapes ' as ''
    std::wstring out;
    out.reserve(text.size() + 8);
    for (wchar_t ch : text) {
        if (ch == L'\'') out += L"''";
        else out += ch;
    }
    return out;
}

static fs::path GetTempDir() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, buf);
    if (n == 0 || n > MAX_PATH) throw std::runtime_error("无法获取临时目录路径");
    return fs::path(buf);
}

static fs::path WeakCanonical(const fs::path& p) {
    std::error_code ec;
    fs::path c = fs::weakly_canonical(p, ec);
    if (!ec) return c;
    fs::path a = fs::absolute(p, ec);
    return ec ? p : a;
}

static bool IsDangerousPath(const fs::path& p) {
    fs::path absP = WeakCanonical(p);

    if (absP.has_root_path() && absP == absP.root_path()) return true;

    wchar_t winDirBuf[MAX_PATH];
    UINT n = GetWindowsDirectoryW(winDirBuf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        fs::path winDir = WeakCanonical(fs::path(winDirBuf));
        auto lower = [](std::wstring s) {
            std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
            return s;
            };
        if (lower(absP.wstring()) == lower(winDir.wstring())) return true;
        if (absP == winDir.root_path()) return true;
    }
    return false;
}

static fs::path NormalizeInstallRoot(const fs::path& userPath) {
    // Accept either:
    // 1) root where Xdows-Security folder lives
    // 2) direct path to ...\Xdows-Security
    fs::path p = userPath;
    std::error_code ec;
    if (!fs::exists(p, ec)) return p;

    if (p.filename() == "Xdows-Security") return p.parent_path();

    fs::path candidate = p / "Xdows-Security";
    if (fs::exists(candidate, ec) && fs::is_directory(candidate, ec)) return p;

    return p;
}

// Marker file to reduce accidental deletes
static fs::path MarkerPathForInstallRoot(const fs::path& installRoot) {
    return installRoot / "Xdows-Security" / ".xdows_install_marker";
}

static void WriteInstallMarker(const fs::path& installRoot, const std::string& version) {
    fs::path marker = MarkerPathForInstallRoot(installRoot);
    fs::create_directories(marker.parent_path());
    std::ofstream ofs(marker, std::ios::binary);
    if (!ofs) return;
    auto now = std::chrono::system_clock::now().time_since_epoch();
    auto sec = std::chrono::duration_cast<std::chrono::seconds>(now).count();
    ofs << "Xdows-Security installed by installer\n";
    ofs << "version=" << version << "\n";
    ofs << "timestamp=" << sec << "\n";
}

static bool HasMarker(const fs::path& installRoot) {
    fs::path marker = MarkerPathForInstallRoot(installRoot);
    std::error_code ec;
    return fs::exists(marker, ec) && fs::is_regular_file(marker, ec);
}

// ------------------------- Zip meta -------------------------

static fs::path MetaPathForZip(const fs::path& zipPath) {
    // <zipfilename>.xdows.meta next to zip
    return zipPath.parent_path() / (zipPath.filename().wstring() + L".xdows.meta");
}

static void WriteZipMeta(const fs::path& zipPath, const std::string& version, const std::string& url) {
    fs::path meta = MetaPathForZip(zipPath);
    std::ofstream ofs(meta, std::ios::binary);
    if (!ofs) return;
    ofs << "version=" << version << "\n";
    ofs << "url=" << url << "\n";
}

static std::string ReadZipMetaVersion(const fs::path& zipPath) {
    fs::path meta = MetaPathForZip(zipPath);
    std::error_code ec;
    if (!fs::exists(meta, ec)) return "unknown";
    std::ifstream ifs(meta, std::ios::binary);
    if (!ifs) return "unknown";
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.rfind("version=", 0) == 0) return line.substr(std::string("version=").size());
    }
    return "unknown";
}

// ------------------------- Registry (Version-based keys) -------------------------

static const wchar_t* kRegInstalls = L"Software\\Xdows Software\\Xdows-Security\\Installs";

static void PrintRegModifyVersionKey(const std::wstring& versionKey) {
    std::wcout << L"修改注册表：HKCU\\" << kRegInstalls << L"\\" << versionKey << L"\n";
}

static void EnsureKeyHKCU(const std::wstring& subkey) {
    HKEY hKey = nullptr;
    DWORD disp = 0;
    LONG r = RegCreateKeyExW(HKEY_CURRENT_USER, subkey.c_str(), 0, nullptr, 0,
        KEY_READ | KEY_WRITE, nullptr, &hKey, &disp);
    if (r != ERROR_SUCCESS) {
        throw std::runtime_error("创建/打开注册表键失败: " + std::to_string((int)r));
    }
    RegCloseKey(hKey);
}

static bool KeyExistsHKCU(const std::wstring& subkey) {
    HKEY hKey = nullptr;
    LONG r = RegOpenKeyExW(HKEY_CURRENT_USER, subkey.c_str(), 0, KEY_READ, &hKey);
    if (r == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

static void SetDefaultValueHKCU(const std::wstring& subkey, const std::wstring& value) {
    HKEY hKey = nullptr;
    LONG r = RegCreateKeyExW(HKEY_CURRENT_USER, subkey.c_str(), 0, nullptr, 0,
        KEY_READ | KEY_WRITE, nullptr, &hKey, nullptr);
    if (r != ERROR_SUCCESS) throw std::runtime_error("打开注册表键失败: " + std::to_string((int)r));

    // Default value => lpValueName = nullptr
    r = RegSetValueExW(hKey, nullptr, 0, REG_SZ, (const BYTE*)value.c_str(),
        (DWORD)((value.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS) throw std::runtime_error("写注册表默认值失败: " + std::to_string((int)r));
}

static bool GetDefaultValueHKCU(const std::wstring& subkey, std::wstring& out) {
    HKEY hKey = nullptr;
    LONG r = RegOpenKeyExW(HKEY_CURRENT_USER, subkey.c_str(), 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) return false;

    DWORD type = 0;
    DWORD bytes = 0;
    r = RegQueryValueExW(hKey, nullptr, nullptr, &type, nullptr, &bytes);
    if (r != ERROR_SUCCESS || type != REG_SZ || bytes < sizeof(wchar_t)) {
        RegCloseKey(hKey);
        return false;
    }

    std::wstring buf(bytes / sizeof(wchar_t), L'\0');
    r = RegQueryValueExW(hKey, nullptr, nullptr, &type, (LPBYTE)buf.data(), &bytes);
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS) return false;

    if (!buf.empty() && buf.back() == L'\0') buf.pop_back();
    out = buf;
    return true;
}

static bool DeleteKeyTreeHKCU(const std::wstring& subkey) {
    LONG r = RegDeleteTreeW(HKEY_CURRENT_USER, subkey.c_str());
    return (r == ERROR_SUCCESS || r == ERROR_FILE_NOT_FOUND);
}

static std::vector<std::wstring> EnumSubKeysHKCU(const std::wstring& subkey) {
    std::vector<std::wstring> keys;
    HKEY hKey = nullptr;
    LONG r = RegOpenKeyExW(HKEY_CURRENT_USER, subkey.c_str(), 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) return keys;

    DWORD index = 0;
    wchar_t nameBuf[256];
    DWORD nameLen = 0;
    FILETIME ft{};

    while (true) {
        nameLen = (DWORD)(sizeof(nameBuf) / sizeof(wchar_t));
        r = RegEnumKeyExW(hKey, index, nameBuf, &nameLen, nullptr, nullptr, nullptr, &ft);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r == ERROR_SUCCESS) keys.emplace_back(nameBuf, nameLen);
        index++;
    }

    RegCloseKey(hKey);
    return keys;
}

static std::wstring MakeVersionSubkeyPath(const std::wstring& version) {
    return std::wstring(kRegInstalls) + L"\\" + version;
}

static bool RegistryHasVersion(const std::wstring& version) {
    return KeyExistsHKCU(MakeVersionSubkeyPath(version));
}

static bool RegistryTryGetInstallPathByVersion(const std::wstring& version, fs::path& outInstallRoot) {
    std::wstring sub = MakeVersionSubkeyPath(version);
    std::wstring value;
    if (!GetDefaultValueHKCU(sub, value)) return false;
    outInstallRoot = fs::path(value);
    return true;
}

static void RegistryWriteVersionPath(const std::wstring& version, const fs::path& installRoot) {
    EnsureKeyHKCU(kRegInstalls);
    std::wstring sub = MakeVersionSubkeyPath(version);
    PrintRegModifyVersionKey(version);
    EnsureKeyHKCU(sub);
    SetDefaultValueHKCU(sub, WeakCanonical(installRoot).wstring());
}

static void RegistryDeleteVersion(const std::wstring& version) {
    std::wstring sub = MakeVersionSubkeyPath(version);
    PrintRegModifyVersionKey(version);
    DeleteKeyTreeHKCU(sub);
}

static std::optional<std::wstring> RegistryFindVersionByPath(const fs::path& installRoot) {
    std::wstring target = WeakCanonical(installRoot).wstring();
    auto lowerW = [](std::wstring s) {
        std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
        return s;
        };
    std::wstring t = lowerW(target);

    auto versions = EnumSubKeysHKCU(kRegInstalls);
    for (const auto& v : versions) {
        fs::path p;
        if (RegistryTryGetInstallPathByVersion(v, p)) {
            if (lowerW(WeakCanonical(p).wstring()) == t) return v;
        }
    }
    return std::nullopt;
}

static void ListInstalledFromRegistry() {
    std::cout << "已安装版本（注册表 HKCU\\" << WideToUtf8(kRegInstalls) << "）：\n";

    auto versions = EnumSubKeysHKCU(kRegInstalls);

    if (versions.empty()) {
        std::cout << "  （无记录）\n";
        return;
    }

    for (const auto& v : versions) {
        std::wstring pathW;
        if (GetDefaultValueHKCU(MakeVersionSubkeyPath(v), pathW)) {
            std::cout << "  - 版本: " << WideToUtf8(v) << "\n";
            std::cout << "    路径: " << WideToUtf8(pathW) << "\n";
        }
        else {
            std::cout << "  - 版本: " << WideToUtf8(v) << "\n";
            std::cout << "    路径: (读取失败)\n";
        }
    }
}


// ------------------------- WinINet HTTP (HttpOpenRequest + status + redirects + TLS) -------------------------

static void ParseUrlA(
    const std::string& url,
    std::string& scheme,
    std::string& host,
    std::string& pathAndQuery,
    INTERNET_PORT& port,
    bool& isHttps
) {
    URL_COMPONENTSA uc{};
    uc.dwStructSize = sizeof(uc);

    char schemeBuf[16] = { 0 };
    char hostBuf[256] = { 0 };
    char pathBuf[2048] = { 0 };
    char extraBuf[2048] = { 0 };

    uc.lpszScheme = schemeBuf; uc.dwSchemeLength = (DWORD)sizeof(schemeBuf);
    uc.lpszHostName = hostBuf; uc.dwHostNameLength = (DWORD)sizeof(hostBuf);
    uc.lpszUrlPath = pathBuf; uc.dwUrlPathLength = (DWORD)sizeof(pathBuf);
    uc.lpszExtraInfo = extraBuf; uc.dwExtraInfoLength = (DWORD)sizeof(extraBuf);

    if (!InternetCrackUrlA(url.c_str(), 0, 0, &uc)) {
        throw std::runtime_error("无法解析 URL: " + url);
    }

    scheme.assign(uc.lpszScheme, uc.dwSchemeLength);
    host.assign(uc.lpszHostName, uc.dwHostNameLength);

    std::string path(uc.lpszUrlPath, uc.dwUrlPathLength);
    std::string extra(uc.lpszExtraInfo ? uc.lpszExtraInfo : "", uc.dwExtraInfoLength);
    pathAndQuery = path + extra;

    port = uc.nPort;
    isHttps = (_stricmp(scheme.c_str(), "https") == 0);
}

static int QueryHttpStatusCode(HINTERNET hReq) {
    DWORD status = 0;
    DWORD len = sizeof(status);
    if (HttpQueryInfoA(hReq, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &len, nullptr)) {
        return (int)status;
    }
    return -1;
}

static bool QueryHeaderStringA(HINTERNET hReq, DWORD query, std::string& out) {
    DWORD len = 0;
    if (!HttpQueryInfoA(hReq, query, nullptr, &len, nullptr)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return false;
    }
    std::string buf(len, '\0');
    if (!HttpQueryInfoA(hReq, query, buf.data(), &len, nullptr)) return false;
    while (!buf.empty() && (buf.back() == '\0' || buf.back() == '\r' || buf.back() == '\n')) buf.pop_back();
    out = buf;
    return true;
}

static std::string ReadAllFromInternetHandle(HINTERNET h) {
    std::string resp;
    char buf[4096]{};
    DWORD br = 0;
    while (InternetReadFile(h, buf, (DWORD)sizeof(buf), &br) && br > 0) {
        resp.append(buf, br);
    }
    return resp;
}

static std::string HttpGetWithHeaders(const std::string& url, const std::vector<std::string>& headers, int maxRedirects = 5) {
    std::string currentUrl = url;

    HINTERNET hSession = InternetOpenA("Xdows-Security/4.1", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hSession) throw std::runtime_error("InternetOpenA 失败: " + std::to_string(GetLastError()));

    for (int i = 0; i <= maxRedirects; ++i) {
        std::string scheme, host, path;
        INTERNET_PORT port = 0;
        bool isHttps = false;
        ParseUrlA(currentUrl, scheme, host, path, port, isHttps);

        HINTERNET hConnect = InternetConnectA(hSession, host.c_str(), port, nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConnect) {
            InternetCloseHandle(hSession);
            throw std::runtime_error("InternetConnectA 失败: " + std::to_string(GetLastError()));
        }

        const char* acceptTypes[] = { "*/*", nullptr };
        DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT;
        if (isHttps) flags |= INTERNET_FLAG_SECURE;

        HINTERNET hReq = HttpOpenRequestA(hConnect, "GET", path.c_str(), "HTTP/1.1", nullptr, acceptTypes, flags, 0);
        if (!hReq) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hSession);
            throw std::runtime_error("HttpOpenRequestA 失败: " + std::to_string(GetLastError()));
        }

        std::string headerBlob;
        for (const auto& h : headers) headerBlob += h + "\r\n";

        BOOL ok = HttpSendRequestA(hReq,
            headerBlob.empty() ? nullptr : headerBlob.c_str(),
            headerBlob.empty() ? 0 : (DWORD)headerBlob.size(),
            nullptr, 0);
        if (!ok) {
            DWORD err = GetLastError();
            InternetCloseHandle(hReq);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hSession);
            throw std::runtime_error("HttpSendRequestA 失败: " + std::to_string(err));
        }

        int status = QueryHttpStatusCode(hReq);

        if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
            std::string loc;
            if (QueryHeaderStringA(hReq, HTTP_QUERY_LOCATION, loc) && !loc.empty()) {
                InternetCloseHandle(hReq);
                InternetCloseHandle(hConnect);
                currentUrl = loc;
                continue;
            }
        }

        std::string body = ReadAllFromInternetHandle(hReq);
        std::string statusText;
        QueryHeaderStringA(hReq, HTTP_QUERY_STATUS_TEXT, statusText);

        InternetCloseHandle(hReq);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hSession);

        if (status < 200 || status >= 300) {
            std::string snippet = body.substr(0, std::min<size_t>(512, body.size()));
            throw std::runtime_error("HTTP 请求失败: " + std::to_string(status) + " " + statusText + "\n响应片段:\n" + snippet);
        }
        if (body.empty()) throw std::runtime_error("空响应");
        return body;
    }

    InternetCloseHandle(hSession);
    throw std::runtime_error("重定向次数过多，已终止（maxRedirects）");
}

static bool DownloadFileHttpOpenRequest(
    const std::string& url,
    const fs::path& outputPath,
    const std::vector<std::string>& headers,
    int maxRedirects = 8
) {
    std::string currentUrl = url;

    HINTERNET hSession = InternetOpenA("XdowsSecurityInstaller/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hSession) return false;

    bool okAll = false;

    for (int i = 0; i <= maxRedirects; ++i) {
        std::string scheme, host, path;
        INTERNET_PORT port = 0;
        bool isHttps = false;

        try { ParseUrlA(currentUrl, scheme, host, path, port, isHttps); }
        catch (...) { break; }

        HINTERNET hConnect = InternetConnectA(hSession, host.c_str(), port, nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConnect) break;

        const char* acceptTypes[] = { "*/*", nullptr };
        DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT;
        if (isHttps) flags |= INTERNET_FLAG_SECURE;

        HINTERNET hReq = HttpOpenRequestA(hConnect, "GET", path.c_str(), "HTTP/1.1", nullptr, acceptTypes, flags, 0);
        if (!hReq) { InternetCloseHandle(hConnect); break; }

        std::string headerBlob;
        for (const auto& h : headers) headerBlob += h + "\r\n";

        BOOL sendOk = HttpSendRequestA(hReq,
            headerBlob.empty() ? nullptr : headerBlob.c_str(),
            headerBlob.empty() ? 0 : (DWORD)headerBlob.size(),
            nullptr, 0);
        if (!sendOk) {
            InternetCloseHandle(hReq);
            InternetCloseHandle(hConnect);
            break;
        }

        int status = QueryHttpStatusCode(hReq);

        if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
            std::string loc;
            if (QueryHeaderStringA(hReq, HTTP_QUERY_LOCATION, loc) && !loc.empty()) {
                InternetCloseHandle(hReq);
                InternetCloseHandle(hConnect);
                currentUrl = loc;
                continue;
            }
        }

        if (status < 200 || status >= 300) {
            std::string statusText;
            QueryHeaderStringA(hReq, HTTP_QUERY_STATUS_TEXT, statusText);
            std::string bodySnippet = ReadAllFromInternetHandle(hReq);
            bodySnippet = bodySnippet.substr(0, std::min<size_t>(512, bodySnippet.size()));
            std::cerr << "HTTP 下载失败: " << status << " " << statusText << "\n响应片段:\n" << bodySnippet << "\n";
            InternetCloseHandle(hReq);
            InternetCloseHandle(hConnect);
            break;
        }

        // Open output file only after we got 2xx
        FILE* fp = nullptr;
        if (fopen_s(&fp, outputPath.string().c_str(), "wb") != 0 || !fp) {
            InternetCloseHandle(hReq);
            InternetCloseHandle(hConnect);
            break;
        }

        DWORD contentLength = 0;
        DWORD bufLen = sizeof(contentLength);
        bool hasLength = (HttpQueryInfoA(hReq, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &contentLength, &bufLen, nullptr) == TRUE);

        std::cout << "\n正在下载 ";
        if (hasLength && contentLength > 0) std::cout << "(" << contentLength << " 字节) ";
        else std::cout << "(未知大小) ";
        std::cout.flush();

        char buffer[8192]{};
        DWORD bytesRead = 0;
        size_t totalRead = 0;

        auto lastUpdate = std::chrono::steady_clock::now();
        double lastTotal = 0;

        bool success = true;
        while (InternetReadFile(hReq, buffer, (DWORD)sizeof(buffer), &bytesRead) && bytesRead > 0) {
            if (fwrite(buffer, 1, bytesRead, fp) != bytesRead) {
                success = false;
                break;
            }
            totalRead += bytesRead;

            auto now = std::chrono::steady_clock::now();
            auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastUpdate).count();
            if (elapsedMs >= 500) {
                double delta = (double)totalRead - lastTotal;
                double speed = delta / (elapsedMs / 1000.0);
                lastTotal = (double)totalRead;
                lastUpdate = now;

                std::string speedStr;
                if (speed > 1024 * 1024) speedStr = std::to_string((int)(speed / (1024 * 1024))) + " MB/s";
                else if (speed > 1024) speedStr = std::to_string((int)(speed / 1024)) + " KB/s";
                else speedStr = std::to_string((int)speed) + " B/s";

                std::cout << "\r";
                if (hasLength && contentLength > 0) {
                    int percent = (int)((double)totalRead * 100.0 / (double)contentLength);
                    if (percent > 100) percent = 100;
                    double remainingTime = (speed > 0) ? ((double)contentLength - (double)totalRead) / speed : 0;

                    std::string timeStr = "N/A";
                    if (remainingTime > 0) {
                        int sec = (int)remainingTime;
                        if (sec >= 60) timeStr = std::to_string(sec / 60) + "m " + std::to_string(sec % 60) + "s";
                        else timeStr = std::to_string(sec) + "s";
                    }

                    std::cout << "[" << std::setw(3) << percent << "%] "
                        << totalRead << "/" << contentLength
                        << " 字节 | 速度: " << speedStr << " | 剩余: " << timeStr;
                }
                else {
                    std::cout << totalRead << " 字节 | 速度: " << speedStr;
                }
                std::cout.flush();
            }
        }

        std::cout << "\r";
        if (hasLength && contentLength > 0) {
            std::cout << "[100%] " << totalRead << "/" << contentLength << " 字节 | 完成!" << std::endl;
        }
        else {
            std::cout << totalRead << " 字节 | 完成!" << std::endl;
        }

        fclose(fp);

        InternetCloseHandle(hReq);
        InternetCloseHandle(hConnect);

        if (!success) {
            std::error_code ec;
            fs::remove(outputPath, ec);
            break;
        }

        okAll = true;
        break;
    }

    InternetCloseHandle(hSession);

    if (!okAll) {
        std::error_code ec;
        fs::remove(outputPath, ec);
    }
    return okAll;
}

// ------------------------- GitHub release parsing -------------------------

struct DownloadInfo {
    std::string url;
    std::string version; // tag_name
};

static std::vector<std::string> ExtractAllDownloadUrls(const std::string& json) {
    std::regex re(R"(\"browser_download_url\"\s*:\s*\"([^"]+)\")");
        std::vector<std::string> urls;
    for (auto it = std::sregex_iterator(json.begin(), json.end(), re); it != std::sregex_iterator(); ++it) {
        if ((*it).size() > 1) urls.push_back((*it)[1].str());
    }
    return urls;
}

static std::string ExtractTagName(const std::string& json) {
    std::regex re(R"(\"tag_name\"\s*:\s*\"([^"]+)\")");
        std::smatch m;
    if (std::regex_search(json, m, re) && m.size() > 1) return m[1].str();
    return "unknown";
}

static bool EndsWithCaseInsensitive(const std::string& s, const std::string& suffix) {
    if (suffix.size() > s.size()) return false;
    std::string a = s.substr(s.size() - suffix.size());
    auto lower = [](unsigned char c) { return (char)std::tolower(c); };
    std::transform(a.begin(), a.end(), a.begin(), lower);
    std::string suf = suffix;
    std::transform(suf.begin(), suf.end(), suf.begin(), lower);
    return a == suf;
}

static int ScoreAssetUrl(const std::string& url) {
    int score = 0;
    if (EndsWithCaseInsensitive(url, ".zip")) score += 100;
    if (url.find("win-x64") != std::string::npos) score += 30;
    if (url.find("windows") != std::string::npos) score += 20;
    if (url.find(".sha256") != std::string::npos || url.find(".sig") != std::string::npos) score -= 200;
    return score;
}

static std::string ChooseBestDownloadUrl(const std::string& json) {
    auto urls = ExtractAllDownloadUrls(json);
    if (urls.empty()) throw std::runtime_error("JSON 中未找到 browser_download_url");
    std::string best = urls[0];
    int bestScore = ScoreAssetUrl(best);
    for (const auto& u : urls) {
        int sc = ScoreAssetUrl(u);
        if (sc > bestScore) { bestScore = sc; best = u; }
    }
    return best;
}

static DownloadInfo GetLatestDownloadInfo(bool useMirror) {
    const std::string mirrorPrefix = "https://ghproxy.it/";
    const std::string apiUrl = "https://api.github.com/repositories/1032964256/releases/latest";

    std::vector<std::string> headers = {
        "User-Agent: Xdows-Security/4.1",
        "Accept: application/vnd.github+json"
    };

    std::string json = HttpGetWithHeaders(apiUrl, headers, 5);

    DownloadInfo info;
    info.version = ExtractTagName(json);
    info.url = ChooseBestDownloadUrl(json);
    if (useMirror) info.url = mirrorPrefix + info.url;
    return info;
}

// ------------------------- Expand-Archive (safe, no system()) -------------------------

static int RunExpandArchiveCreateProcess(const fs::path& zipPath, const fs::path& destPath) {
    std::wstring zipW = EscapeForPowerShellSingleQuoted(zipPath.wstring());
    std::wstring destW = EscapeForPowerShellSingleQuoted(destPath.wstring());
    std::wstring psCommand = L"Expand-Archive -LiteralPath '" + zipW + L"' -DestinationPath '" + destW + L"' -Force";
    std::wstring cmdLine = L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" + psCommand + L"\"";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end());
    buf.push_back(L'\0');

    BOOL ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!ok) return (int)GetLastError();

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)exitCode;
}

// ------------------------- Data folder handling -------------------------

static fs::path GetLocalAppDataXdowsPath() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    if (!(n > 0 && n < MAX_PATH)) return fs::path();
    return fs::path(buf) / "Xdows-Security";
}

static bool AskKeepDataInteractive() {
    fs::path p = GetLocalAppDataXdowsPath();
    if (p.empty()) {
        std::cout << "无法获取 LOCALAPPDATA 环境变量，默认保留配置数据。\n";
        return true;
    }
    std::cout << "是否保留配置文件、信任区、隔离区等数据 (" << p.string() << ")? (y=保留 / n=删除): ";
    std::string input;
    std::getline(std::cin, input);
    return (input == "y" || input == "Y" || input.empty());
}

static void DeleteDataFolderIfNeeded(bool keepData) {
    if (keepData) return;
    fs::path p = GetLocalAppDataXdowsPath();
    if (p.empty()) {
        std::cout << "无法获取 LOCALAPPDATA 环境变量，跳过删除设置。\n";
        return;
    }
    if (fs::exists(p)) {
        fs::remove_all(p);
        std::cout << "已删除: " << p.string() << "\n";
    }
    else {
        std::cout << "未找到目录: " << p.string() << "\n";
    }
}

// ------------------------- Core operations -------------------------

static int DoInstall(const fs::path& zipP, const fs::path& userInstallRoot, bool writeRegistry) {
    fs::path installRoot = userInstallRoot;
    if (!fs::exists(zipP) || !fs::is_regular_file(zipP)) {
        std::cerr << "压缩包不存在: " << zipP.string() << "\n";
        return 1;
    }

    std::string version = ReadZipMetaVersion(zipP);

    if (writeRegistry) {
        if (version == "unknown") {
            std::cerr << "无法确定版本号（未找到 zip 的 .xdows.meta 或 meta 中无 version）。\n";
            std::cerr << "请使用 -noreg 安装，或使用 -download 获取带版本信息的 zip。\n";
            return 1;
        }
        // Same version cannot be installed multiple times when writing registry
        if (RegistryHasVersion(Utf8ToWide(version))) {
            std::cerr << "检测到该版本已在注册表记录中存在（同一版本不能重复安装）。\n";
            std::cerr << "如需在不同目录安装同版本，请加参数 -noreg。\n";
            return 1;
        }
    }

    fs::create_directories(installRoot);

    std::cout << "正在解压: " << zipP.string() << " 到 " << installRoot.string() << "\n";
    int rc = RunExpandArchiveCreateProcess(zipP, installRoot);
    if (rc != 0) {
        std::cerr << "解压失败，PowerShell 退出码/错误码: " << rc << "\n";
        return 1;
    }

    // rename win-x64 -> Xdows-Security
    bool renamed = false;
    for (auto& entry : fs::recursive_directory_iterator(installRoot)) {
        try {
            if (entry.is_directory() && entry.path().filename() == "win-x64") {
                fs::path newPath = entry.path().parent_path() / "Xdows-Security";
                if (fs::exists(newPath)) {
                    std::cout << "目标目录已存在，正在删除: " << newPath.string() << "\n";
                    fs::remove_all(newPath);
                }
                fs::rename(entry.path(), newPath);
                std::cout << "已将 " << entry.path().string() << " 重命名为 " << newPath.string() << "\n";
                renamed = true;
                break;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "处理路径时出错: " << entry.path().string() << " -> " << e.what() << "\n";
        }
    }

    if (!renamed) {
        std::cout << "未找到名为 'win-x64' 的目录，未执行重命名。\n";
        if (!fs::exists(installRoot / "Xdows-Security")) {
            std::cout << "警告：未找到 Xdows-Security 文件夹，安装结果可能不符合预期。\n";
        }
    }

    WriteInstallMarker(installRoot, version);

    if (writeRegistry) {
        RegistryWriteVersionPath(Utf8ToWide(version), installRoot);
    }

    std::cout << "安装完成。版本: " << version << (writeRegistry ? "（已写注册表）" : "（未写注册表）") << "\n";
    return 0;
}

static int DoUninstallByDir(const fs::path& userPath, std::optional<bool> keepDataFlag) {
    fs::path installRoot = NormalizeInstallRoot(userPath);
    if (!fs::exists(installRoot)) {
        std::cerr << "安装路径不存在: " << installRoot.string() << "\n";
        return 1;
    }

    if (IsDangerousPath(WeakCanonical(installRoot))) {
        std::cerr << "出于安全原因，拒绝卸载/删除危险路径: " << WeakCanonical(installRoot).string() << "\n";
        return 1;
    }

    bool markerOk = HasMarker(installRoot);

    std::cout << "将要删除安装目录: '" << installRoot.string() << "'\n";
    if (!markerOk) {
        std::cout << "警告：未检测到安装标记文件（可能不是本安装器安装的目录）。\n";
        std::cout << "为防误删，需要你额外确认：请输入 DELETE 继续，否则回车取消: ";
        std::string token;
        std::getline(std::cin, token);
        if (token != "DELETE") {
            std::cout << "已取消卸载。\n";
            return 0;
        }
    }
    else {
        std::cout << "检测到安装标记文件，允许卸载。\n";
        std::cout << "确定要卸载并删除安装目录? (y/n): ";
        std::string conf;
        std::getline(std::cin, conf);
        if (!(conf == "y" || conf == "Y")) {
            std::cout << "已取消卸载。\n";
            return 0;
        }
    }

    bool keepData = keepDataFlag.has_value() ? *keepDataFlag : AskKeepDataInteractive();

    std::cout << "正在删除安装目录: " << installRoot.string() << "\n";
    fs::remove_all(installRoot);

    // Remove registry record if any matches this path
    auto ver = RegistryFindVersionByPath(installRoot);
    if (ver.has_value()) {
        RegistryDeleteVersion(*ver);
    }

    DeleteDataFolderIfNeeded(keepData);

    std::cout << "卸载完成。\n";
    return 0;
}

static int DoUninstallByVersion(const std::wstring& version, std::optional<bool> keepDataFlag) {
    fs::path installRoot;
    if (!RegistryTryGetInstallPathByVersion(version, installRoot)) {
        std::wcout << L"找不到软件（注册表无该版本记录）：'" << version << L"'。\n";
        std::wcout << L"请按目录（-d）卸载。\n";
        return 1;
    }
    return DoUninstallByDir(installRoot, keepDataFlag);
}

static fs::path DownloadLatestZipToTemp(DownloadInfo& outInfo) {
    const std::string mirrorPrefix = "https://ghproxy.it/";
    bool useMirror = false;

    std::cout << "是否使用镜像站（" << mirrorPrefix << "）加速下载？(y/n): ";
    std::string input;
    std::getline(std::cin, input);
    useMirror = (input == "y" || input == "Y");

    std::cout << "正在连接到 GitHub...\n\n";
    outInfo = GetLatestDownloadInfo(useMirror);

    std::cout << "最新版本: " << outInfo.version << "\n";
    std::cout << "下载 URL: " << outInfo.url << "\n";

    fs::path tempDir = GetTempDir();
    fs::create_directories(tempDir);

    std::string filename = "Xdows-Security.zip";
    size_t pos = outInfo.url.find_last_of('/');
    if (pos != std::string::npos && pos + 1 < outInfo.url.size()) {
        filename = outInfo.url.substr(pos + 1);
        size_t qpos = filename.find('?');
        if (qpos != std::string::npos) filename.erase(qpos);
        if (filename.empty()) filename = "Xdows-Security.zip";
    }

    fs::path zipPath = tempDir / filename;
    if (fs::exists(zipPath)) {
        std::cout << "检测到旧文件，正在删除...\n";
        std::error_code ec;
        fs::remove(zipPath, ec);
    }

    std::vector<std::string> dlHeaders = {
        "User-Agent: Xdows-Security/4.1",
        "Accept: application/octet-stream"
    };

    std::cout << "开始下载...\n";
    if (!DownloadFileHttpOpenRequest(outInfo.url, zipPath, dlHeaders, 8)) {
        throw std::runtime_error("文件下载失败");
    }

    std::cout << "\n下载成功! 文件已保存到:\n" << zipPath.string() << "\n";
    WriteZipMeta(zipPath, outInfo.version, outInfo.url);
    return zipPath;
}

static int DoUpdateByDir(const fs::path& userPath, std::optional<bool> keepDataFlag) {
    fs::path installRoot = NormalizeInstallRoot(userPath);
    if (!fs::exists(installRoot)) {
        std::cerr << "安装路径不存在: " << installRoot.string() << "\n";
        return 1;
    }

    // Download latest
    DownloadInfo info;
    fs::path zipPath = DownloadLatestZipToTemp(info);

    // Uninstall old by directory
    int urc = DoUninstallByDir(installRoot, keepDataFlag);
    if (urc != 0) return urc;

    // Install new (write registry by default) - but must enforce "same version not duplicate" rule
    // Here installRoot likely has no registry record now (we removed by path), so OK.
    return DoInstall(zipPath, installRoot, true);
}

static int DoUpdateByVersion(const std::wstring& version, std::optional<bool> keepDataFlag) {
    fs::path installRoot;
    if (!RegistryTryGetInstallPathByVersion(version, installRoot)) {
        std::wcout << L"找不到软件（注册表无该版本记录）：'" << version << L"'。\n";
        std::wcout << L"请按目录（-d）更新。\n";
        return 1;
    }
    return DoUpdateByDir(installRoot, keepDataFlag);
}

// ------------------------- CLI -------------------------

static bool IsFlag(const std::string& s) { return !s.empty() && s[0] == '-'; }

static void ShowHelp() {
    std::cout << "\n使用帮助:\n";
    std::cout << "  -help\n";
    std::cout << "      输出此帮助\n\n";

    std::cout << "  -download [安装位置]\n";
    std::cout << "      下载最新版本到临时目录；若提供安装位置则下载完成后自动安装（默认写注册表）。\n\n";

    std::cout << "  -install <zip路径> <安装位置> [-noreg]\n";
    std::cout << "      解压并安装；默认写注册表（版本号作为键名）。\n";
    std::cout << "      -noreg：安装时不修改注册表（允许同版本多份安装）。\n";
    std::cout << "      注意：写注册表需要能确定版本号（来自 <zip>.xdows.meta）。\n\n";

    std::cout << "  -list\n";
    std::cout << "      列出已安装版本（读取注册表安装记录）。\n\n";

    std::cout << "  -uninstall -d <目录> [-keepdata | -removedata]\n";
    std::cout << "  -uninstall -v <版本号> [-keepdata | -removedata]\n";
    std::cout << "      卸载；按目录或按版本号（精确匹配）定位。\n";
    std::cout << "      若 -v 找不到注册表记录，会提示按 -d 卸载。\n\n";

    std::cout << "  -update -d <目录> [-keepdata]\n";
    std::cout << "  -update -v <版本号> [-keepdata]\n";
    std::cout << "      更新：下载 latest -> 卸载目录 -> 安装到原目录（默认写注册表）。\n";
    std::cout << "      若 -v 找不到注册表记录，会提示按 -d 更新。\n\n";
}

static std::optional<std::string> NextArg(int& i, int argc, char* argv[]) {
    if (i + 1 >= argc) return std::nullopt;
    return std::string(argv[++i]);
}

int main(int argc, char* argv[]) {
    std::cout << "Xdows Security Installer\n";
    std::cout << "By Xdows Software\n";

    if (argc <= 1) {
        ShowHelp();
        return 0;
    }

    std::string cmd = argv[1];

    try {
        if (cmd == "-help") {
            ShowHelp();
            return 0;
        }

        if (cmd == "-list") {
            ListInstalledFromRegistry();
            return 0;
        }

        if (cmd == "-download") {
            DownloadInfo info;
            fs::path zipPath = DownloadLatestZipToTemp(info);

            if (argc >= 3 && !IsFlag(argv[2])) {
                fs::path installRoot = argv[2];
                // one-click install, default registry enabled
                return DoInstall(zipPath, installRoot, true);
            }
            return 0;
        }

        if (cmd == "-install") {
            if (argc < 4) {
                std::cerr << "-install 需要参数: <zip路径> <安装位置> [-noreg]\n";
                ShowHelp();
                return 1;
            }
            fs::path zipP = argv[2];
            fs::path installRoot = argv[3];

            bool noreg = false;
            for (int i = 4; i < argc; ++i) {
                std::string a = argv[i];
                if (a == "-noreg") noreg = true;
            }

            return DoInstall(zipP, installRoot, !noreg);
        }

        if (cmd == "-uninstall") {
            std::optional<std::string> mode;
            std::optional<std::string> value;
            bool keepFlag = false;
            bool removeFlag = false;

            for (int i = 2; i < argc; ++i) {
                std::string a = argv[i];
                if (a == "-d") {
                    mode = "d";
                    auto v = NextArg(i, argc, argv);
                    if (!v.has_value()) { std::cerr << "-d 需要目录\n"; return 1; }
                    value = *v;
                }
                else if (a == "-v") {
                    mode = "v";
                    auto v = NextArg(i, argc, argv);
                    if (!v.has_value()) { std::cerr << "-v 需要版本号\n"; return 1; }
                    value = *v;
                }
                else if (a == "-keepdata") {
                    keepFlag = true;
                }
                else if (a == "-removedata") {
                    removeFlag = true;
                }
            }

            if (!mode.has_value() || !value.has_value()) {
                std::cerr << "-uninstall 需要 -d <目录> 或 -v <版本号>\n";
                ShowHelp();
                return 1;
            }
            if (keepFlag && removeFlag) {
                std::cerr << "不能同时指定 -keepdata 和 -removedata\n";
                return 1;
            }

            std::optional<bool> keepData;
            if (keepFlag) keepData = true;
            if (removeFlag) keepData = false;

            if (*mode == "d") {
                return DoUninstallByDir(fs::path(*value), keepData);
            }
            else {
                return DoUninstallByVersion(Utf8ToWide(*value), keepData);
            }
        }

        if (cmd == "-update") {
            std::optional<std::string> mode;
            std::optional<std::string> value;
            bool keepFlag = false;

            for (int i = 2; i < argc; ++i) {
                std::string a = argv[i];
                if (a == "-d") {
                    mode = "d";
                    auto v = NextArg(i, argc, argv);
                    if (!v.has_value()) { std::cerr << "-d 需要目录\n"; return 1; }
                    value = *v;
                }
                else if (a == "-v") {
                    mode = "v";
                    auto v = NextArg(i, argc, argv);
                    if (!v.has_value()) { std::cerr << "-v 需要版本号\n"; return 1; }
                    value = *v;
                }
                else if (a == "-keepdata") {
                    keepFlag = true;
                }
            }

            if (!mode.has_value() || !value.has_value()) {
                std::cerr << "-update 需要 -d <目录> 或 -v <版本号>\n";
                ShowHelp();
                return 1;
            }

            // If -keepdata specified, keep without asking; otherwise interactive
            std::optional<bool> keepData;
            if (keepFlag) keepData = true;

            if (*mode == "d") {
                return DoUpdateByDir(fs::path(*value), keepData);
            }
            else {
                return DoUpdateByVersion(Utf8ToWide(*value), keepData);
            }
        }

        std::cerr << "未知命令: " << cmd << "\n";
        ShowHelp();
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << "\n";
        return 1;
    }
}
