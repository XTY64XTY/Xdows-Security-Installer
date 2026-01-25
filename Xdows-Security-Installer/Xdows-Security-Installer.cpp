#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <iomanip>
#include <chrono>
#include <windows.h>
#include <wininet.h>
#include <shlobj.h>
#include <filesystem>
#include <cstdlib>

namespace fs = std::filesystem;

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shell32.lib")

fs::path GetCacheDirectory() {
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath) == 0) {
        throw std::runtime_error("无法获取临时目录路径");
    }
    return fs::path(tempPath);
}

std::string HttpGet(const char* url) {
    HINTERNET hSession = InternetOpenA("Xdows-Security/4.1", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hSession) {
        throw std::runtime_error("InternetOpenA 失败: " + std::to_string(GetLastError()));
    }
    HINTERNET hConnect = InternetOpenUrlA(hSession, url, nullptr, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        InternetCloseHandle(hSession);
        throw std::runtime_error("InternetOpenUrlA 失败: " + std::to_string(GetLastError()));
    }

    std::string response;
    char buffer[4096];
    DWORD bytesRead;
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        response.append(buffer, bytesRead);
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hSession);

    if (response.empty()) {
        throw std::runtime_error("空响应");
    }
    return response;
}

// 从 JSON 提取下载 URL
std::string ExtractDownloadUrl(const std::string& json) {
    std::regex assetRegex(R"("browser_download_url"\s*:\s*"([^"]+))");
    std::smatch match;
    if (std::regex_search(json, match, assetRegex) && match.size() > 1) {
        return match[1].str();
    }
    throw std::runtime_error("JSON 中未找到有效的下载 URL");
}

// 下载文件
bool DownloadFile(const std::string& url, const fs::path& outputPath) {
    HINTERNET hSession = InternetOpenA("XdowsSecurityInstaller/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hSession) return false;
    HINTERNET hFile = InternetOpenUrlA(hSession, url.c_str(), nullptr, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hFile) {
        InternetCloseHandle(hSession);
        return false;
    }

    DWORD contentLength = 0;
    DWORD bufLen = sizeof(contentLength);
    HttpQueryInfoA(hFile, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &contentLength, &bufLen, nullptr);

    FILE* fp = nullptr;
    // 修复 fopen_s 调用
    if (fopen_s(&fp, outputPath.string().c_str(), "wb") != 0 || !fp) {
        InternetCloseHandle(hFile);
        InternetCloseHandle(hSession);
        return false;
    }

    char buffer[8192];
    DWORD bytesRead;
    size_t totalRead = 0;
    bool success = true;

    // 获取开始时间用于计算速度和剩余时间
    auto startTime = std::chrono::steady_clock::now();
    auto lastUpdate = startTime;
    double lastRead = 0;

    std::cout << "\n正在下载 ";
    if (contentLength > 0) {
        std::cout << "(" << contentLength << " 字节) ";
    }
    std::cout.flush();

    while (InternetReadFile(hFile, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        if (fwrite(buffer, 1, bytesRead, fp) != bytesRead) {
            success = false;
            break;
        }
        totalRead += bytesRead;

        // 计算下载速度和剩余时间
        auto currentTime = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - lastUpdate).count();

        if (elapsed >= 500) { // 每500毫秒更新一次速度
            double currentSpeed = (totalRead - lastRead) / (elapsed / 1000.0); // 字节/秒
            lastRead = static_cast<double>(totalRead);
            lastUpdate = currentTime;

            double remainingTime = 0;
            if (contentLength > 0 && currentSpeed > 0) {
                remainingTime = (contentLength - totalRead) / currentSpeed; // 秒
            }

            // 清除当前行并重新打印
            std::cout << "\r";
            if (contentLength > 0) {
                int percent = static_cast<int>((static_cast<double>(totalRead) / contentLength) * 100);
                std::cout << "[" << std::setw(3) << percent << "%] ";
            }

            // 格式化下载速度
            std::string speedStr;
            if (currentSpeed > 1024 * 1024) {
                speedStr = std::to_string(static_cast<int>(currentSpeed / (1024 * 1024))) + " MB/s";
            }
            else if (currentSpeed > 1024) {
                speedStr = std::to_string(static_cast<int>(currentSpeed / 1024)) + " KB/s";
            }
            else {
                speedStr = std::to_string(static_cast<int>(currentSpeed)) + " B/s";
            }

            // 格式化剩余时间
            std::string timeStr;
            if (remainingTime > 0) {
                if (remainingTime > 60) {
                    timeStr = std::to_string(static_cast<int>(remainingTime / 60)) + "m " +
                        std::to_string(static_cast<int>(remainingTime) % 60) + "s";
                }
                else {
                    timeStr = std::to_string(static_cast<int>(remainingTime)) + "s";
                }
            }
            else {
                timeStr = "N/A";
            }

            std::cout << totalRead << "/" << contentLength << " 字节 | 速度: " << speedStr
                << " | 剩余: " << timeStr;
            std::cout.flush();
        }
    }

    // 最终更新显示
    std::cout << "\r";
    if (contentLength > 0) {
        std::cout << "[100%] ";
    }
    std::cout << totalRead << "/" << contentLength << " 字节 | 完成!" << std::endl;

    fclose(fp);
    InternetCloseHandle(hFile);
    InternetCloseHandle(hSession);

    if (!success) {
        fs::remove(outputPath);
        return false;
    }
    return true;
}

std::string GetDownloadUrl() {
    const std::string mirrorPrefix = "https://ghproxy.it/";
    bool useMirror = false;
    std::cout << "是否使用镜像站（" << mirrorPrefix << "）加速下载？(y/n): ";
    std::string input;
    std::getline(std::cin, input);
    if (input == "y" || input == "Y") {
        useMirror = true;
        std::cout << "已启用镜像站: " << mirrorPrefix << std::endl;
    }
    else {
        std::cout << "使用原始 GitHub 下载链接。\n";
    }
    std::cout << "正在连接到 GitHub...\n" << std::endl;
    const char* apiUrl = "https://api.github.com/repositories/1032964256/releases/latest";
    std::string jsonResponse = HttpGet(apiUrl);
    std::string downloadUrl = ExtractDownloadUrl(jsonResponse);
    if (useMirror) {
        downloadUrl = mirrorPrefix + downloadUrl;
    }
    std::cout << "下载 URL: " << downloadUrl << std::endl;
    return downloadUrl;
}
static void showHelp() {
    std::cout << "\n使用帮助:\n";
    std::cout << "命令行参数\n";
    std::cout << "  -help 输出此帮助，命令行无参数时的默认值\n";
    std::cout << "  -download 下载最新版本的 Xdows Security 到临时目录\n";
    std::cout << "  -install <zip路径> <安装位置> 将指定压缩包解压到安装位置，并将目录名 \"win-x64\" 重命名为 \"Xdows-Security\"\n";
    std::cout << "  -uninstall <安装位置> 卸载指定安装位置的 Xdows-Security\n";

}
static int runInstall(const std::string& zipPath, const std::string& installPath) {
    try {
        fs::path zipP = zipPath;
        fs::path destP = installPath;

        if (!fs::exists(zipP) || !fs::is_regular_file(zipP)) {
            std::cerr << "压缩包不存在: " << zipP.string() << std::endl;
            return 1;
        }

        // 创建目标目录
        fs::create_directories(destP);

        // 使用 PowerShell 的 Expand-Archive 来解压（依赖 Windows PowerShell）
        // 使用单引号包裹路径以减少转义问题
        std::string cmd = "powershell -NoProfile -Command \"Expand-Archive -LiteralPath '" + zipP.string() + "' -DestinationPath '" + destP.string() + "' -Force\"";
        std::cout << "正在解压: " << zipP.string() << " 到 " << destP.string() << std::endl;
        int rc = std::system(cmd.c_str());
        if (rc != 0) {
            std::cerr << "解压失败，PowerShell 返回代码: " << rc << std::endl;
            return 1;
        }

        // 在目标目录中查找名为 "win-x64" 的目录并重命名为 "Xdows-Security"
        bool renamed = false;
        for (auto& entry : fs::recursive_directory_iterator(destP)) {
            try {
                if (entry.is_directory() && entry.path().filename() == "win-x64") {
                    fs::path newPath = entry.path().parent_path() / "Xdows-Security";
                    if (fs::exists(newPath)) {
                        std::cout << "目标目录已存在，正在删除: " << newPath.string() << std::endl;
                        fs::remove_all(newPath);
                    }
                    fs::rename(entry.path(), newPath);
                    std::cout << "已将 " << entry.path().string() << " 重命名为 " << newPath.string() << std::endl;
                    renamed = true;
                    break;
                }
            }
            catch (const std::exception& e) {
                // 继续尝试其他条目
                std::cerr << "处理路径时出错: " << entry.path().string() << " -> " << e.what() << std::endl;
            }
        }

        if (!renamed) {
            std::cout << "未找到名为 'win-x64' 的目录，未执行重命名。" << std::endl;
        }

        std::cout << "安装完成。" << std::endl;
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }
}
static int runUninstall(const std::string& installPath) {
    try {
        fs::path destP = installPath;
        if (!fs::exists(destP)) {
            std::cerr << "安装路径不存在: " << destP.string() << std::endl;
            return 1;
        }

        // 卸载前确认
        std::cout << "确定要卸载并删除安装目录 '" << destP.string() << "' ? (y/n): ";
        std::string conf;
        std::getline(std::cin, conf);
        if (!(conf == "y" || conf == "Y")) {
            std::cout << "已取消卸载。" << std::endl;
            return 0;
        }

        // 删除安装目录
        std::cout << "正在删除安装目录: " << destP.string() << std::endl;
        fs::remove_all(destP);

        // 提示是否删除 %LOCALAPPDATA%\Xdows-Security 目录
        char* localAppData = nullptr;
        size_t len = 0;
        errno_t err = _dupenv_s(&localAppData, &len, "LOCALAPPDATA");
        if (err == 0 && localAppData != nullptr) {
            fs::path settingsRoot = fs::path(localAppData) / "Xdows-Security";
            std::cout << "是否同时删除配置文件、信任区、隔离区等数据 (" << settingsRoot.string() << ")? (y/n): ";
            std::string input;
            std::getline(std::cin, input);
            if (input == "y" || input == "Y") {
                if (fs::exists(settingsRoot)) {
                    fs::remove_all(settingsRoot);
                    std::cout << "已删除: " << settingsRoot.string() << std::endl;
                } else {
                    std::cout << "未找到目录: " << settingsRoot.string() << std::endl;
                }
            }
        } else {
            std::cout << "无法获取 LOCALAPPDATA 环境变量，跳过删除设置。" << std::endl;
        }
        if (localAppData) free(localAppData);

        std::cout << "卸载完成。" << std::endl;
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }
}
static int runDownload() {
    try {
        std::string downloadUrl = GetDownloadUrl();

        fs::path cacheDir = GetCacheDirectory();
        fs::create_directories(cacheDir);

        std::string filename = "Xdows-Security.zip";
        size_t pos = downloadUrl.find_last_of('/');
        if (pos != std::string::npos && pos < downloadUrl.size() - 1) {
            filename = downloadUrl.substr(pos + 1);
            size_t qpos = filename.find('?');
            if (qpos != std::string::npos) {
                filename.erase(qpos);
            }
        }

        fs::path outputPath = cacheDir / filename;
        if (fs::exists(outputPath)) {
            std::cout << "检测到旧文件，正在删除...\n";
            fs::remove(outputPath);
        }

        std::cout << "开始下载...\n";
        if (!DownloadFile(downloadUrl, outputPath)) {
            throw std::runtime_error("文件下载失败");
        }

        std::cout << "\n下载成功! 文件已保存到:\n" << outputPath.string() << std::endl;
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "\n错误: " << e.what() << std::endl;
        return 1;
    }
}
int main(int argc, char* argv[]) {
    std::cout << "Xdows Security Installer\n";
    std::cout << "By Xdows Software\n";

    if (argc <= 1)
    {
        showHelp();
        return 0;
    }
    for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
        if (arg == "-help") {
            showHelp();
            return 0;
        }else if (arg == "-download") {
            return runDownload();
        } else if (arg == "-install") {
            if (i + 2 >= argc) {
                std::cerr << "-install 需要两个参数: <zip路径> <安装位置>\n";
                showHelp();
                return 1;
            }
            std::string zipPath = argv[++i];
            std::string installPath = argv[++i];
            return runInstall(zipPath, installPath);
        } else if (arg == "-uninstall") {
            if (i + 1 >= argc) {
                std::cerr << "-uninstall 需要一个参数: <安装位置>\n";
                showHelp();
                return 1;
            }
            std::string installPath = argv[++i];
            return runUninstall(installPath);
        }
        else {
            std::cerr << "未知参数: " << arg << std::endl;
            showHelp();
            return 1;
		}
    }
}