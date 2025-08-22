#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <curl/curl.h>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <fstream>
#include <queue>
#include <functional>
#include <condition_variable>
#include <set>
#include <atomic>
#include <regex>
#include <map>
#include <chrono>
#include <ctime>

// ANSI color codes
#define GREEN   "\033[1;32m"
#define RED     "\033[1;31m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

std::mutex printMutex;
std::mutex reportMutex;

// Structure for storing vulnerability findings
struct VulnerabilityReport {
    std::string url;
    std::string type;
    std::string status;
    std::string parameter;
    std::string payload;
    float cvss_score;
    std::string severity;
};

std::vector<VulnerabilityReport> g_reports;

// CVSS Base Score mapping for common CWEs
std::map<std::string, std::pair<float, std::string>> cvss_map = {
    {"CWE-89", {9.8, "Critical"}}, // SQL Injection
    {"CWE-79", {6.1, "Medium"}},   // Cross-Site Scripting (XSS)
    // Add more mappings here for new vulnerability types
};

std::pair<float, std::string> getCvssInfo(const std::string& cwe) {
    if (cvss_map.count(cwe)) {
        return cvss_map[cwe];
    }
    return {0.0, "Unknown"};
}

// =================================================================
// Thread Pool Implementation (No changes needed here)
// =================================================================
class ThreadPool {
public:
    ThreadPool(size_t numThreads);
    ~ThreadPool();
    void enqueue(std::function<void()> task);
    void waitFinished();
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    std::condition_variable wait_condition;
    std::atomic<bool> stop;
    std::atomic<size_t> active_tasks;
};

ThreadPool::ThreadPool(size_t numThreads) : stop(false), active_tasks(0) {
    for (size_t i = 0; i < numThreads; ++i) {
        workers.emplace_back([this] {
            while (true) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(this->queue_mutex);
                    this->condition.wait(lock, [this] { return this->stop || !this->tasks.empty(); });
                    if (this->stop && this->tasks.empty()) {
                        return;
                    }
                    task = std::move(this->tasks.front());
                    this->tasks.pop();
                }
                task();
                active_tasks--;
                wait_condition.notify_all();
            }
        });
    }
}

void ThreadPool::enqueue(std::function<void()> task) {
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        if (stop) throw std::runtime_error("enqueue on stopped ThreadPool");
        tasks.emplace(std::move(task));
    }
    active_tasks++;
    condition.notify_one();
}

void ThreadPool::waitFinished() {
    std::unique_lock<std::mutex> lock(queue_mutex);
    wait_condition.wait(lock, [this] { return tasks.empty() && active_tasks == 0; });
}

ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        stop = true;
    }
    condition.notify_all();
    wait_condition.notify_all();
    for (std::thread &worker : workers) {
        worker.join();
    }
}
// =================================================================
// Utility Functions
// =================================================================
std::string urlEncode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << int((unsigned char)c);
        }
    }
    return escaped.str();
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string httpGet(const std::string& url) {
    CURL* curl = curl_easy_init();
    std::string response;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "PayloadSpecialistScanner/1.1");
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return response;
}

std::vector<std::string> loadPayloadsFromFile(const std::string& filename) {
    std::vector<std::string> payloads;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::lock_guard<std::mutex> guard(printMutex);
        std::cerr << RED << "Error: Could not open payload file: " << filename << RESET << std::endl;
        return payloads;
    }
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            payloads.push_back(line);
        }
    }
    return payloads;
}

void addReport(const std::string& url, const std::string& type, const std::string& status, const std::string& parameter, const std::string& payload, const std::string& cwe) {
    std::lock_guard<std::mutex> guard(reportMutex);
    auto cvss = getCvssInfo(cwe);
    g_reports.push_back({url, type, status, parameter, payload, cvss.first, cvss.second});
}

void printResult(const std::string& section, const std::string& url, const std::string& status, const std::string& details = "", const std::string& cwe = "") {
    std::lock_guard<std::mutex> guard(printMutex);
    auto cvss = getCvssInfo(cwe);
    std::cout << CYAN << "[+] " << section << RESET << " on " << url << std::endl;
    std::cout << "    Status: ";
    if (status == "VULNERABLE") {
        std::cout << RED << status << RESET;
        std::cout << " " << YELLOW << "(Severity: " << cvss.second << ", CVSS: " << std::fixed << std::setprecision(1) << cvss.first << ")" << RESET;
        std::cout << "\n    Details: " << details;
    } else {
        std::cout << GREEN << status << RESET;
    }
    std::cout << std::endl << std::endl;
}

// =================================================================
// Vulnerability Checks - "Payload Specialist" Logic
// =================================================================

void checkSQLInjection(const std::string& baseUrl, const std::vector<std::string>& params, const std::vector<std::string>& payloads) {
    for (const auto& param : params) {
        for (const auto& payload : payloads) {
            std::string testUrl = baseUrl + (baseUrl.find('?') == std::string::npos ? "?" : "&") + param + "=" + urlEncode(payload);
            std::string response = httpGet(testUrl);
            if (response.find("SQL") != std::string::npos || response.find("syntax error") != std::string::npos || response.find("mysql") != std::string::npos) {
                std::string details = "Parameter: " + param + ", Payload: " + payload;
                printResult("SQL Injection", testUrl, "VULNERABLE", details, "CWE-89");
                addReport(baseUrl, "SQL Injection", "VULNERABLE", param, payload, "CWE-89");
                return; // Found one, move to next page
            }
        }
    }
}

void checkXSS(const std::string& baseUrl, const std::vector<std::string>& params, const std::vector<std::string>& payloads) {
    for (const auto& param : params) {
        for (const auto& payload : payloads) {
            std::string testUrl = baseUrl + (baseUrl.find('?') == std::string::npos ? "?" : "&") + param + "=" + urlEncode(payload);
            std::string response = httpGet(testUrl);
            if (response.find(payload) != std::string::npos) {
                std::string details = "Parameter: " + param + ", Reflected Payload: " + payload;
                printResult("Cross-Site Scripting (XSS)", testUrl, "VULNERABLE", details, "CWE-79");
                addReport(baseUrl, "Cross-Site Scripting (XSS)", "VULNERABLE", param, payload, "CWE-79");
                return; // Found one, move to next page
            }
        }
    }
}

// =================================================================
// Crawler Implementation (No changes needed here)
// =================================================================
std::string getDomain(const std::string& url) {
    std::regex domain_regex(R"(^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n?]+))");
    std::smatch match;
    if (std::regex_search(url, match, domain_regex) && match.size() > 1) {
        return match[1].str();
    }
    return "";
}

std::set<std::string> findLinks(const std::string& baseUrl, const std::string& pageContent) {
    std::set<std::string> links;
    std::string baseDomain = getDomain(baseUrl);
    std::regex link_regex(R"|(<a\s+(?:[^>]*?\s+)?href="([^"]*)")|");
    auto words_begin = std::sregex_iterator(pageContent.begin(), pageContent.end(), link_regex);
    auto words_end = std::sregex_iterator();

    for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
        std::string link = (*i)[1].str();
        if (link.empty() || link[0] == '#' || link.rfind("javascript:", 0) == 0 || link.rfind("mailto:", 0) == 0) {
            continue;
        }

        if (link.rfind("//", 0) == 0) {
            link = "http:" + link;
        } else if (link.rfind("/", 0) == 0) {
            link = baseUrl.substr(0, baseUrl.find(baseDomain) + baseDomain.length()) + link;
        } else if (link.rfind("http", 0) != 0) {
            // Skip complex relative links for this example
            continue;
        }
        
        if (getDomain(link) == baseDomain) {
            links.insert(link);
        }
    }
    return links;
}
// =================================================================
// Report Generation
// =================================================================
void generateHtmlReport(const std::string& filename, const std::string& targetUrl) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << RED << "Failed to open report file: " << filename << RESET << std::endl;
        return;
    }

    // Get current time
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);

    // Calculate summary
    std::map<std::string, int> severity_counts;
    for(const auto& report : g_reports) {
        if(report.status == "VULNERABLE") {
            severity_counts[report.severity]++;
        }
    }

    file << R"html(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.9.2/html2pdf.bundle.min.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; background-color: #f4f7f9; color: #333; }
        .container { max-width: 1200px; margin: 20px auto; padding: 20px; background-color: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-radius: 8px; }
        h1, h2 { color: #2c3e50; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        #download-btn { background-color: #3498db; color: white; padding: 10px 15px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        #download-btn:hover { background-color: #2980b9; }
        .summary { display: flex; justify-content: space-around; text-align: center; margin: 20px 0; }
        .summary-box { padding: 20px; border-radius: 8px; color: #fff; min-width: 150px; }
        .critical { background-color: #c0392b; }
        .high { background-color: #e67e22; }
        .medium { background-color: #f1c40f; }
        .low { background-color: #27ae60; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; border: 1px solid #ddd; text-align: left; word-break: break-all; }
        th { background-color: #ecf0f1; color: #2c3e50; }
        tr.severity-Critical { background-color: #fadbd8; }
        tr.severity-High { background-color: #fdebd0; }
        tr.severity-Medium { background-color: #fef9e7; }
        .footer { text-align: center; margin-top: 20px; font-size: 0.9em; color: #777; }
    </style>
</head>
<body>
    <div class="container" id="report">
        <div class="header">
            <h1>Vulnerability Scan Report</h1>
            <button id="download-btn">Download as PDF</button>
        </div>
        <p><strong>Target URL:</strong> )html" << targetUrl << R"html(</p>
        <p><strong>Scan Date:</strong> )html" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << R"html(</p>

        <h2>Scan Summary</h2>
        <div class="summary">
            <div class="summary-box critical"><h3>)html" << severity_counts["Critical"] << R"html(</h3><p>Critical</p></div>
            <div class="summary-box high"><h3>)html" << severity_counts["High"] << R"html(</h3><p>High</p></div>
            <div class="summary-box medium"><h3>)html" << severity_counts["Medium"] << R"html(</h3><p>Medium</p></div>
            <div class="summary-box low"><h3>)html" << severity_counts["Low"] << R"html(</h3><p>Low</p></div>
        </div>

        <h2>Detailed Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Vulnerability</th>
                    <th>Parameter</th>
                    <th>Payload</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                </tr>
            </thead>
            <tbody>
    )html";

    for (const auto& report : g_reports) {
        if (report.status == "VULNERABLE") {
            file << "<tr class=\"severity-" << report.severity << "\">"
                 << "<td>" << report.url << "</td>"
                 << "<td>" << report.type << "</td>"
                 << "<td>" << report.parameter << "</td>"
                 << "<td>" << report.payload << "</td>"
                 << "<td>" << report.severity << "</td>"
                 << "<td>" << std::fixed << std::setprecision(1) << report.cvss_score << "</td>"
                 << "</tr>\n";
        }
    }

    file << R"html(
            </tbody>
        </table>
        <div class="footer">
            <p>Generated by PayloadSpecialistScanner/1.1</p>
        </div>
    </div>
    <script>
        document.getElementById('download-btn').addEventListener('click', function () {
            const element = document.getElementById('report');
            const opt = {
                margin:       0.5,
                filename:     'vulnerability_report.pdf',
                image:        { type: 'jpeg', quality: 0.98 },
                html2canvas:  { scale: 2 },
                jsPDF:        { unit: 'in', format: 'letter', orientation: 'portrait' }
            };
            html2pdf().set(opt).from(element).save();
        });
    </script>
</body>
</html>
    )html";

    std::cout << GREEN << "✅ HTML report generated: " << filename << RESET << std::endl;
}

// =================================================================
// Main Logic
// =================================================================

void scanPage(const std::string& url, const std::vector<std::string>& params, const std::vector<std::string>& sqlPayloads, const std::vector<std::string>& xssPayloads) {
    {
        std::lock_guard<std::mutex> guard(printMutex);
        std::cout << YELLOW << "Scanning: " << url << RESET << std::endl;
    }
    checkSQLInjection(url, params, sqlPayloads);
    checkXSS(url, params, xssPayloads);
    // Add new checks here...
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << RED << "Usage: ./scanner <start_url>" << RESET << std::endl;
        return 1;
    }

    std::string startUrl = argv[1];
    unsigned int num_threads = std::thread::hardware_concurrency();
    ThreadPool pool(num_threads);

    std::cout << YELLOW << "🔍 Starting powerful scan on: " << startUrl << " with " << num_threads << " threads." << RESET << std::endl;
    
    // Load payloads
    auto sqlPayloads = loadPayloadsFromFile("sql_payloads.txt");
    auto xssPayloads = loadPayloadsFromFile("xss_payloads.txt");
    if (sqlPayloads.empty() || xssPayloads.empty()) {
        std::cerr << RED << "Payload files are missing or empty. Exiting." << RESET << std::endl;
        return 1;
    }

    // Common parameters to test
    std::vector<std::string> common_params = {"id", "page", "file", "q", "search", "name", "item", "lang", "dir"};
    
    std::queue<std::string> urlsToCrawl;
    std::set<std::string> crawledUrls;
    
    urlsToCrawl.push(startUrl);
    crawledUrls.insert(startUrl);

    int max_urls_to_crawl = 50;
    int crawled_count = 0;

    while (!urlsToCrawl.empty() && crawled_count < max_urls_to_crawl) {
        std::string currentUrl = urlsToCrawl.front();
        urlsToCrawl.pop();
        crawled_count++;

        pool.enqueue([currentUrl, common_params, sqlPayloads, xssPayloads] {
            scanPage(currentUrl, common_params, sqlPayloads, xssPayloads);
        });

        std::string pageContent = httpGet(currentUrl);
        std::set<std::string> newLinks = findLinks(startUrl, pageContent);

        for (const auto& link : newLinks) {
            if (crawledUrls.find(link) == crawledUrls.end()) {
                crawledUrls.insert(link);
                urlsToCrawl.push(link);
            }
        }
    }
    
    pool.waitFinished();

    std::cout << GREEN << "\n✅ Scan complete!" << RESET << std::endl;
    
    generateHtmlReport("scan_report.html", startUrl);

    return 0;
}
