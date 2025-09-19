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
#include <chrono>
#include <ctime>

// ANSI color codes
#define GREEN   "\033[1;32m"
#define RED     "\033[1;31m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

std::mutex printMutex;
std::mutex pagesMutex;
std::mutex subdomainsMutex;

// Data structures to hold findings
std::set<std::string> g_found_pages;
std::set<std::string> g_found_subdomains;

// =================================================================
// Thread Pool Implementation (No changes needed)
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
                    if (this->stop && this->tasks.empty()) return;
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
    for (std::thread &worker : workers) worker.join();
}

// =================================================================
// Utility Functions
// =================================================================
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
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "ReconTool/1.0");
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return response;
}

std::string getDomain(const std::string& url) {
    std::regex domain_regex(R"(^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n?]+))");
    std::smatch match;
    if (std::regex_search(url, match, domain_regex) && match.size() > 1) {
        return match[1].str();
    }
    return url; // Assume input is domain if regex fails
}

// =================================================================
// Core Logic: Subdomain and Page Discovery
// =================================================================

void checkSubdomain(const std::string& subdomain) {
    CURL* curl = curl_easy_init();
    if (curl) {
        std::string url = "http://" + subdomain;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L); // We only need to check for connection
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        
        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            // Any successful connection or valid HTTP response means it exists
            if (response_code > 0) {
                std::lock_guard<std::mutex> guard(subdomainsMutex);
                g_found_subdomains.insert(subdomain);
                std::lock_guard<std::mutex> print_guard(printMutex);
                std::cout << GREEN << "[+] Subdomain Found: " << subdomain << RESET << std::endl;
            }
        }
        curl_easy_cleanup(curl);
    }
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
        
        std::string full_url = "";
        if (link.rfind("//", 0) == 0) {
            full_url = "http:" + link;
        } else if (link.rfind("/", 0) == 0) {
            std::smatch match;
            std::regex base_url_regex(R"(^(https?:\/\/[^\/]+))");
            if(std::regex_search(baseUrl, match, base_url_regex)){
                full_url = match[1].str() + link;
            }
        } else if (link.rfind("http", 0) != 0) {
            continue;
        } else {
            full_url = link;
        }
        
        if (!full_url.empty() && getDomain(full_url) == baseDomain) {
            links.insert(full_url);
        }
    }
    return links;
}

// =================================================================
// HTML Report Generation
// =================================================================
void generateHtmlReport(const std::string& filename, const std::string& targetUrl) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << RED << "Failed to open report file: " << filename << RESET << std::endl;
        return;
    }
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);

    file << R"html(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Reconnaissance Report</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.9.2/html2pdf.bundle.min.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; background-color: #f4f7f9; color: #333; }
        .container { max-width: 1200px; margin: 20px auto; padding: 20px; background-color: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-radius: 8px; }
        h1, h2 { color: #2c3e50; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        #download-btn { background-color: #3498db; color: white; padding: 10px 15px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        .grid-container { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .list-box { border: 1px solid #ddd; border-radius: 5px; padding: 15px; max-height: 400px; overflow-y: auto; }
        .list-box ul { list-style-type: none; padding: 0; }
        .list-box li { padding: 8px; border-bottom: 1px solid #eee; word-break: break-all; }
        .list-box li:last-child { border-bottom: none; }
        .footer { text-align: center; margin-top: 20px; font-size: 0.9em; color: #777; }
    </style>
</head>
<body>
    <div class="container" id="report">
        <div class="header"><h1>Reconnaissance Report</h1><button id="download-btn">Download as PDF</button></div>
        <p><strong>Target Domain:</strong> )html" << getDomain(targetUrl) << R"html(</p>
        <p><strong>Scan Date:</strong> )html" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << R"html(</p>
        
        <div class="grid-container">
            <div>
                <h2>Found Subdomains ()html" << g_found_subdomains.size() << R"html()</h2>
                <div class="list-box"><ul>)html";
    for(const auto& sub : g_found_subdomains) file << "<li>" << sub << "</li>";
    file << R"html(</ul></div></div><div>
                <h2>Discovered Pages ()html" << g_found_pages.size() << R"html()</h2>
                <div class="list-box"><ul>)html";
    for(const auto& page : g_found_pages) file << "<li>" << page << "</li>";
    file << R"html(</ul></div></div>
        
        <div class="footer"><p>Generated by ReconTool/1.0</p></div>
    </div>
    <script>
        document.getElementById('download-btn').addEventListener('click', () => {
            const el = document.getElementById('report');
            html2pdf().from(el).set({filename: 'recon_report.pdf'}).save();
        });
    </script>
</body>
</html>)html";

    std::cout << GREEN << "✅ HTML report generated: " << filename << RESET << std::endl;
}

// =================================================================
// Main Logic
// =================================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << RED << "Usage: ./recon-tool <start_url_or_domain>" << RESET << std::endl;
        return 1;
    }

    std::string target = argv[1];
    std::string domain = getDomain(target);
    std::string startUrl = (target.find("http") == 0) ? target : "http://" + target;

    unsigned int num_threads = std::thread::hardware_concurrency() * 2;
    ThreadPool pool(num_threads);

    std::cout << YELLOW << "🔍 Starting reconnaissance on: " << domain << " with " << num_threads << " threads." << RESET << std::endl;

    // --- Start Subdomain Scan ---
    std::cout << CYAN << "[*] Starting subdomain scan..." << RESET << std::endl;
    std::vector<std::string> subdomain_wordlist = {
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2", "admin",
        "blog", "dev", "test", "api", "staging", "shop", "support", "forum", "news", "cdn"
    };
    for(const auto& word : subdomain_wordlist) {
        pool.enqueue([sub = word + "." + domain]{ checkSubdomain(sub); });
    }

    // --- Start Page Crawl ---
    std::cout << CYAN << "[*] Starting page crawl from: " << startUrl << RESET << std::endl;
    std::queue<std::string> urlsToCrawl;
    std::set<std::string> crawledUrls;
    
    urlsToCrawl.push(startUrl);
    crawledUrls.insert(startUrl);
    g_found_pages.insert(startUrl);

    int max_urls_to_crawl = 100;
    std::atomic<int> active_crawl_tasks = 0;

    // We can't use the simple while loop with the thread pool easily.
    // Instead, we create a function that can be re-enqueued.
    std::function<void(std::string)> crawlPage;
    crawlPage = [&](std::string currentUrl) {
        std::string pageContent = httpGet(currentUrl);
        std::set<std::string> newLinks = findLinks(startUrl, pageContent);

        for (const auto& link : newLinks) {
            bool inserted = false;
            {
                std::lock_guard<std::mutex> guard(pagesMutex);
                if (crawledUrls.find(link) == crawledUrls.end() && crawledUrls.size() < max_urls_to_crawl) {
                    crawledUrls.insert(link);
                    g_found_pages.insert(link);
                    inserted = true;
                }
            }
            if(inserted){
                 pool.enqueue([link, &crawlPage]{ crawlPage(link); });
            }
        }
    };
    
    pool.enqueue([startUrl, &crawlPage]{ crawlPage(startUrl); });
    
    pool.waitFinished();

    std::cout << GREEN << "\n✅ Reconnaissance complete!" << RESET << std::endl;
    
    generateHtmlReport("recon_report.html", target);

    return 0;
}
