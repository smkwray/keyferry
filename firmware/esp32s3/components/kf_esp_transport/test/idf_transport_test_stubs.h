#pragma once

// Native substitutes for carriers/crypto only. The test compiles the complete
// production EspTransport, EndpointSession and TransportArbiter unchanged.
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>

using ssize_t = std::ptrdiff_t;
using esp_err_t = int;
using EventBits_t = unsigned;
using EventGroupHandle_t = EventBits_t*;
using portMUX_TYPE = int;
using esp_event_base_t = int;
using esp_event_handler_instance_t = int;
struct mbedtls_ssl_context { unsigned controller = 0; };
struct mbedtls_ssl_config {};
struct mbedtls_x509_crt {};
struct mbedtls_md_info_t {};
struct esp_netif_t {};
struct wifi_init_config_t {};
struct wifi_event_sta_disconnected_t { int reason = 0; };
struct wifi_ap_record_t { int authmode = 1; };
struct esp_netif_ip_info_t { struct { unsigned addr = 1; } ip; };
struct wifi_config_t {
  struct {
    unsigned char ssid[32]{}, password[64]{};
    int scan_method = 0, sort_method = 0;
    struct { int rssi = 0, authmode = 0; } threshold;
    struct { bool capable = false, required = false; } pmf_cfg;
  } sta;
};
struct tls_keep_alive_cfg_t { bool enabled; int idle, interval, count; };
struct esp_tls_cfg_t {
  const std::uint8_t* cacert_buf = nullptr;
  unsigned cacert_bytes = 0;
  int timeout_ms = 0;
  const char* common_name = nullptr;
  bool skip_common_name = false;
  tls_keep_alive_cfg_t* keep_alive_cfg = nullptr;
  int addr_family = 0;
  const int* ciphersuites_list = nullptr;
  int tls_version = 0;
  bool non_block = false;
};
struct esp_tls_t {
  mbedtls_ssl_context ssl;
  bool closed = false;
  std::vector<std::uint8_t> incoming;
};
constexpr int ESP_OK = 0, ESP_ERR_NO_MEM = 1, ESP_EVENT_ANY_ID = -1;
constexpr int IP_EVENT = 1, WIFI_EVENT = 2, IP_EVENT_STA_GOT_IP = 3;
constexpr int WIFI_EVENT_STA_DISCONNECTED = 4, IP_EVENT_STA_LOST_IP = 5;
constexpr int WIFI_AUTH_WPA2_PSK = 1, WIFI_AUTH_WPA2_WPA3_PSK = 2;
constexpr int WIFI_STORAGE_RAM = 1, WIFI_MODE_STA = 1, WIFI_IF_STA = 1;
constexpr int WIFI_ALL_CHANNEL_SCAN = 1, WIFI_CONNECT_AP_BY_SIGNAL = 1;
constexpr int ESP_TLS_AF_INET = 1, ESP_TLS_VER_TLS_1_2 = 1;
constexpr int ESP_TLS_ERR_SSL_WANT_READ = -2, ESP_TLS_ERR_SSL_WANT_WRITE = -3;
constexpr int MBEDTLS_ERR_SSL_WANT_READ = -2, MBEDTLS_ERR_SSL_WANT_WRITE = -3;
constexpr int MBEDTLS_MD_SHA256 = 1;
constexpr unsigned BIT0 = 1, BIT1 = 2;
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL(lock) (void)(lock)
#define portEXIT_CRITICAL(lock) (void)(lock)
#define pdMS_TO_TICKS(ms) (ms)
#define ESP_LOGE(tag, ...) (void)(tag)
#define WIFI_INIT_CONFIG_DEFAULT() wifi_init_config_t{}

namespace idf_test {
struct Stop {};
inline std::uint64_t now = 0, stop_at = 0, tls_elapsed = 0;
inline unsigned advertised = 0, discovery_reads = 0, wifi_disconnects = 0;
inline unsigned ble_stops = 0, ble_starts = 0;
inline std::array<bool, 3> reachable{true, true, true};
inline std::array<bool, 3> failed{};
inline std::vector<std::unique_ptr<esp_tls_t>> connections;
inline std::function<void()> tick;
inline std::function<void(esp_tls_t*)> connected;
inline EventBits_t event_bits = 0;
}
inline std::int64_t esp_timer_get_time() { return idf_test::now * 1000; }
inline void vTaskDelay(unsigned ms) {
  idf_test::now += ms;
  if (idf_test::tick) idf_test::tick();
  if (idf_test::now >= idf_test::stop_at) throw idf_test::Stop{};
}
inline void esp_fill_random(void* data, std::size_t n) { std::memset(data, 0x66, n); }
inline EventGroupHandle_t xEventGroupCreate() { return &idf_test::event_bits; }
inline EventBits_t xEventGroupGetBits(EventGroupHandle_t bits) { return *bits; }
inline void xEventGroupClearBits(EventGroupHandle_t bits, unsigned mask) { *bits &= ~mask; }
inline void xEventGroupSetBits(EventGroupHandle_t bits, unsigned mask) { *bits |= mask; }
inline int esp_netif_init() { return 0; }
inline int esp_event_loop_create_default() { return 0; }
inline esp_netif_t* esp_netif_create_default_wifi_sta() { static esp_netif_t netif; return &netif; }
inline int esp_netif_get_ip_info(esp_netif_t*, esp_netif_ip_info_t*) { return 0; }
inline int esp_event_handler_instance_register(int, int, void(*)(void*,int,int,void*), void*, int*) { return 0; }
inline int esp_wifi_init(wifi_init_config_t*) { return 0; }
inline int esp_wifi_set_storage(int) { return 0; }
inline int esp_wifi_set_mode(int) { return 0; }
inline int esp_wifi_set_config(int, wifi_config_t*) { return 0; }
inline int esp_wifi_start() { return 0; }
inline int esp_wifi_connect() { return 0; }
inline int esp_wifi_disconnect() { ++idf_test::wifi_disconnects; return 0; }
inline int esp_wifi_sta_get_ap_info(wifi_ap_record_t*) { return 0; }
inline esp_tls_t* esp_tls_init() {
  idf_test::connections.push_back(std::make_unique<esp_tls_t>());
  return idf_test::connections.back().get();
}
inline int esp_tls_conn_new_sync(const char* address, int, int, const esp_tls_cfg_t*, esp_tls_t* tls) {
  tls->ssl.controller = static_cast<unsigned>(address[std::strlen(address) - 1] - '1');
  idf_test::now += idf_test::tls_elapsed;
  if (!idf_test::reachable.at(tls->ssl.controller)) return 0;
  if (idf_test::connected) idf_test::connected(tls);
  return 1;
}
inline void esp_tls_conn_destroy(esp_tls_t* tls) { tls->closed = true; }
inline void* esp_tls_get_ssl_context(esp_tls_t* tls) { return &tls->ssl; }
inline ssize_t esp_tls_conn_write(esp_tls_t*, const void*, std::size_t length) { return length; }
inline int esp_tls_conn_read(esp_tls_t* tls, void* output, std::size_t capacity) {
  if (idf_test::failed.at(tls->ssl.controller)) return 0;
  if (tls->incoming.empty()) return ESP_TLS_ERR_SSL_WANT_READ;
  const auto n = std::min(capacity, tls->incoming.size());
  std::memcpy(output, tls->incoming.data(), n);
  tls->incoming.erase(tls->incoming.begin(), tls->incoming.begin() + n);
  return static_cast<int>(n);
}
inline const mbedtls_md_info_t* mbedtls_md_info_from_type(int) { static mbedtls_md_info_t info; return &info; }
inline int mbedtls_md_hmac(const mbedtls_md_info_t*, const unsigned char*, std::size_t,
                           const unsigned char*, std::size_t, unsigned char* out) {
  std::memset(out, 0x66, 32); return 0;
}
inline int mbedtls_md(const mbedtls_md_info_t*, const unsigned char*, std::size_t, unsigned char* out) {
  std::memset(out, 0x66, 32); return 0;
}
