#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_netif.h>
#include <nvs_flash.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <lwip/pbuf.h>
#include <dhcpserver/dhcpserver.h>


_Static_assert(offsetof(struct pbuf, payload) == 4, "filter.S reads payload at offset 4");
_Static_assert(offsetof(struct pbuf, len) == 10, "filter.S reads len at offset 10");


void subnet(uint32_t ip, uint32_t mask);
int gatekeep(struct pbuf* p, uint32_t dest);
uint64_t fnv(const char* s);
int listed(const char* name);
int question(const uint8_t* q, int len, char* name, int* qtype, int* end);
int sinkhole(const uint8_t* q, int end, int qtype, uint8_t* out);
int calm(uint32_t ip);
void dns(uint32_t ip, uint32_t mask);
void stats(void);


extern volatile unsigned long passed;
extern volatile unsigned long foreign;
extern volatile unsigned long ported;
extern volatile unsigned long stranger;


static int good;
static int total;


static esp_netif_t* sta;
static esp_netif_t* ap;


static void onwifi(void* arg, esp_event_base_t base, int32_t id, void* data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START)
    {
        esp_wifi_connect();
    }
    else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED)
    {
        wifi_event_sta_disconnected_t* e = data;

        printf("Lost %s (reason %d), trying again...\n", CONFIG_UP_SSID, e->reason);
        esp_wifi_connect();
    }
    else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t* e = data;
        struct in_addr a;
        char text[16];

        a.s_addr = e->ip_info.ip.addr;
        inet_ntop(AF_INET, &a, text, sizeof text);
        printf("Joined %s as %s, relaying now!!\n", CONFIG_UP_SSID, text);
        esp_netif_napt_enable(ap);
    }
    else if (base == WIFI_EVENT && id == WIFI_EVENT_AP_STACONNECTED)
    {
        wifi_event_ap_staconnected_t* e = data;

        printf("Device %02x:%02x:%02x:%02x:%02x:%02x joined the relay\n",
            e->mac[0], e->mac[1], e->mac[2], e->mac[3], e->mac[4], e->mac[5]);
    }
    else if (base == WIFI_EVENT && id == WIFI_EVENT_AP_STADISCONNECTED)
    {
        wifi_event_ap_stadisconnected_t* e = data;

        printf("Device %02x:%02x:%02x:%02x:%02x:%02x left the relay\n",
            e->mac[0], e->mac[1], e->mac[2], e->mac[3], e->mac[4], e->mac[5]);
    }
}


static void network(void)
{
    esp_netif_ip_info_t info;
    esp_netif_dns_info_t server;
    dhcps_offer_t offer = OFFER_DNS;

    memset(&info, 0, sizeof info);
    info.ip.addr = htonl(0x0A2C0001u);
    info.gw.addr = htonl(0x0A2C0001u);
    info.netmask.addr = htonl(0xFFFFFF00u);

    esp_netif_dhcps_stop(ap);
    ESP_ERROR_CHECK(esp_netif_set_ip_info(ap, &info));
    esp_netif_dhcps_option(ap, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, &offer, sizeof offer);

    memset(&server, 0, sizeof server);
    server.ip.type = ESP_IPADDR_TYPE_V4;
    server.ip.u_addr.ip4.addr = info.ip.addr;
    esp_netif_set_dns_info(ap, ESP_NETIF_DNS_MAIN, &server);
    ESP_ERROR_CHECK(esp_netif_dhcps_start(ap));

    subnet(ntohl(info.ip.addr), ntohl(info.netmask.addr));
    dns(ntohl(info.ip.addr), ntohl(info.netmask.addr));
}


static void radio(void)
{
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    wifi_config_t up;
    wifi_config_t relay;

    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, onwifi, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, onwifi, NULL);

    memset(&up, 0, sizeof up);
    strncpy((char*)up.sta.ssid, CONFIG_UP_SSID, sizeof up.sta.ssid);
    strncpy((char*)up.sta.password, CONFIG_UP_PASSWORD, sizeof up.sta.password);
    up.sta.threshold.authmode = strlen(CONFIG_UP_PASSWORD) > 0 ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    up.sta.pmf_cfg.capable = true;
    up.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;

    memset(&relay, 0, sizeof relay);
    strncpy((char*)relay.ap.ssid, CONFIG_AP_SSID, sizeof relay.ap.ssid);
    strncpy((char*)relay.ap.password, CONFIG_AP_PASSWORD, sizeof relay.ap.password);
    relay.ap.ssid_len = strlen(CONFIG_AP_SSID);
    relay.ap.channel = 1;
    relay.ap.max_connection = CONFIG_AP_MAX;
    relay.ap.authmode = WIFI_AUTH_WPA2_WPA3_PSK;
    relay.ap.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
    relay.ap.pmf_cfg.capable = true;
    relay.ap.pmf_cfg.required = false;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &up));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &relay));
    ESP_ERROR_CHECK(esp_wifi_start());

    printf("Relay %s is up with WPA2/WPA3, joining %s...\n", CONFIG_AP_SSID, CONFIG_UP_SSID);
}


static void check(const char* what, int ok)
{
    total++;
    good += ok;

    if (!ok)
    {
        printf("Self-test FAILED: %s\n", what);
    }
}


static int probe(uint32_t to, int proto, int port)
{
    uint8_t pkt[40];
    struct pbuf p;

    memset(pkt, 0, sizeof pkt);
    memset(&p, 0, sizeof p);
    pkt[0] = 0x45;
    pkt[9] = proto;
    pkt[12] = 10;
    pkt[13] = 44;
    pkt[14] = 0;
    pkt[15] = 5;
    pkt[22] = port >> 8;
    pkt[23] = port & 255;
    p.payload = pkt;
    p.len = sizeof pkt;

    return gatekeep(&p, to);
}


static void selftest(void)
{
    static const uint8_t ask[] =
    {
        0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
        3, 'A', 'd', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
        0, 1, 0, 1
    };
    uint8_t out[128];
    char name[256];
    int qtype = 0;
    int end = 0;
    int n;
    int burst = 1;

    subnet(0x0A2C0001u, 0xFFFFFF00u);

    check("8.8.8.8 should pass", probe(0x08080808u, 6, 443) == 1);
    check("142.250.80.46 should pass", probe(0x8EFA502Eu, 6, 443) == 1);
    check("9.9.9.9 should pass", probe(0x09090909u, 6, 443) == 1);
    check("1.1.1.1 should drop", probe(0x01010101u, 6, 443) == 0);
    check("77.88.55.88 should drop", probe(0x4D58373Bu, 6, 443) == 0);
    check("Instagram 31.13.71.174 (IE) should pass", probe(0x1F0D47AEu, 6, 443) == 1);
    check("Instagram 185.60.218.174 (IE) should pass", probe(0xB93CDAAEu, 6, 443) == 1);
    check("192.168.1.1 should drop", probe(0xC0A80101u, 6, 443) == 0);
    check("reply to 10.44.0.7 should pass", probe(0x0A2C0007u, 6, 443) == 1);
    check("udp/53 to 8.8.8.8 should drop", probe(0x08080808u, 17, 53) == 0);
    check("tcp/853 to 8.8.8.8 should drop", probe(0x08080808u, 6, 853) == 0);

    check("fnv google.com", fnv("google.com") == 0xe1a2c1ae38dcdf45ULL);
    check("fnv doubleclick", fnv("4436230.fls.doubleclick.net") == 0x45a245e577fccfbcULL);
    check("doubleclick is blocked", listed("4436230.fls.doubleclick.net") == 1);
    check("google.com is allowed", listed("google.com") == 0);
    check("s.youtube.com is allowed", listed("s.youtube.com") == 0);
    check("YouTube ad server pubads is blocked", listed("pubads.g.doubleclick.net") == 1);
    check("YouTube video API stays allowed", listed("youtubei.googleapis.com") == 0);

    check("question parses", question(ask, sizeof ask, name, &qtype, &end) == 1);
    check("question name", strcmp(name, "ads.example.com") == 0);
    check("question type", qtype == 1 && end == (int)sizeof ask);
    n = sinkhole(ask, end, qtype, out);
    check("sinkhole size", n == 49);
    check("sinkhole header", out[0] == 0x12 && out[1] == 0x34 && out[2] == 0x81 && out[3] == 0x80 && out[7] == 1);
    check("sinkhole answer", out[n - 4] == 0 && out[n - 3] == 0 && out[n - 2] == 0 && out[n - 1] == 0);

    for (int i = 0; i < 50; i++)
    {
        burst &= calm(0x01020304u);
    }

    check("50 lookups a second are fine", burst == 1);
    check("the 51st is held back", calm(0x01020304u) == 0);

    passed = 0;
    foreign = 0;
    ported = 0;
    stranger = 0;

    printf("Self-test: %d of %d assembly checks passed%s\n", good, total, good == total ? "!!" : "");
}


void app_main(void)
{
    selftest();

    if (nvs_flash_init() != ESP_OK)
    {
        nvs_flash_erase();
        nvs_flash_init();
    }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    sta = esp_netif_create_default_wifi_sta();
    ap = esp_netif_create_default_wifi_ap();
    esp_netif_set_default_netif(sta);

    network();
    stats();
    radio();

}