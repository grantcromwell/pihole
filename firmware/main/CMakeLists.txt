idf_component_register(SRCS "main.c" "dns.c" "report.c" "filter.S" "sinkhole.S" "gen/policy.c"
                       PRIV_REQUIRES esp_wifi esp_netif esp_event nvs_flash
                                     esp_hw_support pthread lwip
                       EMBED_FILES "gen/ranges.bin" "gen/domains.bin")

idf_component_get_property(lwip lwip COMPONENT_LIB)
target_compile_options(${lwip} PRIVATE "-I${CMAKE_CURRENT_LIST_DIR}")
target_compile_definitions(${lwip} PRIVATE "ESP_IDF_LWIP_HOOK_FILENAME=\"hook.h\"")
