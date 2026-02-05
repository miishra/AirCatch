idf_component_register(SRCS "openhaystack_main.c"          
                    INCLUDE_DIRS "."
                    REQUIRES nvs_flash bt
                    PRIV_REQUIRES esp_driver_spi esp_driver_gpio)