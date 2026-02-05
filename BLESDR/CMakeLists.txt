cmake_minimum_required(VERSION 3.10...3.30)
project (blesdr)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

# add_subdirectory(blesdr-tools)

# iq2pcap target (no LimeSuite required)
add_executable(iq2pcap
    iq2pcap.cpp
    modified_lib/BLESDREncoder.cpp
    modified_lib/BLESDRDecoder.cpp
)
target_include_directories(iq2pcap PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/modified_lib
)

# Find and link OpenSSL for HMAC
find_package(OpenSSL REQUIRED)
target_link_libraries(iq2pcap PRIVATE OpenSSL::Crypto)

# If your build needs math:
find_library(M_LIB m)
if(M_LIB)
  target_link_libraries(iq2pcap PRIVATE ${M_LIB})
endif()
