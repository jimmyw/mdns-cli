cmake_minimum_required(VERSION 3.16)
project(mdns-cli
        VERSION 1.0.0
        DESCRIPTION "Interactive mDNS and SSDP network scanner"
        LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)   # getifaddrs, SO_REUSEPORT, ip_mreqn

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(ENABLE_ASAN "Build with AddressSanitizer and UBSan" OFF)

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes)

if(ENABLE_ASAN)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

# ncursesw: pkg-config knows about the wide build; FindCurses is the fallback.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(NCURSES IMPORTED_TARGET ncursesw)
endif()
if(NOT NCURSES_FOUND)
  set(CURSES_NEED_NCURSES TRUE)
  set(CURSES_NEED_WIDE TRUE)
  find_package(Curses REQUIRED)
endif()

# Everything except main(), so the tests can link the same objects.
add_library(mdnscli_core STATIC
  src/util.c
  src/dns.c
  src/net.c
  src/device.c
  src/http.c
  src/xmlmini.c
  src/mdns.c
  src/ssdp.c
  src/ping.c
  src/neigh.c
  src/clip.c
  src/oui.c
  src/fetcher.c
)
target_include_directories(mdnscli_core PUBLIC src)

add_executable(mdns-cli src/main.c src/ui.c)
target_link_libraries(mdns-cli PRIVATE mdnscli_core)

if(NCURSES_FOUND)
  target_link_libraries(mdns-cli PRIVATE PkgConfig::NCURSES)
else()
  target_include_directories(mdns-cli PRIVATE ${CURSES_INCLUDE_DIRS})
  target_link_libraries(mdns-cli PRIVATE ${CURSES_LIBRARIES})
endif()

include(GNUInstallDirs)
# The OUI vendor DB is program data, so it lives in <prefix>/share/<pkg>/ (not
# bin/). It's copied next to the binary in the build tree; at install time the
# binary resolves it from <exedir>/../share/<pkg>/oui.bin after failing on
# <exedir>/oui.bin. Override at runtime with the MDNS_OUI env var.
file(COPY data/oui.bin DESTINATION ${CMAKE_BINARY_DIR})
install(TARGETS mdns-cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
# DB goes in <prefix>/share/<pkg>/ (program data, not bin/). The DB filename
# and <pkg> here must match the path suffixes searched in src/oui.c.
install(FILES data/oui.bin DESTINATION share/${PROJECT_NAME})

enable_testing()
add_executable(test_dns tests/test_dns.c)
target_link_libraries(test_dns PRIVATE mdnscli_core)
add_test(NAME dns_parser COMMAND test_dns)

add_executable(test_parse tests/test_parse.c)
target_link_libraries(test_parse PRIVATE mdnscli_core)
add_test(NAME http_xml_store COMMAND test_parse)
