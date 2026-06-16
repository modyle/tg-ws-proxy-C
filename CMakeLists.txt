cmake_minimum_required(VERSION 3.15)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

# Форсируем статический рантайм /MT для всего проекта
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project(tg_c_bridge C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

cmake_policy(SET CMP0048 NEW)
cmake_policy(SET CMP0091 NEW)

include(FetchContent)

# 1. Настройки OpenSSL для libwebsockets (Прямые пути к MT)
set(LWS_WITH_OPENSSL ON CACHE BOOL "" FORCE)
set(LWS_WITH_GNUTLS OFF CACHE BOOL "" FORCE)
set(LWS_OPENSSL_INCLUDE_DIRS "C:/Program Files/OpenSSL-Win64/include" CACHE STRING "" FORCE)
set(LWS_OPENSSL_LIBRARIES "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MT/libssl.lib;C:/Program Files/OpenSSL-Win64/lib/VC/x64/MT/libcrypto.lib" CACHE STRING "" FORCE)

# 2. Оптимизируем настройки libwebsockets, убирая ломающиеся на Windows модули
set(LWS_WITH_MINIMAL_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LWS_WITHOUT_TESTAPPS ON CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(LWS_WITH_SHARED OFF CACHE BOOL "" FORCE)
set(LWS_WITH_STATIC ON CACHE BOOL "" FORCE)
set(LWS_WITH_DIR OFF CACHE BOOL "" FORCE) # Выключаем багнутый module, который требовал 'vpt'

# Возвращаем стабильный релизный тег v4.3.3
FetchContent_Declare(
    libwebsockets
    GIT_REPOSITORY https://github.com/warmcat/libwebsockets.git
    GIT_TAG         v4.3.3
)
FetchContent_MakeAvailable(libwebsockets)

# Наш исполняемый файл
add_executable(tg_bridge
    src/main.c
    src/mtproto.c
    src/mtproto_transport.c
    src/secret.c
    src/crash_handler.c
    src/mem.c
)

# Указываем CMake, что наш таргет зависит от сборки библиотеки
add_dependencies(tg_bridge websockets)

# Пути для поиска заголовочных файлов (.h)
target_include_directories(tg_bridge PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    "C:/Program Files/OpenSSL-Win64/include"
    "${libwebsockets_SOURCE_DIR}/include"
    "${libwebsockets_BINARY_DIR}"
)

# Линкуем библиотеки (.lib) — исправили websockets_static на websockets
target_link_libraries(tg_bridge PRIVATE 
    websockets
    "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MT/libssl_static.lib"
    "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MT/libcrypto_static.lib"
)

if(WIN32)
    target_link_libraries(tg_bridge PRIVATE ws2_32 userenv bcrypt crypt32 iphlpapi)
    if(MSVC)
        target_link_options(tg_bridge PRIVATE "/SUBSYSTEM:CONSOLE")
    endif()
endif()