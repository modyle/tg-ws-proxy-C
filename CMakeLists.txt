cmake_minimum_required(VERSION 3.15)

# ==============================================================================
# 1. АВТОМАТИЧЕСКИЙ ПОИСК VCPKG (ДО project())
# ==============================================================================
# Если переменная CMAKE_TOOLCHAIN_FILE не была передана вручную,
# попробуем автоматически подтянуть vcpkg из переменной окружения VCPKG_ROOT
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE AND DEFINED ENV{VCPKG_ROOT})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

# Настройка триплета vcpkg для статической сборки Windows (задается до project())
if(WIN32)
    set(VCPKG_TARGET_TRIPLET "x64-windows-static" CACHE STRING "vcpkg target triplet")
endif()

# Политиками управляем до объявления проекта
cmake_policy(SET CMP0048 NEW) # Позволяет использовать project(VERSION)
cmake_policy(SET CMP0091 NEW) # Позволяет настраивать рантайм MSVC через CMAKE_MSVC_RUNTIME_LIBRARY

# ==============================================================================
# 2. ОПРЕДЕЛЕНИЕ ПРОЕКТА (Здесь загружается тулчейн vcpkg)
# ==============================================================================
project(tg_c_bridge 
    VERSION 1.0.0
    LANGUAGES C
)

# ==============================================================================
# 3. ПРОВЕРКА ПОДКЛЮЧЕНИЯ VCPKG (СТРОГО ПОСЛЕ project())
# ==============================================================================
# Теперь переменная VCPKG_TOOLCHAIN гарантированно инициализирована, если тулчейн отработал
if(NOT VCPKG_TOOLCHAIN)
    message(FATAL_ERROR 
        "\n======================================================================\n"
        "[FATAL ERROR] vcpkg is not detected! This project requires vcpkg.\n"
        "======================================================================\n"
        "Please follow these steps to build the project:\n"
        "1. Install vcpkg (https://github.com/microsoft/vcpkg)\n"
        "2. Define the VCPKG_ROOT environment variable pointing to your vcpkg folder\n"
        "   OR configure CMake manually by passing the toolchain file:\n\n"
        "   cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=<path_to_vcpkg>/scripts/buildsystems/vcpkg.cmake\n"
        "======================================================================\n"
    )
endif()

# Экспорт compile_commands.json для корректной работы LSP/clangd
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Настройка статического рантайма для MSVC (/MT или /MTd)
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Поиск статических библиотек OpenSSL
set(OPENSSL_USE_STATIC_LIBS TRUE)
set(LinkAsStatic TRUE) 

# ==============================================================================
# 4. ОРГАНИЗАЦИЯ КАТАЛОГОВ ВЫВОДА
# ==============================================================================
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ==============================================================================
# 5. ПОИСК ЗАВИСИМОСТЕЙ (vcpkg автоматически скачает их перед этим шагом)
# ==============================================================================
find_package(OpenSSL REQUIRED)
find_package(libwebsockets CONFIG REQUIRED)

# ==============================================================================
# 6. ОБЪЯВЛЕНИЕ ЦЕЛИ (TARGET)
# ==============================================================================
add_executable(tg_bridge)

target_sources(tg_bridge PRIVATE
    src/main.c
    src/mtproto.c
    src/mtproto_transport.c
    src/secret.c
    src/crash_handler.c
    src/mem.c
)

target_compile_features(tg_bridge PRIVATE c_std_11)

target_include_directories(tg_bridge PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ==============================================================================
# 7. КОНТРОЛЬ КАЧЕСТВА КОДА
# ==============================================================================
if(MSVC)
    target_compile_options(tg_bridge PRIVATE 
        /W4
        /WX
        /wd4100
    )
else()
    target_compile_options(tg_bridge PRIVATE 
        -Wall 
        -Wextra 
        -Wpedantic 
        -Werror
        -Wno-unused-parameter
    )
endif()

# ==============================================================================
# 8. ЛИНКОВКА БИБЛИОТЕК
# ==============================================================================
target_link_libraries(tg_bridge PRIVATE 
    OpenSSL::SSL
    OpenSSL::Crypto
    websockets
)

if(WIN32)
    target_link_libraries(tg_bridge PRIVATE 
        ws2_32 
        userenv 
        bcrypt 
        crypt32 
        iphlpapi
    )
    if(MSVC)
        target_link_options(tg_bridge PRIVATE "/SUBSYSTEM:CONSOLE")
    endif()
endif()

# ==============================================================================
# 9. ПРАВИЛА УСТАНОВКИ
# ==============================================================================
include(GNUInstallDirs)
install(TARGETS tg_bridge
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)