cmake_minimum_required(VERSION 3.20)
project(GCAD VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- Compiler warnings: -Werror, zero tolerance (for our code) ---
# Global flags are strict but applied per-target to avoid poisoning vendored libs
set(GCAD_CXX_FLAGS_MSVC /W4 /WX /permissive- /Zc:__cplusplus /utf-8)
set(GCAD_CXX_FLAGS_GCC -Wall -Wextra -Wpedantic -Werror -Wno-unused-parameter)
if(MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

# --- Platform detection ---
if(WIN32)
    add_compile_definitions(GCAD_PLATFORM_WINDOWS=1)
    set(GCAD_PLATFORM "windows")
else()
    add_compile_definitions(GCAD_PLATFORM_LINUX=1)
    set(GCAD_PLATFORM "linux")
endif()

# --- Dear ImGui via FetchContent ---
include(FetchContent)

FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        v1.91.8-docking
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(imgui)

set(IMGUI_DIR ${imgui_SOURCE_DIR})
set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
)

if(WIN32)
    list(APPEND IMGUI_SOURCES
        ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
        ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp
    )
else()
    FetchContent_Declare(
        glfw
        GIT_REPOSITORY https://github.com/glfw/glfw.git
        GIT_TAG        3.4
        GIT_SHALLOW    TRUE
    )
    set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(glfw)

    list(APPEND IMGUI_SOURCES
        ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
        ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
    )
endif()

add_library(imgui_lib STATIC ${IMGUI_SOURCES})
target_include_directories(imgui_lib PUBLIC ${IMGUI_DIR} ${IMGUI_DIR}/backends)
# Suppress strict warnings for vendored imgui
if(NOT MSVC)
    target_compile_options(imgui_lib PRIVATE -w)
endif()
if(WIN32)
    target_link_libraries(imgui_lib PUBLIC gdi32 dwmapi d3dcompiler)
else()
    target_link_libraries(imgui_lib PUBLIC glfw GL)
endif()

# --- GCAD engine library (all non-UI, non-main sources) ---
set(GCAD_ENGINE_SOURCES
    src/common.cpp
    src/engine_manager.cpp
    src/engines/pmsr_engine.cpp
    src/engines/etg_ri_engine.cpp
    src/engines/arhs_engine.cpp
    src/engines/zrgp_engine.cpp
    src/engines/self_defense.cpp
    src/engines/syscall_guard.cpp
    src/engines/kernel_monitor_engine.cpp
    src/scanner/signature_db.cpp
    src/scanner/deep_scanner.cpp
    src/scanner/heuristic_rules.cpp
    src/security/telemetry_bus.cpp
    src/security/policy.cpp
    src/security/correlation_engine.cpp
    src/security/security_pipeline.cpp
    src/security/artifact_trust_engine.cpp
    src/security/process_behavior_engine.cpp
    src/security/etw_kernel_process_engine.cpp
    src/security/legacy_adapter.cpp
    src/security/policy_store.cpp
    src/security/quarantine_executor.cpp
    src/security/asn1.cpp
    src/security/x509.cpp
    src/security/bignum.cpp
    src/security/rsa_pkcs1.cpp
    src/security/pkcs7.cpp
    src/security/pe_authenticode_hash.cpp
    src/security/trust_anchors.cpp
    src/security/authenticode.cpp
    src/platform/platform_compat.cpp
    src/platform/win32_etw.cpp
    src/platform/linux_ebpf.cpp
)

add_library(gcad_engine STATIC ${GCAD_ENGINE_SOURCES})
target_include_directories(gcad_engine PUBLIC include)
if(MSVC)
    target_compile_options(gcad_engine PRIVATE ${GCAD_CXX_FLAGS_MSVC})
else()
    target_compile_options(gcad_engine PRIVATE ${GCAD_CXX_FLAGS_GCC})
endif()

if(WIN32)
    target_link_libraries(gcad_engine PUBLIC ws2_32 psapi iphlpapi)
else()
    target_link_libraries(gcad_engine PUBLIC pthread)
endif()

# --- GCAD UI library ---
set(GCAD_UI_SOURCES
    src/ui/theme.cpp
    src/ui/ui_manager.cpp
    src/ui/views/dashboard_view.cpp
    src/ui/views/scan_view.cpp
    src/ui/views/network_view.cpp
    src/ui/views/quarantine_view.cpp
    src/ui/views/forensics_view.cpp
    src/ui/views/settings_view.cpp
)

add_library(gcad_ui STATIC ${GCAD_UI_SOURCES})
target_include_directories(gcad_ui PUBLIC include)
target_link_libraries(gcad_ui PUBLIC gcad_engine imgui_lib)
if(MSVC)
    target_compile_options(gcad_ui PRIVATE ${GCAD_CXX_FLAGS_MSVC})
else()
    target_compile_options(gcad_ui PRIVATE ${GCAD_CXX_FLAGS_GCC})
endif()

# --- Main executable ---
add_executable(gcad src/main.cpp)
target_link_libraries(gcad PRIVATE gcad_ui gcad_engine imgui_lib)
if(MSVC)
    target_compile_options(gcad PRIVATE ${GCAD_CXX_FLAGS_MSVC})
else()
    target_compile_options(gcad PRIVATE ${GCAD_CXX_FLAGS_GCC})
endif()

if(WIN32)
    target_link_libraries(gcad PRIVATE d3d11 dxgi)
    set_target_properties(gcad PROPERTIES
        WIN32_EXECUTABLE $<IF:$<CONFIG:Release>,TRUE,FALSE>
    )
endif()

set_target_properties(gcad PROPERTIES
    OUTPUT_NAME "gcad"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# --- Tests ---
option(GCAD_BUILD_TESTS "Build unit tests" ON)
if(GCAD_BUILD_TESTS)
    enable_testing()

    add_executable(gcad_tests
        tests/test_main.cpp
        tests/test_pmsr.cpp
        tests/test_etg_ri.cpp
        tests/test_arhs.cpp
        tests/test_zrgp.cpp
        tests/test_self_defense.cpp
        tests/test_forensic_graph.cpp
        tests/test_security_pipeline.cpp
        tests/test_artifact_trust.cpp
        tests/test_process_behavior.cpp
        tests/test_etw_kernel_process.cpp
        tests/test_legacy_adapter.cpp
        tests/test_policy_store.cpp
        tests/test_quarantine_executor.cpp
        tests/test_deep_scanner.cpp
        tests/test_asn1.cpp
        tests/test_x509.cpp
        tests/test_bignum.cpp
        tests/test_rsa_pkcs1.cpp
        tests/test_pkcs7.cpp
        tests/test_pe_authenticode_hash.cpp
        tests/test_trust_anchors.cpp
        tests/test_authenticode.cpp
        tests/fuzz_packet_parser.cpp
    )
    target_include_directories(gcad_tests PRIVATE include)
    target_link_libraries(gcad_tests PRIVATE gcad_engine)

    if(WIN32)
        target_link_libraries(gcad_tests PRIVATE ws2_32 psapi iphlpapi)
    else()
        target_link_libraries(gcad_tests PRIVATE pthread)
    endif()

    add_test(NAME gcad_unit_tests COMMAND gcad_tests)
endif()
