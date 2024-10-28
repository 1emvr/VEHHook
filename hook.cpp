#include <windows.h>
#include <cstdint>
#include <mutex>
#include <map>

static uint8_t bp_opcode = 0xcc;
static bool g_veh_is_set = false;

static std::map<FARPROC, BYTE> g_hooks{};
static std::mutex g_hooks_mux;

// TODO: error logging

LONG WINAPI ExceptionHandler(_EXCEPTION_POINTERS *exception) {

    std::lock_guard<std::mutex> lock(g_hooks_mux);
    int32_t retval = EXCEPTION_CONTINUE_SEARCH;

    // breakpoint (first)
    if (exception->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        std::map<FARPROC, BYTE>::iterator g_hook_idx;

        for (g_hook_idx = g_hooks.begin(); g_hook_idx != g_hooks.end(); ++g_hook_idx) {
            if (exception->ContextRecord->Rip == (uintptr_t) g_hook_idx->first) {

                // Implying that we are only able to hook ourselves
                WriteProcessMemory((HANDLE)(ULONG_PTR) -1, g_hook_idx->first, &g_hook_idx->second, 1, nullptr);
                exception->ContextRecord->EFlags |= 0x100;

                // TODO: dispatch analysis by type??
                // Will this be a consumer?

                retval = EXCEPTION_CONTINUE_EXECUTION;
                break;
            }
        }
    }
    // trap flag (second)
    else if (exception->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        std::map<FARPROC, BYTE>::iterator g_hook_idx;

        for (g_hook_idx = g_hooks.begin(); g_hook_idx != g_hooks.end(); ++g_hook_idx) {
            if ((exception->ContextRecord->Rip - (uintptr_t) g_hook_idx->first) < 8) {

                WriteProcessMemory((HANDLE)(ULONG_PTR) -1, g_hook_idx->first, &bp_opcode, 1, nullptr);
                exception->ContextRecord->EFlags &= ~0x100;
                retval = EXCEPTION_CONTINUE_EXECUTION;

                break;
            }
        }
    }
        
    return retval;
}

BOOL HookFunction(const char *module_name, const char *func_name) {

    // set lock 
    bool success = false;
    std::lock_guard<std::mutex> lock(g_hooks_mux);

    // only hook if veh already set
    if (g_veh_is_set == false) {
        // LOG_ERROR("hook_function : cannot hook while g_is_veh_set is false");
        goto defer;
    }
        
    HMODULE module_base = GetModuleHandleA(module_name);
    if (!module_base) {
        // LOG_ERROR("hook_function : GetModuleHandleA failed to resolve %s", module_name);
        goto defer;
    }

    FARPROC func_base = GetProcAddress(module_base, func_name);
    if (!func_base) {
        // LOG_ERROR("hook_function : GetProcAddress failed to resolve %s!%s", module_name, func_name);
        goto defer;
    }

    // save byte and hooked function in g_hooks
    g_hooks.insert( {func_base, ((uint8_t*) func_base)[0]} );
    success = WriteProcessMemory((HANDLE)(ULONG_PTR)-1, func_base, &bp_opcode, 1, nullptr);

 defer:
    return success;
}







































