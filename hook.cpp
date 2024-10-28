#include <windows.h>
#include <mutex>
#include <map>

static bool g_veh_is_set = false;

static std::map<FARPROC, BYTE> g_hooks{};
static std::mutex g_hooks_mux;

LONG WINAPI ExceptionHandler(_EXCEPTION_POINTERS *exception) {

    std::lock_guard<std::mutex> lock(g_hooks_mux);
    int32_t retval = EXCEPTION_CONTINUE_SEARCH;

    if (exception->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        std::map<FARPROC, BYTE>::iterator fn_index;

        for (fn_index = g_hooks.begin(); fn_index != g_hooks.end(); ++fn_index) {
            if (exception->ContextRecord->Rip == (uintptr_t) fn_index->first) {

                WriteProcessMemory((HANDLE)(ULONG_PTR) -1, fn_index->first, &fn_index->second, 1, nullptr);
                exception->ContextRecord->EFlags |= 0x100;

                // TODO: dispatch analysis by type??
                // Will this be a consumer?

                retval = EXCEPTION_CONTINUE_EXECUTION;
                break;
            }
        }
    }
    // trap flag
    else if (exception->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        std::map<FARPROC, BYTE>::iterator fn_index;

        for (fn_index = g_hooks.begin(); fn_index != g_hooks.end(); ++fn_index) {
            if ((exception->ContextRecord->Rip - (uintptr_t) fn_index->first) < 8) {

                uint8_t bp_opcode = 0xCC;
                WriteProcessMemory((HANDLE)(ULONG_PTR) -1, fn_index->first, &bp_opcode, 1, nullptr);

                exception->ContextRecord->EFlags &= ~0x100;
                retval = EXCEPTION_CONTINUE_EXECUTION;

                break;
            }
        }
    }
        
    return retval;
}

BOOL HookFunction(const char *module_name, const char *func_name) {

    bool success = false;
    uint8_t bp_opcode = 0xcc;

    // set lock 
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







































