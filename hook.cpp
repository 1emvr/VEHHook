
LONG WINAPI ExceptionHandler(_EXCEPTION_POINTERS *exception) {

    int32_t retval = EXCEPTION_CONTINUE_SEARCH;

    // breakpoint
    if (exception->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        std::map<FARPROC, BYTE>::iterator fn_index;

        for (fn_index = g_hooks.begin(); fn_index != g_hooks.end(); ++fn_index) {
            if (exception->ContextRecord->Rip == (uintptr_t) fn_index->first) {

                // unhook and set the trap flag
                WriteProcessMemory((HANDLE)(ULONG_PTR) -1, fn_index->first, &fn_index->second, 1, NULL);
                exception->ContextRecord->EFlags |= 0x100;

                // TODO: dispatch analysis by type??

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
                WriteProcessMemory((HANDLE)(ULONG_PTR) -1, fn_index->first, &bp_opcode, 1, NULL);

                exception->ContextRecord->EFlags &= ~0x100;
                retval = EXCEPTION_CONTINUE_EXECUTION;

                break;
            }
        }
    }
        
    return retval;
}

BOOL HookFunction(const char *module_name, const char *func_name) {

    uint8_t bp_opcode = 0xCC;
    // only hook if veh already set

    if (g_is_veh_set == false) {
        LOG_ERROR("hook_function : cannot hook while g_is_veh_set is false");
        return false;
    }
        
    HMODULE module_base = GetModuleHandleA(module_name);
    if (!module_base) {
        LOG_ERROR("hook_function : GetModuleHandleA failed to resolve %s", module_name);
        return false;
    }

    FARPROC func_base = GetProcAddress(module_base, func_name);
    if (!func_base) {
        LOG_ERROR("hook_function : GetProcAddress failed to resolve %s!%s", module_name, func_name);
        return false;
    }

    // TODO: save byte and hooked function in a hashmap to unhook later
    bool success = WriteProcessMemory((HANDLE)(ULONG_PTR)-1, func_base, &bp_opcode, 1, nullptr);

    // TODO: append std::map<FARPROC, BYTE> g_hooks list
    return success;
}







































