"use strict";

const DEBUG = false;
const log  = msg => host.diagnostics.debugLog(`${msg}\n`);
var debug;
if (DEBUG) {
    debug  = msg => log(msg);
}
else {
    debug  = msg => null;
}
const execute = cmd => host.namespace.Debugger.Utility.Control.ExecuteCommand(cmd);


function initializeScript()
{
    
    return [new host.apiVersionSupport(1, 7)];
}

function invokeScript()
{
    // execute('bp ntdll!NtAllocateVirtualMemory "dx @$scriptContents.OnBreakNtAllocateVirtualMemory()"');
    
    // execute('bp /w "@$scriptContents.BreakCondTest_NtAllocateVirtualMemory()" ntdll!NtAllocateVirtualMemory');
    
    execute('bp ntdll!NtAllocateVirtualMemory "dx @$scriptContents.SetBreakCondToT0_NtAllocateVirtualMemory(); r @$t0; .if (@$t0 != 0) {.echo \'Will break.\';} .else {.echo \'Will g.\';g;} " ');

    log("Breakpoint is set up. Run g.");
}

function uninitializeScript()
{
    execute('bc *');
}

function read_register(reg_name) {
    var cmd = `r ${reg_name}`;
    var output = execute(cmd).First();
    debug('cmd:'+cmd+'=>'+output);
    output = '0x'+output.split('=')[1];
    var ret = host.parseInt64(output);
    debug('ret='+ret.toString());
    return ret;
}

function read_addr(addr, d_posfix) {
    var cmd = `d${d_posfix} ${addr} L1`;
    var output = execute(cmd).First();
    debug('cmd:'+cmd+'=>'+output);
    output = '0x'+output.split(' ')[2].split('`').join('');
    var ret = host.parseInt64(output);
    debug('ret='+ret.toString());
    return ret;
}

function read_stack_param(idx) {
    if (!is_32bitcpu()) {
        var sp = read_register("rsp");
        debug(sp);
        var param_addr = sp.add(host.Int64(8)); // skip the return address
        param_addr = param_addr.add(host.Int64(8*idx))
        debug('param_addr='+param_addr.toString());

        return read_addr(param_addr, 'p');
    }
    else {
        throw new Error("Not yet implemented.");
    }
}

function get_x64_call_param_0_based(param_no) {
    if (param_no < 0) {
        throw new Error("param_no < 0");
    }

    if (param_no == 0) {
        return read_register("rcx");
    }
    else if (param_no == 1) {
        return read_register("rdx");
    }
    else if (param_no == 2) {
        return read_register("r8");
    }
    else if (param_no == 3) {
        return read_register("r9");
    }
    else {
        return read_stack_param(param_no);
    }
}

function is_32bitcpu() {
    var cmd = "dx Debugger.State.DebuggerInformation.Bitness";
    var output = execute(cmd).First().split(':')[1].trim();
    debug(`cmd:${cmd}=>${output}`);
    if (output=="64") {
        return false;
    }
    else {
        return true;
    }
}

function convert_int64_to_type(raw_int64, t) {
    /*
    t can be:
        "HANDLE" 
        "P_VOID" 
        "P_P_VOID"
        "P_ULONG"
        "P_SIZET"
        "ULONG"
        "SIZET"
    */
    if (t == "HANDLE" || t == "SIZET" || t.startsWith("P_")) {
        return raw_int64;
    }
    else if (t == "ULONG") {
        return raw_int64.bitwiseAnd(host.Int64(0xffffffff));
    }
    else {
        throw new Error(`type ${t} not supported.`);
    }
}

function get_x64_call_params(signature_dict) {
    var ret = {}
    for (var i = 0; i < signature_dict.length; i++) {
        var t = signature_dict[i][0];
        var name = signature_dict[i][1];

        var raw_int64 = get_x64_call_param_0_based(i);
        ret[name] = convert_int64_to_type(raw_int64, t);
    }
    return ret;
}

function dereference(addr, t) {
    if (!t.startsWith("P_")) {
        throw new Error('not a P_* type.');
    }
    var n_t = t.substring(2);
    debug(`n_t=${n_t}`);
    return convert_int64_to_type(read_addr(addr, 'p'), n_t);
}

function get_pagesize() {
    var cmd = "dx Debugger.State.PseudoRegisters.General.pagesize";
    var output = execute(cmd).First();
    debug(`cmd:${cmd}=>${output}`);
    var match = output.match(/\S+\s*:\s*(\S+)/)[1];
    debug(`match=${match}`);
    var pagesize = host.parseInt64(match);
    debug(`pagesize=${pagesize}`);
    return pagesize;
}

function is_X(int64_protectionbits) {
    const PAGE_EXECUTE = host.Int64(0x10);
    const PAGE_EXECUTE_READ = host.Int64(0x20);
    const PAGE_EXECUTE_READWRITE = host.Int64(0x40);
    const PAGE_EXECUTE_WRITECOPY = host.Int64(0x80);

    if (int64_protectionbits.bitwiseAnd(PAGE_EXECUTE).compareTo(host.Int64(0)) != 0) {
        debug('PAGE_EXECUTE');
        return true;
    }
    if (int64_protectionbits.bitwiseAnd(PAGE_EXECUTE_READ).compareTo(host.Int64(0)) != 0) {
        debug('PAGE_EXECUTE_READ');
        return true;
    }
    if (int64_protectionbits.bitwiseAnd(PAGE_EXECUTE_READWRITE).compareTo(host.Int64(0)) != 0) {
        debug('PAGE_EXECUTE_READWRITE');
        return true;
    }
    if (int64_protectionbits.bitwiseAnd(PAGE_EXECUTE_WRITECOPY).compareTo(host.Int64(0)) != 0) {
        debug('PAGE_EXECUTE_WRITECOPY');
        return true;
    }
    return false;
}

// NtAllocateVirtualMemory(
// _In_ HANDLE ProcessHandle,
// PVOID *BaseAddress,
// _In_ ULONG_PTR ZeroBits,
// _Inout_ PSIZE_T RegionSize,
// _In_ ULONG AllocationType,
// _In_ ULONG Protect
// );
function SetBreakCondToT0_NtAllocateVirtualMemory()
{
    log("---\nBreakCondTest_NtAllocateVirtualMemory");

    var params_dict = get_x64_call_params([
        ['HANDLE', 'ProcessHandle'],
        ['P_P_VOID', 'pBaseAddress'],
        ['P_ULONG', 'pZeroBits'],
        ['P_SIZET', 'pRegionSize'],
        ['ULONG', 'AllocationType'],
        ['ULONG', 'Protect'],
    ]);

    for (var param_name in params_dict) {
        log(`${param_name}=${params_dict[param_name].toString()}`);
    }
    log(`RegionSize=${dereference(params_dict["pRegionSize"], "P_SIZET")}`);

    log(`pagesize=${get_pagesize()}`);

    var should_break = true;

    if (dereference(params_dict["pRegionSize"], "P_SIZET").compareTo(get_pagesize()) > 0) {
        log('Will gc. RegionSize > pagesize');
        should_break = false;
    }
    else if (!is_X(params_dict['Protect'])) {
        log('Will gc. No XM is involved.');
        should_break = false;
    }
    else {
        log(`BaseAddress=${dereference(params_dict["pBaseAddress"], "P_P_VOID")}`);

        execute('pt');

        log(`BaseAddress=${dereference(params_dict["pBaseAddress"], "P_P_VOID")}`);

        if (dereference(params_dict["pBaseAddress"], "P_P_VOID").compareTo(host.parseInt64("0x7ff000000000")) > 0) {
            log('Will break. BaseAddress > 0x7ff000000000');
            should_break = true;
        }
        else {
            log('Will gc. BaseAddress <= 0x7ff000000000');
            should_break = false;
        }
    }

    if (should_break) {
        execute('r @$t0 = 1');
    }
    else {
        execute('r @$t0 = 0');
    }
}
