# Conditional-Windbg-Breakpoint-via-JavaScript

This is a project that shows in WinDbg how complex conditions for breaking an API call can be specified in JavaScript.

## Problem Statement
We want to break the following API call
```
NTSTATUS NtAllocateVirtualMemory(
  [in]      HANDLE    ProcessHandle,
  [in, out] PVOID     *BaseAddress,
  [in]      ULONG_PTR ZeroBits,
  [in, out] PSIZE_T   RegionSize,
  [in]      ULONG     AllocationType,
  [in]      ULONG     Protect
);
```
when 
1. (*RegionSize) <= 1 page
2. Protect has executable bit set.
3. (*pBaseAddress) > 0x7ff000000000

The above may be difficult to be implemented as a `bp` command (as in `bp /w "localVariable == 4" mymodule!myfunction`) because:
1. Private symbols are not avaiable for `ntdll.dll` (if you are not working at Microsoft). So the function's arguments can not be easily accessed: you need to know the calling convention so you know where to look for the arguments, and you need to manually interpret the arguments' raw binaries.
2. Some data are just not available at the function's entry point. For example, `BaseAddress` contains garbage value at the function's entry point because memory allocation is not done yet. So what we should do is to record `BaseAddress` at the function's entry point, and dereference it to get the value of interest before the function returns.

This project shows a way to achieve the above with JavaScript.

## Prerequisite
You have followed [the official WinDbg JavaScript documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/javascript-debugger-scripting#scriptrun) and have succefully run `.scriptrun C:\WinDbg\Scripts\helloWorld.js`.

## Solution
The solution is in [`main.js`](/main.js). Here is a breakdown of it.
1. First, when the script is invoked, at this line (TODO), it sets a break point at the target function:
```
bp ntdll!NtAllocateVirtualMemory ...
```
and when the breakpoint is hit, the following command is executed:
```
"dx
  @$scriptContents.SetBreakCondToT0_NtAllocateVirtualMemory();
  r @$t0;
  .if (@$t0 != 0) {.echo \'Will break.\';}
  .else {.echo \'Will g.\';g;} ";
```
which calls a JavaScript function, prints the pseudo-register `$t0`, and if `$t0` is non-zero, it breaks, else it continues.

2. Let's move focus to `SetBreakCondToT0_NtAllocateVirtualMemory`.

WHen it's called, ...
