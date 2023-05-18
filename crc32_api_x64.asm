;-----------------------------------------------------------------------------;
; Author: Ege Balcı (egebalci[at]pm[dot]me)
; Version: 1.1 (29 April 2023)
; Architecture: x64
; Size: 192 bytes
;-----------------------------------------------------------------------------;

[BITS 64]

; Windows x64 calling convention:
; http://msdn.microsoft.com/en-us/library/9b372w95.aspx

; Input: The CRC32 hash of the module and function name.
; Output: The address of the function will be in RAX.
; Clobbers: R10
; Un-Clobbered: RCX, RDX, R8, R9, RBX, RSI, RDI, RBP, R12, R13, R14, R15.
; Note: This function assumes the direction flag has allready been cleared via a CLD instruction.

%define CRC32_SEED 0x00

api_call:
  push r9                  ; Save R9
  push r8                  ; Save R8
  push rdx                 ; Save RDX
  push rcx                 ; Save RCX
  push rsi                 ; Save RSI
  xor rdx, rdx             ; Zero rdx
  mov rdx, [gs:rdx+96]     ; Get a pointer to the PEB
  mov rdx, [rdx+24]        ; Get PEB->Ldr
  mov rdx, [rdx+32]        ; Get the first module from the InMemoryOrder module list
next_mod:                  ;
  mov rsi, [rdx+80]        ; Get pointer to modules name (unicode string)
  movzx rcx, word [rdx+74] ; Set rcx to the length we want to check 
  xor r9, r9               ; Clear r9 which will store the hash of the module name
  mov r9, CRC32_SEED       ; Set the initial CRC32 seed value
loop_modname:              ;
  xor rax, rax             ; Clear RAX
  lodsb                    ; Read in the next byte of the name
  cmp al, 'a'              ; Some versions of Windows use lower case module names
  jl not_lowercase         ;
  sub al, 0x20             ; If so normalise to uppercase
not_lowercase:             ;
  crc32 r9d,al             ; Calculate CRC32 of module name
  loop loop_modname        ; Loop untill we have read enough
  ; We now have the module hash computed
  push rdx                 ; Save the current position in the module list for later
  push r9                  ; Save the current module hash for later
  ; Proceed to itterate the export address table, 
  mov rdx, [rdx+32]        ; Get this modules base address
  mov eax, dword [rdx+60]  ; Get PE header
  add rax, rdx             ; Add the modules base address
  cmp word [rax+24], 0x020B ; is this module actually a PE64 executable? 
  ; this test case covers when running on wow64 but in a native x64 context via nativex64.asm and 
  ; their may be a PE32 module present in the PEB's module list, (typicaly the main module).
  ; as we are using the win64 PEB ([gs:96]) we wont see the wow64 modules present in the win32 PEB ([fs:48])
  jne get_next_mod1         ; if not, proceed to the next module
  mov eax, dword [rax+136] ; Get export tables RVA
  test rax, rax            ; Test if no export address table is present
  jz get_next_mod1         ; If no EAT present, process the next module
  add rax, rdx             ; Add the modules base address
  push rax                 ; Save the current modules EAT
  mov ecx, dword [rax+24]  ; Get the number of function names  
  mov r8d, dword [rax+32]  ; Get the rva of the function names
  add r8, rdx              ; Add the modules base address
  ; Computing the module hash + function hash
get_next_func:             ;
  jrcxz get_next_mod       ; When we reach the start of the EAT (we search backwards), process the next module
  mov r9, [rsp+8]          ; Reset the current module hash
  dec rcx                  ; Decrement the function name counter
  mov esi, dword [r8+rcx*4]; Get rva of next module name
  add rsi, rdx             ; Add the modules base address
  ; And compare it to the one we want
loop_funcname:             ;
  xor rax, rax             ; Clear RAX
  lodsb                    ; Read in the next byte of the ASCII function name
  crc32 r9d,al             ; Calculate CRC32 of function name
  cmp al, ah               ; Compare AL (the next byte from the name) to AH (null)
  jne loop_funcname        ; If we have not reached the null terminator, continue
  cmp r9d, r10d            ; Compare the hash to the one we are searchnig for 
  jnz get_next_func        ; Go compute the next function hash if we have not found it
  ; If found, fix up stack, call the function and then value else compute the next one...
  pop rax                  ; Restore the current modules EAT
  mov r8d, dword [rax+36]  ; Get the ordinal table rva      
  add r8, rdx              ; Add the modules base address
  mov cx, [r8+2*rcx]       ; Get the desired functions ordinal
  mov r8d, dword [rax+28]  ; Get the function addresses table rva  
  add r8, rdx              ; Add the modules base address
  mov eax, dword [r8+4*rcx]; Get the desired functions RVA
  add rax, rdx             ; Add the modules base address to get the functions actual VA
  ; We now fix up the stack and perform the call to the drsired function...
finish:
  pop r8                   ; Clear off the current modules hash
  pop r8                   ; Clear off the current position in the module list
  pop rsi                  ; Restore RSI
  pop rcx                  ; Restore RCX
  pop rdx                  ; Restore RDX
  pop r8                   ; Restore R8
  pop r9                   ; Restore R9
  ret                      ; Return to caller with the function address inside RAX
  ; We now automagically return to the correct caller...
get_next_mod:              ;
  pop rax                  ; Pop off the current (now the previous) modules EAT
get_next_mod1:             ;
  pop r9                   ; Pop off the current (now the previous) modules hash
  pop rdx                  ; Restore our position in the module list
  mov rdx, [rdx]           ; Get the next module
  jmp next_mod             ; Process this module
