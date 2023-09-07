BITS 64

SECTION .text

global main

main:
  ; save context
  push rax
  push rcx
  push rdx
  push rsi
  push rdi
  push r11

  ; Injecting "You have been pwned !!"
  
  mov r10, 0x000a21212064656e
  mov r9, 0x7770206e65656220
  mov r8, 0x6576616820756f59
  push r10
  push r9
  push r8
  mov rdx, 23
  mov rsi, rsp
  mov rdi, 1  
  mov rax, 1 
  syscall 

  ; load context
  pop r11
  pop r11
  pop r11
  pop r11 
  pop rdi
  pop rsi
  pop rdx
  pop rcx
  pop rax

  ; return
