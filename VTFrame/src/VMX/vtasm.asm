extern VmxpExitHandler:proc
extern RtlCaptureContext:proc

.CODE

;win10不支持RtlCaptureContext，因为win10对其恢复函数RtlCaptureContext进行了改动，导致某些情况下，无法执行到vmresume
VmxVMEntry PROC
    push    rcx                 ; save RCX, as we will need to orverride it
    lea     rcx, [rsp+8h]       ; store the context in the stack, bias for
                                ; the return address and the push we just did.
    call    RtlCaptureContext   ; save the current register state.
                                ; note that this is a specially written function
                                ; which has the following key characteristics:
                                ;   1) it does not taint the value of RCX
                                ;   2) it does not spill any registers, nor
                                ;      expect home space to be allocated for it

    jmp     VmxpExitHandler     ; jump to the C code handler. we assume that it
                                ; compiled with optimizations and does not use
                                ; home space, which is true of release builds.
VmxVMEntry ENDP

; 宏定义push所有通用寄存器
PUSHAQ MACRO
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    -1      ; 占个位，这里的rsp肯定不是Guest的Rsp了
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
ENDM


; 宏定义pop所有通用寄存器
POPAQ MACRO
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8    ; 不pop到rsp，因为AsmVmmEntryPoint前后有堆栈平衡操作,最终rsp还是原本的GuestRsp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
ENDM

;换个HyperPlatform的写法,或者自己手动创建一个CONTENT结构
AsmVmmEntryPoint PROC

	;保存一下通用寄存器
    PUSHAQ                  ; -8 * 16

	;rcx就是通用寄存器结构MYCONTEXT结构的指针了，传到VmxpExitHandler
    mov rcx, rsp

    ; 保存一下易失寄存器xmm0-xmm5
    sub rsp, 60h
    movaps xmmword ptr [rsp +  0h], xmm0
    movaps xmmword ptr [rsp + 10h], xmm1
    movaps xmmword ptr [rsp + 20h], xmm2
    movaps xmmword ptr [rsp + 30h], xmm3
    movaps xmmword ptr [rsp + 40h], xmm4
    movaps xmmword ptr [rsp + 50h], xmm5

	; 预留一下堆栈空间
    sub rsp, 20h
    call     VmxpExitHandler
    add rsp, 20h

    movaps xmm0, xmmword ptr [rsp +  0h]
    movaps xmm1, xmmword ptr [rsp + 10h]
    movaps xmm2, xmmword ptr [rsp + 20h]
    movaps xmm3, xmmword ptr [rsp + 30h]
    movaps xmm4, xmmword ptr [rsp + 40h]
    movaps xmm5, xmmword ptr [rsp + 50h]
    add rsp, 60h

    POPAQ

	; 执行到这里堆栈和寄存器都已经和发生VM-Extit时的一样了
    vmresume

	; 到这里就表示vmresume失败了
    int 3
AsmVmmEntryPoint ENDP

VmxVMCleanup PROC
    mov     ds, cx              ; set DS to parameter 1
    mov     es, cx              ; set ES to parameter 1
    mov     fs, dx              ; set FS to parameter 2
    ret                         ; return
VmxVMCleanup ENDP

VmxpResume PROC 
    vmresume
    ret
VmxpResume ENDP

__vmx_vmcall PROC
    vmcall
    ret
__vmx_vmcall ENDP

__invept PROC
    invept rcx, OWORD PTR [rdx]
    ret
__invept ENDP

__invvpid PROC
    invvpid rcx, OWORD PTR [rdx]
    ret
__invvpid ENDP

AsmWriteCR2 PROC
    mov cr2, rcx
    ret
AsmWriteCR2 ENDP

PURGE PUSHAQ
PURGE POPAQ

END