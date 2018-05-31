EXTERN HookEnabled:DB
EXTERN ArgTble:DB
EXTERN HookTable:DQ

EXTERN KiSystemCall64Ptr:DQ
EXTERN KiServiceCopyEndPtr:DQ

USERMD_STACK_GS = 10h
KERNEL_STACK_GS = 1A8h

MAX_SYSCALL_INDEX = 1000h

.CODE

; *********************************************************
;
; Determine if the specific syscall should be hooked
;
; if (SyscallHookEnabled[EAX & 0xFFF] == TRUE)
;     jmp KiSystemCall64_Emulate
; else (fall-through)
;     jmp KiSystemCall64
;
; *********************************************************


;这里是我们自定义的系统调用入口,R3层的函数调用R0层的函数会通过此入口跳转
;syscall指令执行后到这里
SyscallEntryPoint PROC
    ;cli                                    ; Disable interrupts
    swapgs                                  ; 将GS寄存器指向KPCR结构 (用户层指向TEB结构，用来标识线程的信息，而内核层的KPCR结构，用来标识处理器的信息)
    mov         gs:[USERMD_STACK_GS], rsp   ; 保存用户层的堆栈指针到KPCR的UserRsp成员处
    cmp         rax, MAX_SYSCALL_INDEX      ; Is the index larger than the array size?
    jge         KiSystemCall64              ;

    lea         rsp, offset HookEnabled     ; RSP = &SyscallHookEnabled
    cmp         byte ptr [rsp + rax], 0     ; Is hooking enabled for this index?
    jne         KiSystemCall64_Emulate      ; NE = index is hooked

SyscallEntryPoint ENDP

; *********************************************************
;
; Return to the original NTOSKRNL syscall handler
; (Restore all old registers first)
;
; *********************************************************
KiSystemCall64 PROC
	mov         rsp, gs:[USERMD_STACK_GS]   ; Usermode RSP
	swapgs                                  ; Switch to usermode GS
	jmp         [KiSystemCall64Ptr]         ; Jump back to the old syscall handler
KiSystemCall64 ENDP

; *********************************************************
;
; Emulated routine executed directly after a SYSCALL
; (See: MSR_LSTAR)
;
; *********************************************************
KiSystemCall64_Emulate PROC
    ; NOTE:
    ; First 2 lines are included in SyscallEntryPoint

    mov         rsp, gs:[KERNEL_STACK_GS]   ; 将堆栈寄存器设置为KPCR结构的RspBase成员，设置内核堆栈
    push        2Bh                         ; 在堆栈中保存ss选择子
    push        qword ptr gs:[10h]          ; 在堆栈中保存用户堆栈指针
    push        r11                         ; 在堆栈中保存原始的RFLAGES寄存器
    push        33h                         ; 在堆栈中保存64位的CS选择子
    push        rcx                         ; 在堆栈中保存返回地址
    mov         rcx, r10                    ; 将第一个参数的值赋值给rcx，因为在SysEntry指令中使用了rcx，所以在native api中，将rcx的值（也就是第一个参数）临时存放在了r10中

    sub         rsp, 8h                     ; 在堆栈中申请错误代码的空间
    push        rbp                         ; save standard register保存rbp寄存器

	;上面代码总共在堆栈中申请了38H个字节大小的空间,下面又申请了158H个字节的空间，总共190H字节大小的空间，正好对应一个_KTRAP_FRAME结构大小
	;上面在堆栈中申请的内存正好对应_KTRAP_FRAME结构的+158H到+190H的成员
    sub         rsp, 158h                   ; allocate fixed frame
  
	lea         rbp, [rsp+80h]              ; 设置rbp为_KTRAP_FRAME结构的TrapFrame成员
    mov         [rbp+0C0h], rbx             ; 保存非易失寄存器
    mov         [rbp+0C8h], rdi             ;
    mov         [rbp+0D0h], rsi             ;
    mov         byte ptr [rbp-55h], 2h      ; set service active
    mov         rbx, gs:[188h]              ; 保存当前线程对象的起始地址
    prefetchw   byte ptr [rbx+90h]          ; prefetch with write intent
    stmxcsr     dword ptr [rbp-54h]         ; save current MXCSR
    ldmxcsr     dword ptr gs:[180h]         ; set default MXCSR
    cmp         byte ptr [rbx+3], 0         ; 如果当前线程处于调试状态
    mov         word ptr [rbp+80h], 0       ; assume debug not enabled
    jz          KiSS05                      ; 不处于调试状态跳转至KiSS05，不在_KTRAP_FRAME中保存存储系统服务调用的头4个参数
    mov         [rbp-50h], rax              ; 处于调试状态，就保存参数的值
    mov         [rbp-48h], rcx              ;
    mov         [rbp-40h], rdx              ;
    mov         [rbp-38h], r8               ;
    mov         [rbp-30h], r9               ;

    int         3                           ; 
    align       10h

    KiSS05:
    ;sti                                    ; enable interrupts
    mov         [rbx+88h], rcx              ;将第一个参数保存到线程对象的FirstArgument成员
    mov         [rbx+80h], eax				;

KiSystemCall64_Emulate ENDP

;此函数5句都是为了找到函数在SSDT表中的实际索引
KiSystemServiceStart_Emulate PROC
    mov         [rbx+90h], rsp				;TrapFrame
    mov         edi, eax					;服务号，服务号的第13位（bit 12）表明是属于SSDT还是shadow SSDT。如果这一位置位，则结果是rdi为0x20，否则就为0
    shr         edi, 7						
    and         edi, 20h
    and         eax, 0FFFh
KiSystemServiceStart_Emulate ENDP

KiSystemServiceRepeat_Emulate PROC
    ; RAX = [IN ] syscall index
    ; RAX = [OUT] number of parameters
    ; R10 = [OUT] function address
    ; R11 = [I/O] trashed

    lea         r11, offset HookTable		;取SSDT表的地址
    mov         r10, qword ptr [r11 + rax * 8h]

    lea         r11, offset ArgTble			;取参数表的地址,存放了被HOOK函数参数的个数
    movzx       rax, byte ptr [r11 + rax]   ; RAX = paramter count

    jmp         [KiServiceCopyEndPtr]
KiSystemServiceRepeat_Emulate ENDP

END