.data
	wSystemCall DWORD 000h

.code
	HellsGate PROC
		nop
		mov wSystemCall, 000h
		nop
		mov wSystemCall, ecx
		nop
		ret
	HellsGate ENDP

	HellDescent PROC
		nop
		mov rax, rcx
		nop
		mov r10, rax
		nop
		mov eax, wSystemCall
		nop
		syscall
		ret
	HellDescent ENDP
end