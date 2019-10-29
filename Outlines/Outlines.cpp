#include "Outlines.h"
#include "Process.h"
#include <winternl.h>

#pragma comment(lib, "ntdll")

/*
Outlines ESP hack for Overwatch
WTFPL

One thing to mention: apparently SetThreadContext under x64 does *not* set volatile registers, but RtlRestoreContext does,
however: RtlRestoreContext does *not* set debug registers, but SetThreadContext can. Therefore, it might look a bit weird
what I'm doing there at first glance.

Since somebody asked me about how to change the color of outlines:
The r8 register in veh CONTEXT structure holds the DWORD for color, so you'd have to just modify the assembly below.
*/

namespace outlines {

	// exception routine (will be called once dr0 is triggered)
	static uint8_t veh[] = {
		0x48, 0x8b, 0x11, // mov rdx, [rcx]
		0x48, 0xb8, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // movabs rax, 0x4141414141414141 (will be outlines_va)
		0x48, 0x89, 0x44, 0x24, 0x08, // mov [rsp + 0x8], rax
		0x48, 0x8b, 0x44, 0x24, 0x08, // mov rax, [rsp + 0x8]
		0x48, 0x3b, 0x42, 0x10, // cmp rax, [rdx + 0x10]
		0x75, 0x2a, // jne 0x47
		0x48, 0x8b, 0x41, 0x08, // mov rax, [rcx + 0x8]
		0x48, 0x83, 0xb8, 0xc0, 0x00, 0x00, 0x00, 0x00, // cmp [rax + 0xc0], 0x0
		0x74, 0x1c, // je 0x47
		0x48, 0xc7, 0x80, 0x88, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, // mov [rax + 0x88], 0xc0
		0x48, 0x8b, 0x41, 0x08, // mov rax, [rcx + 0x8]
		0x81, 0x48, 0x44, 0x00, 0x00, 0x01, 0x00, // or DWORD PTR[rax + 0x44], 0x10000 => set rf flag in EFLAGS
		0xb8, 0xff, 0xff, 0xff, 0xff, // mov eax, 0xffffffff
		0xc3, // ret
		0x33,0xc0, // xor eax,eax
		0xc3, // ret
	};

	// registers our exception routine
	static uint8_t add_veh[] = { 
		0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // movabs rax, 0xcccccccccccccccc
		0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // movabs rcx, 0xcccccccccccccccc
		0x48, 0xBA, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // movabs rdx, 0xcccccccccccccccc
		0xFF, 0xD0 // call rax
	};
	
	// restore context
	static uint8_t restore_context[] = {
		0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // movabs rax, 0xcccccccccccccccc
		0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // movabs rcx, 0xcccccccccccccccc
		0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00, // mov rdx, 0x0
		0xFF, 0xD0 // call rax
	};

	static constexpr auto size_veh = sizeof(veh);
	static constexpr auto size_add_veh = sizeof(add_veh);
	static constexpr auto size_resore_context = sizeof(restore_context);
	static constexpr auto size_shellcode = size_veh + size_add_veh + size_resore_context + 0x10; // extra 0x10 for alignment
	static constexpr auto size_context_aligned = size_shellcode & ~0xf; // make sure the context struct is 16 uint8_t aligned

	bool activate() {

		// find call to outlines function and calculate based on relative offset
		auto outlines_va = process::aob_scan("\x44\x8D\x49\x83\x49\x8B\x4F\x20", "xxxxxxxx");

		if(!outlines_va)
			return false;

		outlines_va += 9;
		auto rel = process::read<int32_t>(outlines_va);
		outlines_va += rel + 4;

		// suspend process for retrieving context
		process::suspend();
		
		// allocate memory for our shellcode, you could also write a function to search for padding in known modules instead
		const auto remote_alloc = process::alloc(size_shellcode + sizeof(CONTEXT), PAGE_EXECUTE_READWRITE);

		if(!remote_alloc){return false;}

		// build our asm code
		*reinterpret_cast<uintptr_t*>(veh + 5) = outlines_va; // the veh will check if outlines_va triggered the exception single_step (hook)
		*reinterpret_cast<void**>(add_veh + 2) = AddVectoredExceptionHandler; // will be called to register our veh
		*reinterpret_cast<uint64_t*>(add_veh + 12) = 0x1ull; // first argument to AddVEH
		*reinterpret_cast<uintptr_t*>(add_veh + 22) = remote_alloc; // second argument to AddVEH (address of our veh asm code above)
		*reinterpret_cast<void**>(restore_context + 2) = RtlRestoreContext; // will be called to restore thread state
		*reinterpret_cast<uintptr_t*>(restore_context + 12) = remote_alloc + size_context_aligned; // this is where context will be written to, that will be used by RtlRestoreContext then

		CONTEXT ctx, ctx_backup{ctx.ContextFlags = CONTEXT_ALL}; // we want all registers to be restored
		GetThreadContext(process::main_thread_handle_, &ctx);
		ctx.Dr0 = outlines_va; // setting dr0 to outlines
		ctx.Dr7 = 0x1ull; // and enabling dr0 locally
		ctx_backup = ctx;
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		SetThreadContext(process::main_thread_handle_, &ctx); // we are setting *only* debug regs now, since RtlRestoreContext does not do it
		ctx.ContextFlags = CONTEXT_ALL;

		// write everything to remote process
		if(!process::write(remote_alloc, veh) ||
			!process::write(remote_alloc + size_veh, add_veh) ||
			!process::write(remote_alloc + size_veh + size_add_veh, restore_context) ||
			!process::write(remote_alloc + size_context_aligned, ctx_backup)) {
			return false;
		}

		DWORD old;
		VirtualProtectEx(process::handle_, (void*)remote_alloc, size_shellcode + sizeof(CONTEXT), PAGE_EXECUTE_READ, &old); // no write needed anymore

		ctx.Rsp = (ctx.Rsp - 0x69) & ~0xfull; // making some space on the stack, so that AddVectoredExceptionHandler does not overwrite stuff on stack, and align it 16 uint8_ts
		ctx.Rip = remote_alloc + size_veh; // setting rip to asm of add_veh_asm
		
		SetThreadContext(process::main_thread_handle_, &ctx);
		process::resume(); // gogo

		return true;
	}
}
