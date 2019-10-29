#pragma once
#include <Windows.h>
#include <stdint.h>
#include <string>

namespace process {
	extern uintptr_t base_;
	extern uint64_t module_size_;
	extern uint32_t id_;
	extern HANDLE handle_;
	extern uint32_t main_thread_id_;
	extern HANDLE main_thread_handle_;
	bool init(const std::basic_string_view<char> _process_name);
	uint32_t suspend();
	uint32_t resume();
	uintptr_t alloc(uint64_t _size, const uint32_t _access_mask = PAGE_READWRITE);
	uintptr_t rva_to_va(uintptr_t _rva);
	bool read(uintptr_t _va, void* _out_buffer, uint64_t _size);
	template <typename T> T read(uintptr_t _va) {
		T t{};
		ReadProcessMemory(handle_, (LPCVOID)_va, &t, sizeof(t), nullptr);
		return t;
	};
	template <typename T> bool write(uintptr_t _va, T& _data) {
		return WriteProcessMemory(handle_, (LPVOID)_va, (LPCVOID)& _data, sizeof(_data), nullptr);
	};
	uintptr_t aob_scan(const std::basic_string_view<char> _pattern, const std::basic_string_view<char> _mask);
}