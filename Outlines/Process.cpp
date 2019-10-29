#include "Process.h"
#include <TlHelp32.h>
#include <Psapi.h>

#define MAKEULONGLONG(ldw, hdw) ((ULONGLONG(hdw) << 32) | ((ldw) & 0xFFFFFFFF))

namespace process {
	uintptr_t base_ = 0;
	uint64_t module_size_ = 0;
	uint32_t id_ = 0;
	HANDLE handle_ = INVALID_HANDLE_VALUE;
	uint32_t main_thread_id_ = 0;
	HANDLE main_thread_handle_ = INVALID_HANDLE_VALUE;

	uint32_t suspend() {
		return SuspendThread(main_thread_handle_);
	}

	uint32_t resume() {
		return ResumeThread(main_thread_handle_);
	}

	uintptr_t alloc(uint64_t _size, const uint32_t _access_mask) {
		return reinterpret_cast<uintptr_t>(VirtualAllocEx(handle_, nullptr, _size, MEM_COMMIT|MEM_RESERVE, _access_mask));
	}

	uintptr_t rva_to_va(uintptr_t _rva) {
		return base_ + _rva;
	}

	bool read(uintptr_t _va, void * _out_buffer, uint64_t _size) {
		SIZE_T read;
		return ReadProcessMemory(handle_, (LPCVOID)_va, _out_buffer, _size, &read) && read == _size;
	}

	uintptr_t aob_scan(const std::basic_string_view<char> _pattern, const std::basic_string_view<char> _mask) {
		uint8_t chunk[0x1000];
		for(auto p = base_; p < base_ + module_size_; p+=0x1000) {
			read(p, chunk, 0x1000);
			int n = 0;
			for(auto c = 0u; c < 0x1000; c++) {
				(_mask[n] != '?') && (chunk[c] == (uint8_t)_pattern[n]) ? n++ : n = 0;
				if(n >= _mask.size()) {
					return p + c - n + 1;
				}
			}
		}
		return 0;
	}

	// getting process with longest thread times to *hopefully* get the mainthread
	bool get_process_main_thread() {
		bool result = false;
		DWORD thread_id = 0;
		auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		THREADENTRY32 te32 = {0};
		te32.dwSize = sizeof(THREADENTRY32);
		ULONGLONG min_create_time = MAXULONGLONG;
		if(INVALID_HANDLE_VALUE != snapshot) {
			auto search_next = Thread32First(snapshot, &te32);
			while(search_next) {
				if(te32.th32OwnerProcessID == id_) {
					auto tmp_thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
					if(NULL != tmp_thread) {
						FILETIME times[4] = {0};
						if(GetThreadTimes(tmp_thread, &times[0], &times[1], &times[2], &times[3])) {
							ULONGLONG current_create_time = MAKEULONGLONG(times[0].dwLowDateTime, times[0].dwHighDateTime);
							if(current_create_time && current_create_time < min_create_time) {
								min_create_time = current_create_time;
								thread_id = te32.th32ThreadID;
							}
						}
						CloseHandle(tmp_thread);
					}
					break;
				}
				search_next = Thread32Next(snapshot, &te32);
			}
			CloseHandle(snapshot);
			if(thread_id) {
				main_thread_id_ = thread_id;
				main_thread_handle_ = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
				if(NULL != main_thread_handle_)
					result = true;
			}
		}
		return result;
	}

	bool init (const std::basic_string_view<char> _process_name) {
		const auto snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS|TH32CS_SNAPTHREAD, 0)};
		if(INVALID_HANDLE_VALUE == snapshot)
			return false;

		PROCESSENTRY32 process_entry{sizeof PROCESSENTRY32};
		auto process{Process32First(snapshot, &process_entry)};
		for(; process; process = Process32Next(snapshot, &process_entry))
			if(_stricmp(process_entry.szExeFile, _process_name.data()) == 0)
				break;

		CloseHandle(snapshot);

		if(!process)
			return false;

		id_ = process_entry.th32ProcessID;

		if(!(handle_ = OpenProcess(PROCESS_ALL_ACCESS, false, process_entry.th32ProcessID)) ||
			!(get_process_main_thread())) {
			return false;
		};

		DWORD needed{0};
		if(K32EnumProcessModulesEx(handle_, (HMODULE*)& base_, sizeof(base_), &needed, LIST_MODULES_64BIT)) {
			MODULEINFO mi;
			GetModuleInformation(handle_, (HMODULE)base_, &mi, sizeof(mi));
			module_size_ = mi.SizeOfImage;
			return true;
		}

		return false;
	}
}