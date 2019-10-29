#include <Windows.h>
#include <iostream>
#include "Process.h"
#include "Outlines.h"

int main() {

	std::cout << "Outlines for Overwatch" << std::endl;

	if(!process::init("Overwatch.exe")) {
		std::cout << "Start Overwatch first" << std::endl;
		return 1;
	}

	if(!outlines::activate()) {
		std::cout << "Error" << std::endl;
	}

	std::cout << "Success" << std::endl;

	return 0;
}