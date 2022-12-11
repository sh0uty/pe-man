#pragma once

#include <Windows.h>
#include <iostream>

#define PRINT_PROP(x, y) std::cout << "\t0x" << std::hex << x << "\t\t" << y << std::endl;
#define PRINT_PROP_SHORT(x, y) std::cout << "\t0x" << std::hex << x << "\t" << y << std::endl;

namespace PEMan
{
	class PEFile {

	private:
		const char* m_Filename;
		bool m_64Bit;
		PIMAGE_DOS_HEADER m_DosHeader;
		PIMAGE_NT_HEADERS m_NTHeader;
		PIMAGE_FILE_HEADER m_FileHeader;
		IMAGE_OPTIONAL_HEADER32 m_OptionalHeader32;
		IMAGE_OPTIONAL_HEADER64 m_OptionalHeader64;

		bool ParsePEFile();

	public:
		PEFile(const char* filename) : m_Filename{ filename }, m_DosHeader{ 0 }, m_NTHeader{ 0 }, m_FileHeader{ 0 }, m_OptionalHeader32{ 0 }, m_OptionalHeader64{ 0 }{}
		void Print();
	};
}