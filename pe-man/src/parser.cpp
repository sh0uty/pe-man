#include "parser.h"

namespace PEMan {

	bool PEFile::ParsePEFile()
	{
		HANDLE file = CreateFile(m_Filename, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (file == INVALID_HANDLE_VALUE)
		{
			std::cout << "[-] Invalid file handle" << std::endl;
			return false;
		}

		DWORD fileSize = GetFileSize(file, NULL);
		LPVOID fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);

		DWORD bytesRead;

		if (!ReadFile(file, fileData, fileSize, &bytesRead, NULL))
		{
			std::cout << "[-] Could not read file." << std::endl;
			return false;
		}

		m_DosHeader = (PIMAGE_DOS_HEADER)fileData;

		if (!m_DosHeader)
		{
			std::cout << "[-] DOS HEADER was null." << std::endl;
			return false;
		}


		if (m_DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			std::cout << "[-] Not a PE file." << std::endl;
			return false;
		}

		m_NTHeader = (PIMAGE_NT_HEADERS)((DWORD64)m_DosHeader + m_DosHeader->e_lfanew);


		if (m_NTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		{
			m_OptionalHeader32 = ((PIMAGE_NT_HEADERS32)((DWORD64)m_DosHeader + m_DosHeader->e_lfanew))->OptionalHeader;
		}
		else if (m_NTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			m_OptionalHeader64 = ((PIMAGE_NT_HEADERS64)((DWORD64)m_DosHeader + m_DosHeader->e_lfanew))->OptionalHeader;
		}

		std::cout << "[+] Parsed successfully." << std::endl << std::endl;
		return true;
	}

	void PEFile::Print()
	{
		if (!ParsePEFile())
			return;

		std::cout << "------- DOS HEADER -------" << std::endl;
		PRINT_PROP(m_DosHeader->e_magic, "Magic number");
		PRINT_PROP(m_DosHeader->e_cblp, "Bytes on last page");
		PRINT_PROP(m_DosHeader->e_cp, "Page count");
		PRINT_PROP(m_DosHeader->e_crlc, "Relocations");
		PRINT_PROP(m_DosHeader->e_cparhdr, "Size of the header in paragraphs");
		PRINT_PROP(m_DosHeader->e_minalloc, "Minimum extra paragraphs needed");
		PRINT_PROP(m_DosHeader->e_maxalloc, "Maximum extra paragraphs needed");
		PRINT_PROP(m_DosHeader->e_ss, "Initial (relative) SS value");
		PRINT_PROP(m_DosHeader->e_sp, "Initial SP value");
		PRINT_PROP(m_DosHeader->e_csum, "Checksum");
		PRINT_PROP(m_DosHeader->e_ip, "Initial IP value");
		PRINT_PROP(m_DosHeader->e_cs, "Initial (relative) CS value");
		PRINT_PROP(m_DosHeader->e_lfarlc, "Raw address of the relocation table");
		PRINT_PROP(m_DosHeader->e_ovno, "Overlay number");
		PRINT_PROP(m_DosHeader->e_oemid, "OEM identifier");
		PRINT_PROP(m_DosHeader->e_oeminfo, "OEM information");
		PRINT_PROP(m_DosHeader->e_lfanew, "Raw address of the NT header");

		std::cout << std::endl << "------- NT HEADER -------" << std::endl;
		PRINT_PROP(m_NTHeader->Signature, "Signature");

		std::cout << std::endl << "------- FILE HEADER -------" << std::endl;
		PRINT_PROP(m_NTHeader->FileHeader.Machine, "The machine (CPU type) the PE file is intended for");
		PRINT_PROP(m_NTHeader->FileHeader.NumberOfSections, "The number of sections in the PE file");
		PRINT_PROP_SHORT(m_NTHeader->FileHeader.TimeDateStamp, "Time and date stamp");
		PRINT_PROP(m_NTHeader->FileHeader.PointerToSymbolTable, "Pointer to COFF symbols table");
		PRINT_PROP(m_NTHeader->FileHeader.NumberOfSymbols, "The number of COFF symbols");
		PRINT_PROP(m_NTHeader->FileHeader.SizeOfOptionalHeader, "The size of the optional header which follow the file header");
		PRINT_PROP(m_NTHeader->FileHeader.Characteristics, "Set of flags which describe the PE file in detail");


	}

}