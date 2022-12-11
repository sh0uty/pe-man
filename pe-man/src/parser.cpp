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
			m_64Bit = false;
		}
		else if (m_NTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			m_OptionalHeader64 = ((PIMAGE_NT_HEADERS64)((DWORD64)m_DosHeader + m_DosHeader->e_lfanew))->OptionalHeader;
			m_64Bit = true;
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

		std::cout << std::endl << "------- OPTIONAL HEADER -------" << std::endl;
		if (m_64Bit) 
		{
			PRINT_PROP(m_OptionalHeader64.Magic, "Flag if the file is x32, x64 or a ROM image");
			PRINT_PROP(m_OptionalHeader64.MajorLinkerVersion, "Major linker version");
			PRINT_PROP(m_OptionalHeader64.MinorLinkerVersion, "Minor linker version");
			PRINT_PROP(m_OptionalHeader64.SizeOfCode, "Size of all code sections together");
			PRINT_PROP(m_OptionalHeader64.SizeOfInitializedData, "Size of all initialized data sections together");
			PRINT_PROP(m_OptionalHeader64.SizeOfUninitializedData, "Size of all uninitialized data sections together");
			PRINT_PROP(m_OptionalHeader64.AddressOfEntryPoint, "RVA of the entry point function");
			PRINT_PROP(m_OptionalHeader64.BaseOfCode, "RVA to the beginning of the code section");
			PRINT_PROP_SHORT(m_OptionalHeader64.ImageBase, "Preferred address of the image when it's loaded to memory");
			PRINT_PROP(m_OptionalHeader64.SectionAlignment, "Section alignment in memory in bytes. Must be greater or equal to the file alignment");
			PRINT_PROP(m_OptionalHeader64.FileAlignment, "File alignment of the raw data of the sections in bytes");
			PRINT_PROP(m_OptionalHeader64.MajorOperatingSystemVersion, "Major operation system version to run the file");
			PRINT_PROP(m_OptionalHeader64.MinorOperatingSystemVersion, "Minor operation system version to run the file");
			PRINT_PROP(m_OptionalHeader64.MajorImageVersion, "Major image version");
			PRINT_PROP(m_OptionalHeader64.MinorImageVersion, "Minor image version");
			PRINT_PROP(m_OptionalHeader64.MajorSubsystemVersion, "Major version of the subsystem");
			PRINT_PROP(m_OptionalHeader64.MinorSubsystemVersion, "Minor version of the subsystem");
			PRINT_PROP(m_OptionalHeader64.Win32VersionValue, "Reserved and must be 0");
			PRINT_PROP(m_OptionalHeader64.SizeOfImage, "Size of the image including all headers in bytes");
			PRINT_PROP(m_OptionalHeader64.SizeOfHeaders, "Sum of e_lfanew, signature, file header size, optional header size and section sizes");
			PRINT_PROP_SHORT(m_OptionalHeader64.CheckSum, "Image checksum validated at runtime for drivers, DLLs loaded at boot time and DLLs loaded into a critical system");
			PRINT_PROP(m_OptionalHeader64.Subsystem, "The subsystem required to run the image e.g., Windows GUI, XBOX etc");
			PRINT_PROP(m_OptionalHeader64.DllCharacteristics, "DLL characteristics of the image");
			PRINT_PROP_SHORT(m_OptionalHeader64.SizeOfStackReserve, "Size of stack reserve in bytes");
			PRINT_PROP(m_OptionalHeader64.SizeOfStackCommit, "Size of bytes committed for the stack in bytes");
			PRINT_PROP_SHORT(m_OptionalHeader64.SizeOfHeapReserve, "Size of the heap to reserve in bytes");
			PRINT_PROP(m_OptionalHeader64.SizeOfHeapCommit, "Size of the heap commit in bytes");
			PRINT_PROP(m_OptionalHeader64.LoaderFlags, "Obsolete");
			PRINT_PROP(m_OptionalHeader64.NumberOfRvaAndSizes, "Number of directory entries in the remainder of the optional header");
		}
		else
		{
			PRINT_PROP(m_OptionalHeader32.Magic, "Flag if the file is x32, x64 or a ROM image");
			PRINT_PROP(m_OptionalHeader32.MajorLinkerVersion, "Major linker version");
			PRINT_PROP(m_OptionalHeader32.MinorLinkerVersion, "Minor linker version");
			PRINT_PROP(m_OptionalHeader32.SizeOfCode, "Size of all code sections together");
			PRINT_PROP(m_OptionalHeader32.SizeOfInitializedData, "Size of all initialized data sections together");
			PRINT_PROP(m_OptionalHeader32.SizeOfUninitializedData, "Size of all uninitialized data sections together");
			PRINT_PROP(m_OptionalHeader32.AddressOfEntryPoint, "RVA of the entry point function");
			PRINT_PROP(m_OptionalHeader32.BaseOfCode, "RVA to the beginning of the code section");
			PRINT_PROP(m_OptionalHeader32.BaseOfData, "RVA to the beginning of the data section");
			PRINT_PROP_SHORT(m_OptionalHeader32.ImageBase, "Preferred address of the image when it's loaded to memory");
			PRINT_PROP(m_OptionalHeader32.SectionAlignment, "Section alignment in memory in bytes. Must be greater or equal to the file alignment");
			PRINT_PROP(m_OptionalHeader32.FileAlignment, "File alignment of the raw data of the sections in bytes");
			PRINT_PROP(m_OptionalHeader32.MajorOperatingSystemVersion, "Major operation system version to run the file");
			PRINT_PROP(m_OptionalHeader32.MinorOperatingSystemVersion, "Minor operation system version to run the file");
			PRINT_PROP(m_OptionalHeader32.MajorImageVersion, "Major image version");
			PRINT_PROP(m_OptionalHeader32.MinorImageVersion, "Minor image version");
			PRINT_PROP(m_OptionalHeader32.MajorSubsystemVersion, "Major version of the subsystem");
			PRINT_PROP(m_OptionalHeader32.MinorSubsystemVersion, "Minor version of the subsystem");
			PRINT_PROP(m_OptionalHeader32.Win32VersionValue, "Reserved and must be 0");
			PRINT_PROP(m_OptionalHeader32.SizeOfImage, "Size of the image including all headers in bytes");
			PRINT_PROP(m_OptionalHeader32.SizeOfHeaders, "Sum of e_lfanew, signature, file header size, optional header size and section sizes");
			PRINT_PROP_SHORT(m_OptionalHeader32.CheckSum, "Image checksum validated at runtime for drivers, DLLs loaded at boot time and DLLs loaded into a critical system");
			PRINT_PROP(m_OptionalHeader32.Subsystem, "The subsystem required to run the image e.g., Windows GUI, XBOX etc");
			PRINT_PROP(m_OptionalHeader32.DllCharacteristics, "DLL characteristics of the image");
			PRINT_PROP_SHORT(m_OptionalHeader32.SizeOfStackReserve, "Size of stack reserve in bytes");
			PRINT_PROP(m_OptionalHeader32.SizeOfStackCommit, "Size of bytes committed for the stack in bytes");
			PRINT_PROP_SHORT(m_OptionalHeader32.SizeOfHeapReserve, "Size of the heap to reserve in bytes");
			PRINT_PROP(m_OptionalHeader32.SizeOfHeapCommit, "Size of the heap commit in bytes");
			PRINT_PROP(m_OptionalHeader32.LoaderFlags, "Obsolete");
			PRINT_PROP(m_OptionalHeader32.NumberOfRvaAndSizes, "Number of directory entries in the remainder of the optional header");
		}

		std::cout << std::endl << "------- DATA DIRECTORIES -------" << std::endl;
		PRINT_PROP(m_NTHeader->OptionalHeader.DataDirectory[0].VirtualAddress, "RVA of export table");
		PRINT_PROP(m_NTHeader->OptionalHeader.DataDirectory[0].Size, "Size of export table");
		PRINT_PROP(m_NTHeader->OptionalHeader.DataDirectory[1].VirtualAddress, "RVA of import table");
		PRINT_PROP(m_NTHeader->OptionalHeader.DataDirectory[1].Size, "Size of import table");

		std::cout << std::endl << "------- SECTION HEADERS -------" << std::endl;
		DWORD64 sectionLocation = (DWORD64)m_NTHeader + sizeof(DWORD64) + (DWORD64)(sizeof(IMAGE_FILE_HEADER)) + (DWORD64)m_NTHeader->FileHeader.SizeOfOptionalHeader;
		DWORD64 sectionSize = (DWORD64)(sizeof(PIMAGE_SECTION_HEADER));

		DWORD64 importDirectoryRVA = m_NTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

		for (int i = 0; i < m_NTHeader->FileHeader.NumberOfSections; i++)
		{
			
		}
		
	}

}