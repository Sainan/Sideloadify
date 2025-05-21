// Ripped from https://github.com/calamity-inc/vm86 (currently not public)

#pragma once

#include <cstdint>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

namespace vm86
{
	// A class for reading and writing Windows executable files (.exe & .dll)

	// Credits:
	// - https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files
	// - https://www.sweetscape.com/010editor/repository/files/EXE.bt

	enum PeHeaderSignature : uint16_t
	{
		PEHEADERSIG_ROM   = 0x107,
		PEHEADERSIG_32BIT = 0x10b,
		PEHEADERSIG_64BIT = 0x20b,
	};

	struct DataDirectoryRvaAndSize
	{
		uint32_t rva; // Relative Virtual Address
		uint32_t size;
	};

	enum DataDirectoryIndex : uint32_t
	{
		DATADIRECTORY_EXPORT = 0,
		DATADIRECTORY_IMPORT = 1,
		DATADIRECTORY_RESOURCE = 2,
		DATADIRECTORY_EXCEPTION = 3,
		DATADIRECTORY_SECURITY = 4,
		DATADIRECTORY_BASERELOC = 5,
		DATADIRECTORY_DEBUG = 6,
		DATADIRECTORY_ARCHITECTURE = 7,
		DATADIRECTORY_GLOBALPTR = 8,
		DATADIRECTORY_TLS = 9,
		DATADIRECTORY_LOAD_CONFIG = 10,
		DATADIRECTORY_BOUND_IMPORT = 11,
		DATADIRECTORY_IAT = 12,
		DATADIRECTORY_DELAY_IMPORT = 13,
		DATADIRECTORY_COM_DESCRIPTOR = 14,
	};

	class WindowsExecutableFile
	{
	public:
		std::fstream file;
		uint32_t pe_sig_offset = 0;

		explicit WindowsExecutableFile(std::fstream&& file);
		explicit WindowsExecutableFile(const std::string& path);

		// === Read Helpers ===
		template <typename T>
		T readFromFileOffset(std::streamoff off)
		{
			file.seekg(off);
			T val{};
			file.read((char*)&val, sizeof(T));
			return val;
		}
		std::string readString(std::streamoff off); // reads a C-style, null-terminated char[] at the given offset

		// === COFF Header ===
		[[nodiscard]] uint16_t getCompiledForMachine(); // 0x14c for i386, 0x8664 for x86_64, anything else for "oh no"
		[[nodiscard]] uint16_t getNumberOfSections();
		[[nodiscard]] uint32_t getTimestamp();
		[[nodiscard]] uint32_t getNumberOfSymbols();
		[[nodiscard]] uint16_t getSizeOfPeHeader();
		[[nodiscard]] uint16_t getCharacteristics();

		// == PE Header ==
		[[nodiscard]] PeHeaderSignature getPeHeaderSignature();
		[[nodiscard]] uint32_t getNumberOfDataDirectories();
		[[nodiscard]] DataDirectoryRvaAndSize getDataDirectoryRvaAndSize(uint32_t index);

		// === Sections ===
		[[nodiscard]] std::streamoff getSectionOffsetInFile(uint16_t section);
		[[nodiscard]] std::string getSectionName(uint16_t section);
		void setSectionName(uint16_t section, const std::string& name); // UTF-8, max. 8 bytes
		[[nodiscard]] uint32_t getSectionVirtualAddress(uint16_t section);
		[[nodiscard]] uint32_t getSectionDataSize(uint16_t section);
		[[nodiscard]] uint32_t getSectionDataOffsetInFile(uint16_t section);
		[[nodiscard]] std::vector<uint8_t> getSectionData(uint16_t section);
		[[nodiscard]] std::optional<std::pair<uint16_t, uint32_t>> resolveRva(uint32_t rva); // resolves a relative virtual address. if has_value(), first is section, second is offset in section.
		[[nodiscard]] std::streamoff getRvaOffsetInFile(uint32_t rva);
	};
}
