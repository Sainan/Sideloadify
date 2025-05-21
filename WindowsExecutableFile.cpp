// Ripped from https://github.com/calamity-inc/vm86 (currently not public)

#include "WindowsExecutableFile.hpp"

#include <stdexcept>

namespace vm86
{
	WindowsExecutableFile::WindowsExecutableFile(std::fstream&& _file)
		: file(std::move(_file))
	{
		if (!file.is_open())
		{
			throw std::runtime_error("fstream is not open");
		}
		const uint16_t mz = readFromFileOffset<uint16_t>(0);
		if (mz != ('M' | ('Z' << 8)))
		{
			throw std::domain_error(std::string("Expected file to start with 'MZ', found '").append(std::string((char*)&mz, 2)).append("'"));
		}
		pe_sig_offset = readFromFileOffset<uint32_t>(0x3C);
		const uint32_t sig = readFromFileOffset<uint32_t>(pe_sig_offset);
		if (sig != ('P' | ('E' << 8)))
		{
			throw std::domain_error(std::string("Unexpected PE signature: ").append(std::string((char*)&sig, 4)));
		}
		// Sanity checks
		const size_t data_directory_size = (size_t)getNumberOfDataDirectories() * 8;
		switch (getPeHeaderSignature())
		{
		default:
			throw std::domain_error(std::string("Unexpected PE header signature: ").append(std::to_string(getPeHeaderSignature())));

		case PEHEADERSIG_ROM:
			throw std::domain_error("ROMs are not supported");

		case PEHEADERSIG_32BIT:
			if (getSizeOfPeHeader() != 96 + data_directory_size)
			{
				throw std::domain_error(std::string("Expected ").append(std::to_string(96 + data_directory_size)).append(" bytes of PE header for a 32-bit PE file with ").append(std::to_string(getNumberOfDataDirectories())).append(" data directories, but COFF header says ").append(std::to_string(getSizeOfPeHeader())).append(" bytes"));
			}
			break;

		case PEHEADERSIG_64BIT:
			if (getSizeOfPeHeader() != 112 + data_directory_size)
			{
				throw std::domain_error(std::string("Expected ").append(std::to_string(112 + data_directory_size)).append(" bytes of PE header for a 64-bit PE file with ").append(std::to_string(getNumberOfDataDirectories())).append(" data directories, but COFF header says ").append(std::to_string(getSizeOfPeHeader())).append(" bytes"));
			}
			break;
		}
	}

	WindowsExecutableFile::WindowsExecutableFile(const std::string& path)
		: WindowsExecutableFile(std::fstream(path, std::ios::in | std::ios::out | std::ios::binary))
	{
	}

#define COFF_BASE (std::streamoff)pe_sig_offset + 4
#define COFF_MACHINE             COFF_BASE
#define COFF_NUMSECTIONS     2 + COFF_MACHINE
#define COFF_TIMESTAMP       2 + COFF_NUMSECTIONS
#define COFF_SYMTBLPTR       4 + COFF_TIMESTAMP
#define COFF_NUMSYM          4 + COFF_SYMTBLPTR
#define COFF_PEHEADERSIZE    4 + COFF_NUMSYM
#define COFF_CHARACTERISTICS 2 + COFF_PEHEADERSIZE
#define COFF_END             2 + COFF_CHARACTERISTICS

	std::string WindowsExecutableFile::readString(std::streamoff off)
	{
		std::string str;
		char c;
		while (true)
		{
			c = readFromFileOffset<char>(off);
			if (c == '\0')
			{
				return str;
			}
			str.append(1, c);
			off++;
		}
	}

	uint16_t WindowsExecutableFile::getCompiledForMachine()
	{
		return readFromFileOffset<uint16_t>(COFF_MACHINE);
	}

	uint16_t WindowsExecutableFile::getNumberOfSections()
	{
		return readFromFileOffset<uint16_t>(COFF_NUMSECTIONS);
	}

	uint32_t WindowsExecutableFile::getTimestamp()
	{
		return readFromFileOffset<uint32_t>(COFF_TIMESTAMP);
	}

	uint32_t WindowsExecutableFile::getNumberOfSymbols()
	{
		return readFromFileOffset<uint32_t>(COFF_NUMSYM);
	}

	uint16_t WindowsExecutableFile::getSizeOfPeHeader()
	{
		return readFromFileOffset<uint16_t>(COFF_PEHEADERSIZE);
	}

	uint16_t WindowsExecutableFile::getCharacteristics()
	{
		return readFromFileOffset<uint16_t>(COFF_CHARACTERISTICS);
	}

#define PE_BASE COFF_END
#define PE_SIG  PE_BASE

	PeHeaderSignature WindowsExecutableFile::getPeHeaderSignature()
	{
		return readFromFileOffset<PeHeaderSignature>(PE_SIG);
	}


	uint32_t WindowsExecutableFile::getNumberOfDataDirectories()
	{
		return readFromFileOffset<uint32_t>(COFF_END + (getPeHeaderSignature() == PEHEADERSIG_32BIT ? 92 : 108));
	}

	DataDirectoryRvaAndSize WindowsExecutableFile::getDataDirectoryRvaAndSize(uint32_t index)
	{
		if (index >= getNumberOfDataDirectories())
		{
			throw std::overflow_error(std::string("Can't access data directory at index ").append(std::to_string(index)).append(" because there's only ").append(std::to_string(getNumberOfDataDirectories())).append(" data directories"));
		}
		return readFromFileOffset<DataDirectoryRvaAndSize>(PE_BASE + (getPeHeaderSignature() == PEHEADERSIG_32BIT ? 96 : 112) + ((std::streamoff)index * 8));
	}

#define SEC_BASE    getSectionOffsetInFile(section)
#define SEC_NAME        SEC_BASE
#define SEC_MISC    8 + SEC_NAME
#define SEC_VADDR   4 + SEC_MISC
#define SEC_SIZE    4 + SEC_VADDR
#define SEC_DATAOFF 4 + SEC_SIZE

	std::streamoff WindowsExecutableFile::getSectionOffsetInFile(uint16_t section)
	{
		return COFF_END + getSizeOfPeHeader() + (0x28 * (std::streamoff)section);
	}

	std::string WindowsExecutableFile::getSectionName(uint16_t section)
	{
		char name[8];
		file.seekg(SEC_BASE);
		file.read(name, 8);
		return std::string(name, name[7] == '\0' ? strlen(name) : 8);
	}

	void WindowsExecutableFile::setSectionName(uint16_t section, const std::string& name)
	{
		if (name.size() > 8)
		{
			throw std::overflow_error("Section name can't use more than 8 bytes");
		}
		const std::streamoff off = SEC_BASE;
		file.seekg(off);
		file.write("\0\0\0\0\0\0\0\0", 8);
		file.seekg(off);
		file.write(name.data(), name.size());
	}

	uint32_t WindowsExecutableFile::getSectionVirtualAddress(uint16_t section)
	{
		return readFromFileOffset<uint32_t>(SEC_VADDR);
	}

	uint32_t WindowsExecutableFile::getSectionDataSize(uint16_t section)
	{
		return readFromFileOffset<uint32_t>(SEC_SIZE);
	}

	uint32_t WindowsExecutableFile::getSectionDataOffsetInFile(uint16_t section)
	{
		return readFromFileOffset<uint32_t>(SEC_DATAOFF);
	}

	std::vector<uint8_t> WindowsExecutableFile::getSectionData(uint16_t section)
	{
		std::vector<uint8_t> data(getSectionDataSize(section));
		file.seekg(getSectionDataOffsetInFile(section));
		file.read((char*)data.data(), data.size());
		return data;
	}

	std::optional<std::pair<uint16_t, uint32_t>> WindowsExecutableFile::resolveRva(uint32_t rva)
	{
		const uint16_t num_sections = getNumberOfSections();
		for (uint16_t i = 0; i < num_sections; i++)
		{
			const uint32_t sec_rva = getSectionVirtualAddress(i);
			if (sec_rva <= rva)
			{
				uint32_t rva_sec_off = rva - sec_rva;
				if (rva_sec_off < getSectionDataSize(i))
				{
					return { { i, rva_sec_off } };
				}
			}
		}
		return std::nullopt;
	}

	std::streamoff WindowsExecutableFile::getRvaOffsetInFile(uint32_t rva)
	{
		auto location = resolveRva(rva);
		if (!location.has_value())
		{
			throw std::runtime_error(std::string("Failed to resolve RVA: ").append(std::to_string(rva)));
		}
		return (std::streamoff)getSectionDataOffsetInFile(location.value().first) + (std::streamoff)location.value().second;
	}
}
