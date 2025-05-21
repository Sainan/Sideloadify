#include <fstream>
#include <windows.h>

#include <main.hpp>

#include "WindowsExecutableFile.hpp"

int entrypoint(std::vector<std::string>&& args, bool console)
{
	if (args.size() < 2)
	{
		MessageBoxA(0, "Drop the EXE you would like to sideloadify onto sideloadify.exe.", "Sideloadify", MB_OK | MB_ICONERROR);
		return 1;
	}

	try
	{
		std::string path = args[1];
		vm86::WindowsExecutableFile exe(path);
		const auto loadConfig = exe.getDataDirectoryRvaAndSize(vm86::DATADIRECTORY_LOAD_CONFIG);
		const auto DependentLoadFlags_offset = exe.getRvaOffsetInFile(loadConfig.rva + 78);
		auto DependentLoadFlags = exe.readFromFileOffset<uint32_t>(DependentLoadFlags_offset);
		if (DependentLoadFlags != 0)
		{
			exe.file.seekg(DependentLoadFlags_offset);
			exe.file.write("\0\0", 2);

			path.append(" has successfully been sideloadified.");
			MessageBoxA(0, path.c_str(), "Sideloadify", MB_OK | MB_ICONINFORMATION);
		}
		else
		{
			path.append(" seems to already be sideloadified.");
			MessageBoxA(0, path.c_str(), "Sideloadify", MB_OK | MB_ICONINFORMATION);
		}
	}
	catch (const std::exception& e)
	{
		MessageBoxA(0, e.what(), "Sideloadify", MB_OK | MB_ICONERROR);
		return 1;
	}

	return 0;
}

SOUP_MAIN_GUI(entrypoint)
