#include <fstream>
#ifdef CLI_BUILD
#include <iostream>
#else
#include <windows.h>
#endif

#include <main.hpp>

#include "WindowsExecutableFile.hpp"

int entrypoint(std::vector<std::string>&& args, bool console)
{
	if (args.size() < 2)
	{
#ifdef CLI_BUILD
		std::cout << "Syntax: sideloadify <exe path>" << std::endl;
#else
		MessageBoxA(0, "Drop the EXE you would like to sideloadify onto sideloadify.exe.", "Sideloadify", MB_OK | MB_ICONERROR);
#endif
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
#ifndef CLI_BUILD
			MessageBoxA(0, path.c_str(), "Sideloadify", MB_OK | MB_ICONINFORMATION);
#endif
		}
		else
		{
			path.append(" seems to already be sideloadified.");
#ifndef CLI_BUILD
			MessageBoxA(0, path.c_str(), "Sideloadify", MB_OK | MB_ICONINFORMATION);
#endif
		}
#ifdef CLI_BUILD
		std::cout << path << std::endl;
#endif
	}
	catch (const std::exception& e)
	{
#ifdef CLI_BUILD
		std::cout << e.what() << std::endl;
#else
		MessageBoxA(0, e.what(), "Sideloadify", MB_OK | MB_ICONERROR);
#endif
		return 1;
	}

	return 0;
}

#ifdef CLI_BUILD
SOUP_MAIN_CLI(entrypoint)
#else
SOUP_MAIN_GUI(entrypoint)
#endif
