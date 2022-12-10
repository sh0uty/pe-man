#define WIN32_LEAN_AND_MEAN

#include <iostream>

#include "parser.h"

void Usage();

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		Usage();
		return 0;
	}
	
	if (strcmp(argv[1], "-f") == 0)
	{
		auto pefile = PEMan::PEFile(argv[2]);
		std::cout << "Trying to parse: " << argv[2] << std::endl;
		pefile.Print();
	}

}

void Usage()
{
	std::cout << "Usage: pe-man <argument>" << std::endl;
	std::cout << "	-f\tInput (PE) file" << std::endl;
}