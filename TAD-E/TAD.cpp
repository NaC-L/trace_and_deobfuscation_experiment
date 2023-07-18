// TAD.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define _CRT_SECURE_NO_WARNINGS



#include "Includes.h"
#include "TaintEngine.cpp"
#include "RegisterStuff.h"

ZydisDecoder decoder;
ZydisFormatter formatter;
ZydisDisassembledInstruction  instruction;

TaintEngine TEngine;

int a = 1;

void printTrueBits(const std::bitset<FLAGSET>& bitset) {
    for (size_t i = 0; i < bitset.size(); i++) {
        if (bitset[i]) {
            cout << i << " ,";
        }
    }
    cout << "\n";
}

vector<pair< pair<ZydisDisassembledInstruction, vector<ZyanU8> >, std::bitset<FLAGSET> > >  instruction_list; // RETARDED WAY THANKS TO ZYDIS NOT PROPERLY ENCODING
std::vector<ZyanU8> bytes; 
std::vector<ZyanU8> newBytes; 

int linelen = 0;

uint64_t rdi;

uint64_t rip;
uint64_t r10;
uint64_t rax;
bool hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {

    memset(&rip, 0, sizeof(rip));
    memset(&bytes, 0, sizeof(bytes));
    memset(&instruction, 0, sizeof(bytes));
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    uc_reg_read(uc, UC_X86_REG_EDI, &r10);



    bytes.resize(size);
    uc_mem_read(uc, rip, bytes.data(), size);



    ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, rip, bytes.data(), bytes.size(), &instruction);


    std::bitset<FLAGSET> flag;
    TEngine.handleInstruction(&instruction, uc, flag, rip, &bytes);
    auto flaghash = TEngine.getTaintHash(flag);
    auto rsp = TEngine.getRegisterTaint(ZYDIS_REGISTER_RSP);


    std::cout << linelen << " --- Emulated instruction at address 0x" << std::hex << rip << " inst: " << instruction.text << " flag: " << hex << flaghash << "\n";


    if (!a) {

        instruction_list.push_back(make_pair(make_pair(instruction, bytes), flag)); // REFER TO LINE 29
    }
    if (a) {
        a = 0;
    }
    linelen++;
    


    return true;
}

// Define the global variables outside of the main function
uc_engine* uc;
uc_hook trace1;

// Define the function to be called outside of the main function
int emulate(const char* filename, uint64_t emuStartAddr, uint64_t emuEndAddr, bool experimental = 0)
{
    // Initialize Zydis decoder and formatter

    // Initialize Unicorn engine
    uc_err err;
    if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc) != UC_ERR_OK) {
        std::cerr << "Failed to initialize Unicorn engine" << std::endl;
        return -1;
    }

    // Load the PE file into memory
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to open the file." << std::endl;
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID fileBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, fileSize);

    // Parse the PE headers
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(fileBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(fileBase) + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    auto ADDRESS = ntHeaders->OptionalHeader.ImageBase;

    uc_mem_map(uc, ADDRESS, 8 * 1024 * 1024, UC_PROT_ALL);

    const uint64_t stack_addr = 0x0;
    const int stack_size = 1024 * 1024;
    uc_mem_map(uc, stack_addr, stack_size, UC_PROT_ALL);
    uint64_t rsp = stack_addr + stack_size - 0x100;

    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);

    rsp = 0x1337;
    uc_reg_write(uc, UC_X86_REG_RCX, &rsp);

    rsp = 0x7332;
    uc_reg_write(uc, UC_X86_REG_RDX, &rsp);

    // Iterate over the sections and extract information
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        uc_mem_write(uc, ADDRESS + sectionHeader->VirtualAddress, (void*)((char*)fileBase + sectionHeader->PointerToRawData), sectionHeader->SizeOfRawData - 1);
        sectionHeader++;
    }

    // Cleanup the loaded PE file resources
    UnmapViewOfFile(fileBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    // Set instruction tracing hook
    TEngine.clone_uc_State(uc);
    if (uc_hook_add(uc, &trace1, UC_HOOK_CODE, &hook_code, nullptr, 1, 0) != UC_ERR_OK) {
        std::cerr << "Failed to set instruction tracing hook" << std::endl;
        uc_close(uc);
        return -1;
    }

    // Emulate the code
    uc_err error = uc_emu_start(uc, emuStartAddr,  emuEndAddr, 0, 0);
    if (error != UC_ERR_OK) {
        uint64_t rip;
        uint64_t Stackp;

        uc_reg_read(uc, UC_X86_REG_RIP, &rip);
        uc_reg_read(uc, UC_X86_REG_RSP, &Stackp);

        std::cout << "Failed address 0x" << std::hex << rip << " rsp: " << hex << Stackp;
        std::cerr << "\nFailed emulation Error: " << error << std::endl;

        uc_close(uc);
        return -1;
    }

    // Cleanup
    std::cout << "cleanup TS:" << TEngine.lastTaint << "\n";
    uc_close(uc);

    return 0;
}

bool last16(bitset<FLAGSET> flag, int* whichReg) {
    bool result = 0;
    vector<bitset<FLAGSET>> taints;

    taints.emplace_back(TEngine.getRegisterTaint(ZYDIS_REGISTER_RAX));

    taints.emplace_back(TEngine.getRegisterTaint(ZYDIS_REGISTER_RCX));

    taints.emplace_back(TEngine.getRegisterTaint(ZYDIS_REGISTER_RBX));

    taints.emplace_back(TEngine.getRegisterTaint(ZYDIS_REGISTER_RDX));


    taints.emplace_back(TEngine.getRegisterTaint(ZYDIS_REGISTER_RBP));
    taints.emplace_back(TEngine.getRegisterTaint(ZYDIS_REGISTER_RSI));
    taints.emplace_back(TEngine.getRegisterTaint(ZYDIS_REGISTER_RDI));
    taints.emplace_back(TEngine.getRegisterTaint(ZYDIS_REGISTER_R8));
    taints.emplace_back(TEngine.getRegisterTaint(ZYDIS_REGISTER_R9));
    taints.emplace_back(TEngine.getRegisterTaint(ZYDIS_REGISTER_R10));
    taints.emplace_back(TEngine.getRegisterTaint(ZYDIS_REGISTER_R11));
    taints.emplace_back(TEngine.getRegisterTaint(ZYDIS_REGISTER_R12));
    taints.emplace_back(TEngine.getRegisterTaint(ZYDIS_REGISTER_R13));
    taints.emplace_back(TEngine.getRegisterTaint(ZYDIS_REGISTER_R14));
    taints.emplace_back(TEngine.getRegisterTaint(ZYDIS_REGISTER_R15));

    taints.emplace_back(TEngine.getRegisterTaint(ZYDIS_REGISTER_RSP));
    for (const auto &taint : taints) {
        (*whichReg)++;
        if (TEngine.isInFlag(taint, flag)   && !TEngine.its1On1but0On2(flag, taint)) {
            //cout << "inst: "; printTrueBits(flag);
            //cout << "register: "; printTrueBits(taint); cout << "\n";
            return  1;
        }
    }
    
    return result;
}


#include <LIEF/LIEF.hpp>

#include <LIEF/LIEF.hpp>

void add_section_to_pe(const std::string& path, const std::vector<uint8_t>& data) {
    // Parse the PE file
    std::unique_ptr<LIEF::PE::Binary> binary = LIEF::PE::Parser::parse(path);

    // Name of the section
    std::string section_name = ".devirt3";

    // Check if the section already exists
    LIEF::PE::Section* old_section = binary->get_section(section_name);
    if (old_section != nullptr) {
        // If the section exists, remove it
        binary->remove_section(section_name);
        binary->remove_section(".l2");
    }

    // Create a new section
    LIEF::PE::Section new_section(section_name);

    // Set the section's data
    new_section.content(data);
    new_section.size(data.size() + 0x1000);

    // Set the section's characteristics
    new_section.add_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_CODE);
    new_section.add_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE);
    new_section.add_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ);

    // Add the section to the binary
    binary->add_section(new_section);

    // Write the modified binary back to the file
    binary->write(path);
}



int main(int argc, char* argv[])
{
    // Check if the required arguments are provided
    if (argc < 4) {
        std::cout << "Usage: ./executable filename emu_start_addr emu_end_addr (optional experimental 0/1)" << std::endl;
        return 1;
    }

    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    // Retrieve the arguments
    const char* filename = argv[1];
    uint64_t emuStartAddr = std::stoull(argv[2], nullptr, 16);
    uint64_t emuEndAddr = std::stoull(argv[3], nullptr, 16);

    // Call the emulate function with the provided arguments
    bool experimental = 0;
    if (argc == 5)
        experimental = 1;

    emulate(filename, emuStartAddr, emuEndAddr,experimental);
    instruction_list.pop_back();
    for (const auto &i : instruction_list) {
        int whichReg = 0;
        if (last16(i.second, &whichReg)) {
            cout << i.first.first.text << " flag: " << hex << TEngine.getTaintHash(i.second) << " this_reg:" << whichReg << "\n";

            for (auto addBytes : i.first.second)
                newBytes.push_back(addBytes); // REFER TO LINE 29
            
        }


    }

    newBytes.push_back(0xC3);

    add_section_to_pe(filename, newBytes);


}
// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
