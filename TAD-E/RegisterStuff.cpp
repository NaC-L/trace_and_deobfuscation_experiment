#pragma once
#include "Includes.h"

#include "RegisterStuff.h"

int zydis2Unicorn(ZydisRegister reg) {
    switch (reg) {
            // 64BIT REGISTERS
        case ZYDIS_REGISTER_RIP: {
            return UC_X86_REG_RIP;
        }

        case ZYDIS_REGISTER_RAX: {
            return UC_X86_REG_RAX;
        }

        case ZYDIS_REGISTER_RCX: {
            return UC_X86_REG_RCX;
        }

        case ZYDIS_REGISTER_RDX: {
            return UC_X86_REG_RDX;
        }

        case ZYDIS_REGISTER_RBX: {
            return UC_X86_REG_RBX;
        }

        case ZYDIS_REGISTER_RSP: {
            return UC_X86_REG_RSP;
        }

        case ZYDIS_REGISTER_RBP: {
            return UC_X86_REG_RBP;
        }

        case ZYDIS_REGISTER_RDI: {
            return UC_X86_REG_RDI;
        }

        case ZYDIS_REGISTER_RSI: {
            return UC_X86_REG_RSI;
        }
        case ZYDIS_REGISTER_R8: {
            return UC_X86_REG_R8;
        }
        case ZYDIS_REGISTER_R9: {
            return UC_X86_REG_R9;
        }

        case ZYDIS_REGISTER_R10: {
            return UC_X86_REG_R10;
        }

        case ZYDIS_REGISTER_R11: {
            return UC_X86_REG_R11;
        }

        case ZYDIS_REGISTER_R12: {
            return UC_X86_REG_R12;
        }

        case ZYDIS_REGISTER_R13: {
            return UC_X86_REG_R13;
        }

        case ZYDIS_REGISTER_R14: {
            return UC_X86_REG_R14;
        }

        case ZYDIS_REGISTER_R15: {
            return UC_X86_REG_R15;
        }
                               // 32BIT REGISTERS
        case ZYDIS_REGISTER_EIP: {
            return UC_X86_REG_EIP;
        }

        case ZYDIS_REGISTER_EAX: {
            return UC_X86_REG_EAX;
        }

        case ZYDIS_REGISTER_ECX: {
            return UC_X86_REG_ECX;
        }

        case ZYDIS_REGISTER_EDX: {
            return UC_X86_REG_EDX;
        }

        case ZYDIS_REGISTER_EBX: {
            return UC_X86_REG_EBX;
        }

        case ZYDIS_REGISTER_ESP: {
            return UC_X86_REG_ESP;
        }

        case ZYDIS_REGISTER_EBP: {
            return UC_X86_REG_EBP;
        }

        case ZYDIS_REGISTER_EDI: {
            return UC_X86_REG_EDI;
        }

        case ZYDIS_REGISTER_ESI: {
            return UC_X86_REG_ESI;
        }


        case ZYDIS_REGISTER_R8D: {
            return UC_X86_REG_R8D;
        }

        case ZYDIS_REGISTER_R9D: {
            return UC_X86_REG_R9D;
        }

        case ZYDIS_REGISTER_R10D: {
            return UC_X86_REG_R10D;
        }

        case ZYDIS_REGISTER_R11D: {
            return UC_X86_REG_R11D;
        }

        case ZYDIS_REGISTER_R12D: {
            return UC_X86_REG_R12D;
        }

        case ZYDIS_REGISTER_R13D: {
            return UC_X86_REG_R13D;
        }

        case ZYDIS_REGISTER_R14D: {
            return UC_X86_REG_R14D;
        }

        case ZYDIS_REGISTER_R15D: {
            return UC_X86_REG_R15D;
        }

                                // 16BIT REGISTERS

        case ZYDIS_REGISTER_IP: {
            return UC_X86_REG_IP;
        }

        case ZYDIS_REGISTER_AX: {
            return UC_X86_REG_AX;
        }

        case ZYDIS_REGISTER_CX: {
            return UC_X86_REG_CX;
        }

        case ZYDIS_REGISTER_DX: {
            return UC_X86_REG_DX;
        }

        case ZYDIS_REGISTER_BX: {
            return UC_X86_REG_BX;
        }

        case ZYDIS_REGISTER_SP: {
            return UC_X86_REG_SP;
        }

        case ZYDIS_REGISTER_BP: {
            return UC_X86_REG_BP;
        }

        case ZYDIS_REGISTER_DI: {
            return UC_X86_REG_DI;
        }

        case ZYDIS_REGISTER_SI: {
            return UC_X86_REG_SI;
        }


        case ZYDIS_REGISTER_R8W: {
            return UC_X86_REG_R8W;
        }

        case ZYDIS_REGISTER_R9W: {
            return UC_X86_REG_R9W;
        }

        case ZYDIS_REGISTER_R10W: {
            return UC_X86_REG_R10W;
        }

        case ZYDIS_REGISTER_R11W: {
            return UC_X86_REG_R11W;
        }

        case ZYDIS_REGISTER_R12W: {
            return UC_X86_REG_R12W;
        }

        case ZYDIS_REGISTER_R13W: {
            return UC_X86_REG_R13W;
        }

        case ZYDIS_REGISTER_R14W: {
            return UC_X86_REG_R14W;
        }

        case ZYDIS_REGISTER_R15W: {
            return UC_X86_REG_R15W;
        }
                                // 8BIT REGISTERS
        case ZYDIS_REGISTER_R8B: {
            return UC_X86_REG_R8B;
        }

        case ZYDIS_REGISTER_R9B: {
            return UC_X86_REG_R9B;
        }

        case ZYDIS_REGISTER_R10B: {
            return UC_X86_REG_R10B;
        }

        case ZYDIS_REGISTER_R11B: {
            return UC_X86_REG_R11B;
        }

        case ZYDIS_REGISTER_R12B: {
            return UC_X86_REG_R12B;
        }

        case ZYDIS_REGISTER_R13B: {
            return UC_X86_REG_R13B;
        }

        case ZYDIS_REGISTER_R14B: {
            return UC_X86_REG_R14B;
        }

        case ZYDIS_REGISTER_R15B: {
            return UC_X86_REG_R15B;
        }
                                // 8BIT REGISTERS LOW
        case ZYDIS_REGISTER_AL: {
            return UC_X86_REG_AL;
        }

        case ZYDIS_REGISTER_CL: {
            return UC_X86_REG_CL;
        }

        case ZYDIS_REGISTER_DL: {
            return UC_X86_REG_DL;
        }

        case ZYDIS_REGISTER_BL: {
            return UC_X86_REG_BL;
        }

        case ZYDIS_REGISTER_SPL: {
            return UC_X86_REG_SPL;
        }

        case ZYDIS_REGISTER_BPL: {
            return UC_X86_REG_BPL;
        }

        case ZYDIS_REGISTER_DIL: {
            return UC_X86_REG_DIL;
        }

        case ZYDIS_REGISTER_SIL: {
            return UC_X86_REG_SIL;
        }

                               // 8BIT REGISTERS HIGH

        case ZYDIS_REGISTER_AH: {
            return UC_X86_REG_AH;
        }

        case ZYDIS_REGISTER_CH: {
            return UC_X86_REG_CH;
        }

        case ZYDIS_REGISTER_DH: {
            return UC_X86_REG_DH;
        }

        case ZYDIS_REGISTER_BH: {
            return UC_X86_REG_BH;
        }
    }


}

int unicorn2Zydis(uc_x86_reg reg) {
    switch (reg) {

        // 64BIT REGISTERS
    case UC_X86_REG_RIP : {
        return ZYDIS_REGISTER_RIP;
    }

    case UC_X86_REG_RAX : {
        return ZYDIS_REGISTER_RAX;
    }

    case UC_X86_REG_RCX : {
        return ZYDIS_REGISTER_RCX;
    }

    case UC_X86_REG_RDX : {
        return ZYDIS_REGISTER_RDX;
    }

    case UC_X86_REG_RBX : {
        return ZYDIS_REGISTER_RBX;
    }

    case UC_X86_REG_RSP : {
        return ZYDIS_REGISTER_RSP;
    }

    case UC_X86_REG_RBP : {
        return ZYDIS_REGISTER_RBP;
    }

    case UC_X86_REG_RDI : {
        return ZYDIS_REGISTER_RDI;
    }

    case UC_X86_REG_RSI : {
        return ZYDIS_REGISTER_RSI;
    }
    case UC_X86_REG_R8 : {
        return ZYDIS_REGISTER_R8;
    }
    case UC_X86_REG_R9 : {
        return ZYDIS_REGISTER_R9;
    }

    case UC_X86_REG_R10 : {
        return ZYDIS_REGISTER_R10;
    }

    case UC_X86_REG_R11 : {
        return ZYDIS_REGISTER_R11;
    }

    case UC_X86_REG_R12 : {
        return ZYDIS_REGISTER_R12;
    }

    case UC_X86_REG_R13 : {
        return ZYDIS_REGISTER_R13;
    }

    case UC_X86_REG_R14 : {
        return ZYDIS_REGISTER_R14;
    }

    case UC_X86_REG_R15 : {
        return ZYDIS_REGISTER_R15;
    }
                           // 32BIT REGISTERS
    case UC_X86_REG_EIP : {
        return ZYDIS_REGISTER_EIP;
    }

    case UC_X86_REG_EAX : {
        return ZYDIS_REGISTER_EAX;
    }

    case UC_X86_REG_ECX : {
        return ZYDIS_REGISTER_ECX;
    }

    case UC_X86_REG_EDX : {
        return ZYDIS_REGISTER_EDX;
    }

    case UC_X86_REG_EBX : {
        return ZYDIS_REGISTER_EBX;
    }

    case UC_X86_REG_ESP : {
        return ZYDIS_REGISTER_ESP;
    }

    case UC_X86_REG_EBP : {
        return ZYDIS_REGISTER_EBP;
    }

    case UC_X86_REG_EDI : {
        return ZYDIS_REGISTER_EDI;
    }

    case UC_X86_REG_ESI : {
        return ZYDIS_REGISTER_ESI;
    }


    case UC_X86_REG_R8D : {
        return ZYDIS_REGISTER_R8D;
    }

    case UC_X86_REG_R9D : {
        return ZYDIS_REGISTER_R9D;
    }

    case UC_X86_REG_R10D : {
        return ZYDIS_REGISTER_R10D;
    }

    case UC_X86_REG_R11D : {
        return ZYDIS_REGISTER_R11D;
    }

    case UC_X86_REG_R12D : {
        return ZYDIS_REGISTER_R12D;
    }

    case UC_X86_REG_R13D : {
        return ZYDIS_REGISTER_R13D;
    }

    case UC_X86_REG_R14D : {
        return ZYDIS_REGISTER_R14D;
    }

    case UC_X86_REG_R15D : {
        return ZYDIS_REGISTER_R15D;
    }

                            // 16BIT REGISTERS

    case UC_X86_REG_IP : {
        return ZYDIS_REGISTER_IP;
    }

    case UC_X86_REG_AX : {
        return ZYDIS_REGISTER_AX;
    }

    case UC_X86_REG_CX : {
        return ZYDIS_REGISTER_CX;
    }

    case UC_X86_REG_DX : {
        return ZYDIS_REGISTER_DX;
    }

    case UC_X86_REG_BX : {
        return ZYDIS_REGISTER_BX;
    }

    case UC_X86_REG_SP : {
        return ZYDIS_REGISTER_SP;
    }

    case UC_X86_REG_BP : {
        return ZYDIS_REGISTER_BP;
    }

    case UC_X86_REG_DI : {
        return ZYDIS_REGISTER_DI;
    }

    case UC_X86_REG_SI : {
        return ZYDIS_REGISTER_SI;
    }


    case UC_X86_REG_R8W : {
        return ZYDIS_REGISTER_R8W;
    }

    case UC_X86_REG_R9W : {
        return ZYDIS_REGISTER_R9W;
    }

    case UC_X86_REG_R10W : {
        return ZYDIS_REGISTER_R10W;
    }

    case UC_X86_REG_R11W : {
        return ZYDIS_REGISTER_R11W;
    }

    case UC_X86_REG_R12W : {
        return ZYDIS_REGISTER_R12W;
    }

    case UC_X86_REG_R13W : {
        return ZYDIS_REGISTER_R13W;
    }

    case UC_X86_REG_R14W : {
        return ZYDIS_REGISTER_R14W;
    }

    case UC_X86_REG_R15W : {
        return ZYDIS_REGISTER_R15W;
    }
                            // 8BIT REGISTERS
    case UC_X86_REG_R8B : {
        return ZYDIS_REGISTER_R8B;
    }

    case UC_X86_REG_R9B : {
        return ZYDIS_REGISTER_R9B;
    }

    case UC_X86_REG_R10B : {
        return ZYDIS_REGISTER_R10B;
    }

    case UC_X86_REG_R11B : {
        return ZYDIS_REGISTER_R11B;
    }

    case UC_X86_REG_R12B : {
        return ZYDIS_REGISTER_R12B;
    }

    case UC_X86_REG_R13B : {
        return ZYDIS_REGISTER_R13B;
    }

    case UC_X86_REG_R14B : {
        return ZYDIS_REGISTER_R14B;
    }

    case UC_X86_REG_R15B : {
        return ZYDIS_REGISTER_R15B;
    }
                            // 8BIT REGISTERS LOW
    case UC_X86_REG_AL : {
        return ZYDIS_REGISTER_AL;
    }

    case UC_X86_REG_CL : {
        return ZYDIS_REGISTER_CL;
    }

    case UC_X86_REG_DL : {
        return ZYDIS_REGISTER_DL;
    }

    case UC_X86_REG_BL : {
        return ZYDIS_REGISTER_BL;
    }

    case UC_X86_REG_SPL : {
        return ZYDIS_REGISTER_SPL;
    }

    case UC_X86_REG_BPL : {
        return ZYDIS_REGISTER_BPL;
    }

    case UC_X86_REG_DIL : {
        return ZYDIS_REGISTER_DIL;
    }

    case UC_X86_REG_SIL : {
        return ZYDIS_REGISTER_SIL;
    }

    // 8BIT REGISTERS HIGH

    case UC_X86_REG_AH : {
        return ZYDIS_REGISTER_AH;
    }

    case UC_X86_REG_CH : {
        return ZYDIS_REGISTER_CH;
    }

    case UC_X86_REG_DH : {
        return ZYDIS_REGISTER_DH;
    }

    case UC_X86_REG_BH: {
        return ZYDIS_REGISTER_BH;
    }
    }

};

// parent register is when you set lower or higher byte, and you modify another register, which is parent register
// e.x.
// mov al, 15
// 
// so this operation will generate a new flag and OR with existing eax because basically it interacts with eax
// 
// in this case eax is parent register of al
// also eax and rax are parent registers of each other beacuse when u make an operation on any other changes
// so in all cases eax and rax will have same flags
// 
// set subRegister
// parentRegister |= subRegister 
//
vector<ZydisRegister> getParentRegisters(ZydisRegister reg) {
    vector<ZydisRegister> registerlist;
    switch (reg) {
        // 64BIT REGISTERS
    case ZYDIS_REGISTER_RIP: {
        registerlist.push_back(ZYDIS_REGISTER_RIP);
        return registerlist;
    }

    case ZYDIS_REGISTER_RAX: {
        registerlist.push_back(ZYDIS_REGISTER_RAX);
        return registerlist;
    }

    case ZYDIS_REGISTER_RCX: {
        registerlist.push_back(ZYDIS_REGISTER_RCX);
        return registerlist;
    }

    case ZYDIS_REGISTER_RDX: {
        registerlist.push_back(ZYDIS_REGISTER_RDX);
        return registerlist;
    }

    case ZYDIS_REGISTER_RBX: {
        registerlist.push_back(ZYDIS_REGISTER_RBX);
        return registerlist;
    }

    case ZYDIS_REGISTER_RSP: {
        registerlist.push_back(ZYDIS_REGISTER_RSP);
        return registerlist;
    }

    case ZYDIS_REGISTER_RBP: {
        registerlist.push_back(ZYDIS_REGISTER_RBP);
        return registerlist;
    }

    case ZYDIS_REGISTER_RDI: {
        registerlist.push_back(ZYDIS_REGISTER_RDI);
        return registerlist;
    }

    case ZYDIS_REGISTER_RSI: {
        registerlist.push_back(ZYDIS_REGISTER_RSI);
        return registerlist;
    }
    case ZYDIS_REGISTER_R8: {
        registerlist.push_back(ZYDIS_REGISTER_R8);
        return registerlist;
    }
    case ZYDIS_REGISTER_R9: {
        registerlist.push_back(ZYDIS_REGISTER_R9);
        return registerlist;
    }

    case ZYDIS_REGISTER_R10: {
        registerlist.push_back(ZYDIS_REGISTER_R10);
        return registerlist;
    }

    case ZYDIS_REGISTER_R11: {
        registerlist.push_back(ZYDIS_REGISTER_R11);
        return registerlist;
    }

    case ZYDIS_REGISTER_R12: {
        registerlist.push_back(ZYDIS_REGISTER_R12);
        return registerlist;
    }

    case ZYDIS_REGISTER_R13: {
        registerlist.push_back(ZYDIS_REGISTER_R13);
        return registerlist;
    }

    case ZYDIS_REGISTER_R14: {
        registerlist.push_back(ZYDIS_REGISTER_R14);
        return registerlist;
    }

    case ZYDIS_REGISTER_R15: {
        registerlist.push_back(ZYDIS_REGISTER_R15);
        return registerlist;
    }
                           // 32BIT REGISTERS
    case ZYDIS_REGISTER_EIP: {
        registerlist.push_back(ZYDIS_REGISTER_RIP);
        return registerlist;
    }

    case ZYDIS_REGISTER_EAX: {
        registerlist.push_back(ZYDIS_REGISTER_RAX);
        return registerlist;
    }

    case ZYDIS_REGISTER_ECX: {
        registerlist.push_back(ZYDIS_REGISTER_RCX);
        return registerlist;
    }

    case ZYDIS_REGISTER_EDX: {
        registerlist.push_back(ZYDIS_REGISTER_RDX);
        return registerlist;
    }

    case ZYDIS_REGISTER_EBX: {
        registerlist.push_back(ZYDIS_REGISTER_RBX);
        return registerlist;
    }

    case ZYDIS_REGISTER_ESP: {
        registerlist.push_back(ZYDIS_REGISTER_RSP);
        return registerlist;
    }

    case ZYDIS_REGISTER_EBP: {
        registerlist.push_back(ZYDIS_REGISTER_RBP);
        return registerlist;
    }

    case ZYDIS_REGISTER_EDI: {
        registerlist.push_back(ZYDIS_REGISTER_RDI);
        return registerlist;
    }

    case ZYDIS_REGISTER_ESI: {
        registerlist.push_back(ZYDIS_REGISTER_RSI);
        return registerlist;
    }

    case ZYDIS_REGISTER_R8D: {
        registerlist.push_back(ZYDIS_REGISTER_R8);
        return registerlist;
    }

    case ZYDIS_REGISTER_R9D: {
        registerlist.push_back(ZYDIS_REGISTER_R9);
        return registerlist;
    }

    case ZYDIS_REGISTER_R10D: {
        registerlist.push_back(ZYDIS_REGISTER_R10);
        return registerlist;
    }

    case ZYDIS_REGISTER_R11D: {
        registerlist.push_back(ZYDIS_REGISTER_R11);
        return registerlist;
    }

    case ZYDIS_REGISTER_R12D: {
        registerlist.push_back(ZYDIS_REGISTER_R12);
        return registerlist;
    }

    case ZYDIS_REGISTER_R13D: {
        registerlist.push_back(ZYDIS_REGISTER_R13);
        return registerlist;
    }

    case ZYDIS_REGISTER_R14D: {
        registerlist.push_back(ZYDIS_REGISTER_R14);
        return registerlist;
    }

    case ZYDIS_REGISTER_R15D: {
        registerlist.push_back(ZYDIS_REGISTER_R15);
        return registerlist;
    }
                            // 16BIT REGISTERS
    case ZYDIS_REGISTER_IP: {
        registerlist.push_back(ZYDIS_REGISTER_EIP);
        registerlist.push_back(ZYDIS_REGISTER_RIP);
        return registerlist;
    }

    case ZYDIS_REGISTER_AX: {
        registerlist.push_back(ZYDIS_REGISTER_EAX);
        registerlist.push_back(ZYDIS_REGISTER_RAX);
        return registerlist;
    }

    case ZYDIS_REGISTER_CX: {
        registerlist.push_back(ZYDIS_REGISTER_ECX);
        registerlist.push_back(ZYDIS_REGISTER_RCX);
        return registerlist;
    }

    case ZYDIS_REGISTER_DX: {
        registerlist.push_back(ZYDIS_REGISTER_EDX);
        registerlist.push_back(ZYDIS_REGISTER_RDX);
        return registerlist;
    }

    case ZYDIS_REGISTER_BX: {
        registerlist.push_back(ZYDIS_REGISTER_EBX);
        registerlist.push_back(ZYDIS_REGISTER_RBX);
        return registerlist;
    }

    case ZYDIS_REGISTER_SP: {
        registerlist.push_back(ZYDIS_REGISTER_ESP);
        registerlist.push_back(ZYDIS_REGISTER_RSP);
        return registerlist;
    }

    case ZYDIS_REGISTER_BP: {
        registerlist.push_back(ZYDIS_REGISTER_EBP);
        registerlist.push_back(ZYDIS_REGISTER_RBP);
        return registerlist;
    }

    case ZYDIS_REGISTER_DI: {
        registerlist.push_back(ZYDIS_REGISTER_EDI);
        registerlist.push_back(ZYDIS_REGISTER_RDI);
        return registerlist;
    }

    case ZYDIS_REGISTER_SI: {
        registerlist.push_back(ZYDIS_REGISTER_ESI);
        registerlist.push_back(ZYDIS_REGISTER_RSI);
        return registerlist;
    }

    case ZYDIS_REGISTER_R8W: {

        registerlist.push_back(ZYDIS_REGISTER_R8D);
        registerlist.push_back(ZYDIS_REGISTER_R8);
        return registerlist;
    }

    case ZYDIS_REGISTER_R9W: {
        registerlist.push_back(ZYDIS_REGISTER_R9D);
        registerlist.push_back(ZYDIS_REGISTER_R9);
        return registerlist;
    }

    case ZYDIS_REGISTER_R10W: {
        registerlist.push_back(ZYDIS_REGISTER_R10D);
        registerlist.push_back(ZYDIS_REGISTER_R10);
        return registerlist;
    }

    case ZYDIS_REGISTER_R11W: {
        registerlist.push_back(ZYDIS_REGISTER_R11D);
        registerlist.push_back(ZYDIS_REGISTER_R11);
        return registerlist;
    }

    case ZYDIS_REGISTER_R12W: {
        registerlist.push_back(ZYDIS_REGISTER_R12D);
        registerlist.push_back(ZYDIS_REGISTER_R12);
        return registerlist;
    }

    case ZYDIS_REGISTER_R13W: {
        registerlist.push_back(ZYDIS_REGISTER_R13D);
        registerlist.push_back(ZYDIS_REGISTER_R13);
        return registerlist;
    }

    case ZYDIS_REGISTER_R14W: {
        registerlist.push_back(ZYDIS_REGISTER_R14D);
        registerlist.push_back(ZYDIS_REGISTER_R14);
        return registerlist;
    }

    case ZYDIS_REGISTER_R15W: {
        registerlist.push_back(ZYDIS_REGISTER_R15D);
        registerlist.push_back(ZYDIS_REGISTER_R15);
        return registerlist;
    }
                            // 8BIT REGISTERS
    case ZYDIS_REGISTER_R8B: {
        registerlist.push_back(ZYDIS_REGISTER_R8W);
        registerlist.push_back(ZYDIS_REGISTER_R8D);
        registerlist.push_back(ZYDIS_REGISTER_R8);
        return registerlist;
    }

    case ZYDIS_REGISTER_R9B: {
        registerlist.push_back(ZYDIS_REGISTER_R9W);
        registerlist.push_back(ZYDIS_REGISTER_R9D);
        registerlist.push_back(ZYDIS_REGISTER_R9);
        return registerlist;
    }

    case ZYDIS_REGISTER_R10B: {
        registerlist.push_back(ZYDIS_REGISTER_R10W);
        registerlist.push_back(ZYDIS_REGISTER_R10D);
        registerlist.push_back(ZYDIS_REGISTER_R10);
        return registerlist;
    }

    case ZYDIS_REGISTER_R11B: {
        registerlist.push_back(ZYDIS_REGISTER_R11W);
        registerlist.push_back(ZYDIS_REGISTER_R11D);
        registerlist.push_back(ZYDIS_REGISTER_R11);
        return registerlist;
    }

    case ZYDIS_REGISTER_R12B: {
        registerlist.push_back(ZYDIS_REGISTER_R12W);
        registerlist.push_back(ZYDIS_REGISTER_R12D);
        registerlist.push_back(ZYDIS_REGISTER_R12);
        return registerlist;
    }

    case ZYDIS_REGISTER_R13B: {
        registerlist.push_back(ZYDIS_REGISTER_R13W);
        registerlist.push_back(ZYDIS_REGISTER_R13D);
        registerlist.push_back(ZYDIS_REGISTER_R13);
        return registerlist;
    }

    case ZYDIS_REGISTER_R14B: {
        registerlist.push_back(ZYDIS_REGISTER_R14W);
        registerlist.push_back(ZYDIS_REGISTER_R14D);
        registerlist.push_back(ZYDIS_REGISTER_R14);
        return registerlist;
    }

    case ZYDIS_REGISTER_R15B: {
        registerlist.push_back(ZYDIS_REGISTER_R15W);
        registerlist.push_back(ZYDIS_REGISTER_R15D);
        registerlist.push_back(ZYDIS_REGISTER_R15);
        return registerlist;
    }
                            // 8BIT REGISTERS LOW
    case ZYDIS_REGISTER_AL: {
        registerlist.push_back(ZYDIS_REGISTER_AX);
        registerlist.push_back(ZYDIS_REGISTER_EAX);
        registerlist.push_back(ZYDIS_REGISTER_RAX);
        return registerlist;
    }

    case ZYDIS_REGISTER_CL: {
        registerlist.push_back(ZYDIS_REGISTER_CX);
        registerlist.push_back(ZYDIS_REGISTER_ECX);
        registerlist.push_back(ZYDIS_REGISTER_RCX);
        return registerlist;
    }

    case ZYDIS_REGISTER_DL: {
        registerlist.push_back(ZYDIS_REGISTER_DX);
        registerlist.push_back(ZYDIS_REGISTER_EDX);
        registerlist.push_back(ZYDIS_REGISTER_RDX);
        return registerlist;
    }

    case ZYDIS_REGISTER_BL: {
        registerlist.push_back(ZYDIS_REGISTER_BX);
        registerlist.push_back(ZYDIS_REGISTER_EBX);
        registerlist.push_back(ZYDIS_REGISTER_RBX);
        return registerlist;
    }

    case ZYDIS_REGISTER_SPL: {
        registerlist.push_back(ZYDIS_REGISTER_SP);
        registerlist.push_back(ZYDIS_REGISTER_ESP);
        registerlist.push_back(ZYDIS_REGISTER_RSP);
        return registerlist;
    }

    case ZYDIS_REGISTER_BPL: {
        registerlist.push_back(ZYDIS_REGISTER_BP);
        registerlist.push_back(ZYDIS_REGISTER_EBP);
        registerlist.push_back(ZYDIS_REGISTER_RBP);
        return registerlist;
    }

    case ZYDIS_REGISTER_DIL: {
        registerlist.push_back(ZYDIS_REGISTER_DI);
        registerlist.push_back(ZYDIS_REGISTER_EDI);
        registerlist.push_back(ZYDIS_REGISTER_RDI);
        return registerlist;
    }

    case ZYDIS_REGISTER_SIL: {
        registerlist.push_back(ZYDIS_REGISTER_SI);
        registerlist.push_back(ZYDIS_REGISTER_ESI);
        registerlist.push_back(ZYDIS_REGISTER_RSI);
        return registerlist;
    }
                           // 8BIT REGISTERS HIGH
    case ZYDIS_REGISTER_AH: {
        registerlist.push_back(ZYDIS_REGISTER_AX);
        registerlist.push_back(ZYDIS_REGISTER_EAX);
        registerlist.push_back(ZYDIS_REGISTER_RAX);
        return registerlist;
    }

    case ZYDIS_REGISTER_CH: {
        registerlist.push_back(ZYDIS_REGISTER_CX);
        registerlist.push_back(ZYDIS_REGISTER_ECX);
        registerlist.push_back(ZYDIS_REGISTER_RCX);
        return registerlist;
    }

    case ZYDIS_REGISTER_DH: {
        registerlist.push_back(ZYDIS_REGISTER_DX);
        registerlist.push_back(ZYDIS_REGISTER_EDX);
        registerlist.push_back(ZYDIS_REGISTER_RDX);
        return registerlist;
    }

    case ZYDIS_REGISTER_BH: {
        registerlist.push_back(ZYDIS_REGISTER_BX);
        registerlist.push_back(ZYDIS_REGISTER_EBX);
        registerlist.push_back(ZYDIS_REGISTER_RBX);
        return registerlist;
    }
    }
    return registerlist; // Return an empty list if no matching register is found
}


// sub register is when you set a register, and lower byte registers also get effected
// e.x.
// mov eax, 15
// in this case al/ah is sub register of eax
// because of that al/ah will have flag of eax
// 
// set parentRegister
// subRegisters = parentRegister
//
vector<ZydisRegister> getSubRegisters(ZydisRegister reg) {
    vector<ZydisRegister> registerlist;
    registerlist.clear();
    switch (reg) {
        // 64BIT REGISTERS
                // 64BIT REGISTERS
    case ZYDIS_REGISTER_RIP: {

        return registerlist;
    }

    case ZYDIS_REGISTER_RAX: {
        registerlist.push_back(ZYDIS_REGISTER_EAX);
        registerlist.push_back(ZYDIS_REGISTER_AX);
        registerlist.push_back(ZYDIS_REGISTER_AL);
        registerlist.push_back(ZYDIS_REGISTER_AH);
        return registerlist;
    }

    case ZYDIS_REGISTER_RCX: {
       
        registerlist.push_back(ZYDIS_REGISTER_ECX);
        registerlist.push_back(ZYDIS_REGISTER_CX);
        registerlist.push_back(ZYDIS_REGISTER_CL);
        registerlist.push_back(ZYDIS_REGISTER_CH);
        return registerlist;
    }

    case ZYDIS_REGISTER_RDX: {
        registerlist.push_back(ZYDIS_REGISTER_EDX);
        registerlist.push_back(ZYDIS_REGISTER_DX);
        registerlist.push_back(ZYDIS_REGISTER_DL);
        registerlist.push_back(ZYDIS_REGISTER_DH);
        return registerlist;
    }

    case ZYDIS_REGISTER_RBX: {
        registerlist.push_back(ZYDIS_REGISTER_EBX);
        registerlist.push_back(ZYDIS_REGISTER_BX);
        registerlist.push_back(ZYDIS_REGISTER_BL);
        registerlist.push_back(ZYDIS_REGISTER_BH);
        return registerlist;
    }

    case ZYDIS_REGISTER_RSP: {
        registerlist.push_back(ZYDIS_REGISTER_ESP);
        registerlist.push_back(ZYDIS_REGISTER_SP);
        registerlist.push_back(ZYDIS_REGISTER_SPL);
        return registerlist;
    }

    case ZYDIS_REGISTER_RBP: {
        registerlist.push_back(ZYDIS_REGISTER_EBP);
        registerlist.push_back(ZYDIS_REGISTER_BP);
        registerlist.push_back(ZYDIS_REGISTER_BPL);
        return registerlist;
    }

    case ZYDIS_REGISTER_RDI: {
        registerlist.push_back(ZYDIS_REGISTER_EDI);
        registerlist.push_back(ZYDIS_REGISTER_DI);
        registerlist.push_back(ZYDIS_REGISTER_DIL);
        return registerlist;
    }

    case ZYDIS_REGISTER_RSI: {
        registerlist.push_back(ZYDIS_REGISTER_ESI);
        registerlist.push_back(ZYDIS_REGISTER_SI);
        registerlist.push_back(ZYDIS_REGISTER_SIL);
        return registerlist;
    }
    case ZYDIS_REGISTER_R8: {
        registerlist.push_back(ZYDIS_REGISTER_R8D);
        registerlist.push_back(ZYDIS_REGISTER_R8W);
        registerlist.push_back(ZYDIS_REGISTER_R8B);
        return registerlist;
    }
    case ZYDIS_REGISTER_R9: {
        registerlist.push_back(ZYDIS_REGISTER_R9D);
        registerlist.push_back(ZYDIS_REGISTER_R9W);
        registerlist.push_back(ZYDIS_REGISTER_R9B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R10: {
        registerlist.push_back(ZYDIS_REGISTER_R10D);
        registerlist.push_back(ZYDIS_REGISTER_R10W);
        registerlist.push_back(ZYDIS_REGISTER_R10B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R11: {
        registerlist.push_back(ZYDIS_REGISTER_R11D);
        registerlist.push_back(ZYDIS_REGISTER_R11W);
        registerlist.push_back(ZYDIS_REGISTER_R11B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R12: {
        registerlist.push_back(ZYDIS_REGISTER_R12D);
        registerlist.push_back(ZYDIS_REGISTER_R12W);
        registerlist.push_back(ZYDIS_REGISTER_R12B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R13: {
        registerlist.push_back(ZYDIS_REGISTER_R13D);
        registerlist.push_back(ZYDIS_REGISTER_R13W);
        registerlist.push_back(ZYDIS_REGISTER_R13B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R14: {
        registerlist.push_back(ZYDIS_REGISTER_R14D);
        registerlist.push_back(ZYDIS_REGISTER_R14W);
        registerlist.push_back(ZYDIS_REGISTER_R14B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R15: {



        registerlist.push_back(ZYDIS_REGISTER_R15D);
        registerlist.push_back(ZYDIS_REGISTER_R15W);
        registerlist.push_back(ZYDIS_REGISTER_R15B);
        return registerlist;
    }
                           // 32BIT REGISTERS
    case ZYDIS_REGISTER_EIP: {
        return registerlist;
    }

    case ZYDIS_REGISTER_EAX: {
        registerlist.push_back(ZYDIS_REGISTER_RAX);
        registerlist.push_back(ZYDIS_REGISTER_AX);

        registerlist.push_back(ZYDIS_REGISTER_AL);
        registerlist.push_back(ZYDIS_REGISTER_AH);
        return registerlist;
    }

    case ZYDIS_REGISTER_ECX: {
        registerlist.push_back(ZYDIS_REGISTER_RCX);
        registerlist.push_back(ZYDIS_REGISTER_CX);

        registerlist.push_back(ZYDIS_REGISTER_CL);
        registerlist.push_back(ZYDIS_REGISTER_CH);
        return registerlist;
    }

    case ZYDIS_REGISTER_EDX: {
        registerlist.push_back(ZYDIS_REGISTER_RDX);
        registerlist.push_back(ZYDIS_REGISTER_DX);

        registerlist.push_back(ZYDIS_REGISTER_DL);
        registerlist.push_back(ZYDIS_REGISTER_DH);
        return registerlist;
    }

    case ZYDIS_REGISTER_EBX: {
        registerlist.push_back(ZYDIS_REGISTER_RBX);
        registerlist.push_back(ZYDIS_REGISTER_BX);

        registerlist.push_back(ZYDIS_REGISTER_BL);
        registerlist.push_back(ZYDIS_REGISTER_BH);
        return registerlist;
    }

    case ZYDIS_REGISTER_ESP: {
        registerlist.push_back(ZYDIS_REGISTER_RSP);
        registerlist.push_back(ZYDIS_REGISTER_SP);

        registerlist.push_back(ZYDIS_REGISTER_SPL);
        return registerlist;
    }

    case ZYDIS_REGISTER_EBP: {
        registerlist.push_back(ZYDIS_REGISTER_RBP);
        registerlist.push_back(ZYDIS_REGISTER_BP);

        registerlist.push_back(ZYDIS_REGISTER_BPL);
        return registerlist;
    }

    case ZYDIS_REGISTER_EDI: {
        registerlist.push_back(ZYDIS_REGISTER_RDI);
        registerlist.push_back(ZYDIS_REGISTER_DI);

        registerlist.push_back(ZYDIS_REGISTER_DIL);
        return registerlist;
    }

    case ZYDIS_REGISTER_ESI: {
        registerlist.push_back(ZYDIS_REGISTER_RSI);
        registerlist.push_back(ZYDIS_REGISTER_SI);

        registerlist.push_back(ZYDIS_REGISTER_SIL);
        return registerlist;
    }


    case ZYDIS_REGISTER_R8D: {
        registerlist.push_back(ZYDIS_REGISTER_R8);
        registerlist.push_back(ZYDIS_REGISTER_R8W);
        registerlist.push_back(ZYDIS_REGISTER_R8B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R9D: {
        registerlist.push_back(ZYDIS_REGISTER_R9);
        registerlist.push_back(ZYDIS_REGISTER_R9W);
        registerlist.push_back(ZYDIS_REGISTER_R9B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R10D: {
        registerlist.push_back(ZYDIS_REGISTER_R10);
        registerlist.push_back(ZYDIS_REGISTER_R10W);
        registerlist.push_back(ZYDIS_REGISTER_R10B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R11D: {
        registerlist.push_back(ZYDIS_REGISTER_R11);
        registerlist.push_back(ZYDIS_REGISTER_R11W);
        registerlist.push_back(ZYDIS_REGISTER_R11B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R12D: {
        registerlist.push_back(ZYDIS_REGISTER_R12);
        registerlist.push_back(ZYDIS_REGISTER_R12W);
        registerlist.push_back(ZYDIS_REGISTER_R12B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R13D: {
        registerlist.push_back(ZYDIS_REGISTER_R13);
        registerlist.push_back(ZYDIS_REGISTER_R13W);
        registerlist.push_back(ZYDIS_REGISTER_R13B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R14D: {
        registerlist.push_back(ZYDIS_REGISTER_R14);
        registerlist.push_back(ZYDIS_REGISTER_R14W);
        registerlist.push_back(ZYDIS_REGISTER_R14B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R15D: {
        registerlist.push_back(ZYDIS_REGISTER_R15);
        registerlist.push_back(ZYDIS_REGISTER_R15W);
        registerlist.push_back(ZYDIS_REGISTER_R15B);
        return registerlist;
    }

                            // 16BIT REGISTERS

    case ZYDIS_REGISTER_IP: {
        return registerlist;
    }

    case ZYDIS_REGISTER_AX: {

        registerlist.push_back(ZYDIS_REGISTER_AL);
        registerlist.push_back(ZYDIS_REGISTER_AH);
        return registerlist;
    }

    case ZYDIS_REGISTER_CX: {

        registerlist.push_back(ZYDIS_REGISTER_CL);
        registerlist.push_back(ZYDIS_REGISTER_CH);
        return registerlist;
    }

    case ZYDIS_REGISTER_DX: {

        registerlist.push_back(ZYDIS_REGISTER_DL);
        registerlist.push_back(ZYDIS_REGISTER_DH);
        return registerlist;
    }

    case ZYDIS_REGISTER_BX: {

        registerlist.push_back(ZYDIS_REGISTER_BL);
        registerlist.push_back(ZYDIS_REGISTER_BH);
        return registerlist;
    }

    case ZYDIS_REGISTER_SP: {

        registerlist.push_back(ZYDIS_REGISTER_SPL);
        return registerlist;
    }

    case ZYDIS_REGISTER_BP: {

        registerlist.push_back(ZYDIS_REGISTER_BPL);
        return registerlist;
    }

    case ZYDIS_REGISTER_DI: {

        registerlist.push_back(ZYDIS_REGISTER_DIL);
        return registerlist;
    }

    case ZYDIS_REGISTER_SI: {

        registerlist.push_back(ZYDIS_REGISTER_SIL);
        return registerlist;
    }


    case ZYDIS_REGISTER_R8W: {

        registerlist.push_back(ZYDIS_REGISTER_R8B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R9W: {
        registerlist.push_back(ZYDIS_REGISTER_R9B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R10W: {
        registerlist.push_back(ZYDIS_REGISTER_R10B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R11W: {
        registerlist.push_back(ZYDIS_REGISTER_R11B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R12W: {
        registerlist.push_back(ZYDIS_REGISTER_R12B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R13W: {
        registerlist.push_back(ZYDIS_REGISTER_R13B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R14W: {
        registerlist.push_back(ZYDIS_REGISTER_R14B);
        return registerlist;
    }

    case ZYDIS_REGISTER_R15W: {
        registerlist.push_back(ZYDIS_REGISTER_R15B);
        return registerlist;
    }
                            // 8BIT REGISTERS
    case ZYDIS_REGISTER_R8B: {
        return registerlist;
    }

    case ZYDIS_REGISTER_R9B: {
        return registerlist;
    }

    case ZYDIS_REGISTER_R10B: {
        return registerlist;
    }

    case ZYDIS_REGISTER_R11B: {
        return registerlist;
    }

    case ZYDIS_REGISTER_R12B: {
        return registerlist;
    }

    case ZYDIS_REGISTER_R13B: {
        return registerlist;
    }

    case ZYDIS_REGISTER_R14B: {
        return registerlist;
    }

    case ZYDIS_REGISTER_R15B: {
        return registerlist;
    }
                            // 8BIT REGISTERS LOW
    case ZYDIS_REGISTER_AL: {
        return registerlist;
    }

    case ZYDIS_REGISTER_CL: {
        return registerlist;
    }

    case ZYDIS_REGISTER_DL: {
        return registerlist;
    }

    case ZYDIS_REGISTER_BL: {
        return registerlist;
    }

    case ZYDIS_REGISTER_SPL: {
        return registerlist;
    }

    case ZYDIS_REGISTER_BPL: {
        return registerlist;
    }

    case ZYDIS_REGISTER_DIL: {
        return registerlist;
    }

    case ZYDIS_REGISTER_SIL: {
        return registerlist;
    }

                           // 8BIT REGISTERS HIGH

    case ZYDIS_REGISTER_AH: {
        return registerlist;
    }

    case ZYDIS_REGISTER_CH: {
        return registerlist;
    }

    case ZYDIS_REGISTER_DH: {
        return registerlist;
    }

    case ZYDIS_REGISTER_BH: {
        return registerlist;
    }
    }


}

