#pragma once

#define FLAGSET 100000

#include "Includes.h"
#include "RegisterStuff.h"

class TaintEngine {
private:

    //initial plan was only having memoryTaintStatus and registerTaintStatus and I wanted to handle both deadstore and constant decryption using these. 
    // However since there are more bugs like major problem1 and 2 (just ctrl + f it)
    // I think only way to solve it is creating parallel maps

    std::unordered_map<ZydisRegister, bitset<FLAGSET> > registerTaintStatus;
    std::unordered_map<uintptr_t, bitset<FLAGSET> > memoryTaintStatus;


    std::unordered_map<ZydisRegister, bitset<FLAGSET> > registerTaintStatus_decrypt;
    std::unordered_map<uintptr_t, bitset<FLAGSET> > memoryTaintStatus_decrypt;




    ZydisEncoderRequest req; int value; uintptr_t memval;
    bitset<FLAGSET> destTaint;
    bitset<FLAGSET> srcTaint;
    bitset<FLAGSET> empty;

    bitset<FLAGSET> regFlag;
    ZydisDecodedOperand srcOp;

    uc_engine* new_uc;
    ZydisDecodedOperand destOp;
public:

    int lastTaint = 0;
    int firstTaints = 0;
    TaintEngine(bool experimental = 0) {

        TaintRegister(ZYDIS_REGISTER_RAX);


        if (!experimental)
            TaintRegister(ZYDIS_REGISTER_RSP);

        TaintRegister(ZYDIS_REGISTER_RDX);

        TaintRegister(ZYDIS_REGISTER_RCX);

        TaintRegister(ZYDIS_REGISTER_RBX);
        TaintRegister(ZYDIS_REGISTER_RBP);
        TaintRegister(ZYDIS_REGISTER_RSI);
        TaintRegister(ZYDIS_REGISTER_RDI);
        TaintRegister(ZYDIS_REGISTER_R8);
        TaintRegister(ZYDIS_REGISTER_R9);
        TaintRegister(ZYDIS_REGISTER_R10);
        TaintRegister(ZYDIS_REGISTER_R11);
        TaintRegister(ZYDIS_REGISTER_R12);
        TaintRegister(ZYDIS_REGISTER_R13);
        TaintRegister(ZYDIS_REGISTER_R14);
        TaintRegister(ZYDIS_REGISTER_R15);


        firstTaints = lastTaint ;
        registerTaintStatus_decrypt = registerTaintStatus;

    }

    void clone_uc_mem_state(uc_engine* uc) {

        uc_mem_region* regions;
        uint32_t count;
        if (uc_mem_regions(uc, &regions, &count) != UC_ERR_OK) {
            printf("Failed to get memory regions\n");
            return;
        }

        for (uint32_t i = 0; i < count; i++) {
            uint64_t base = regions[i].begin;
            uint64_t size = regions[i].end - regions[i].begin + 1;
            std::vector<char> buffer(size);

            if (uc_mem_read(uc, base, buffer.data(), size) != UC_ERR_OK) {
                printf("Failed to read memory region\n");
                return;
            }

            if (uc_mem_write(new_uc, base, buffer.data(), size) != UC_ERR_OK) {
                printf("Failed to write memory region\n");
                return;
            }
        }

        free(regions);
    }

    void clone_uc_State(uc_engine* uc) {
        auto err = uc_open(UC_ARCH_X86, UC_MODE_64, &new_uc);
        if (err != UC_ERR_OK) {
            printf("Failed on uc_open() with error returned: %u\n", err);
            return;
        }
        uc_mem_region* regions;
        uint32_t count;
        if (uc_mem_regions(uc, &regions, &count) != UC_ERR_OK) {
            printf("Failed to get memory regions\n");
            return;
        }

        for (uint32_t i = 0; i < count; i++) {
            uint64_t base = regions[i].begin;
            uint64_t size = regions[i].end - regions[i].begin + 1;
            std::vector<char> buffer(size);

            if (uc_mem_read(uc, base, buffer.data(), size) != UC_ERR_OK) {
                printf("Failed to read memory region\n");
                return;
            }

            if (uc_mem_map(new_uc, base, size, regions[i].perms) != UC_ERR_OK) {
                printf("Failed to map memory region\n");
                return;
            }

            if (uc_mem_write(new_uc, base, buffer.data(), size) != UC_ERR_OK) {
                printf("Failed to write memory region\n");
                return;
            }
        }

        free(regions);
    }

    bitset<FLAGSET> getNewTaint() {
        bitset<FLAGSET> newTaint;
        newTaint.reset();
        newTaint[lastTaint + 1] = 1;

        lastTaint++;
        return newTaint;
    }

    bitset<FLAGSET> TaintRegister(ZydisRegister Register) {
        registerTaintStatus[Register].reset();
        registerTaintStatus[Register].set(lastTaint + 1);

        for (auto reg : getSubRegisters(Register)) {

            registerTaintStatus[reg].reset();
            registerTaintStatus[reg].set(lastTaint + 1);
        }

        lastTaint++;
        return (registerTaintStatus[Register]);
    }

    bitset<FLAGSET> TaintMemory(uintptr_t MemoryAddress) {
        memoryTaintStatus[MemoryAddress].reset();
        memoryTaintStatus[MemoryAddress].set(lastTaint + 1);
        lastTaint++;
        return memoryTaintStatus[MemoryAddress];
    }


    void propagateTaintRegister_decrypt(ZydisRegister destRegister, bitset<FLAGSET>& flag)
    {

        registerTaintStatus_decrypt[destRegister].reset();
        registerTaintStatus_decrypt[destRegister] = flag;
        auto parentRegisters = getParentRegisters(destRegister);
        for (auto reg : parentRegisters) {

            registerTaintStatus_decrypt[reg].reset();
            registerTaintStatus_decrypt[reg] = flag;
        }

        for (auto reg : getSubRegisters(destRegister)) {

            registerTaintStatus_decrypt[reg].reset();
            registerTaintStatus_decrypt[reg] = flag;
        }

    }
    void propagateTaintMemory_decrypt(uintptr_t destMemory, std::bitset<FLAGSET>& flag)
    {

        memoryTaintStatus_decrypt[destMemory].reset();
        memoryTaintStatus_decrypt[destMemory] = flag;
    }
    
    void propagateTaintRegister(ZydisRegister destRegister, bitset<FLAGSET>& flag)
    {

        registerTaintStatus[destRegister].reset();
        registerTaintStatus[destRegister] = flag;
        auto parentRegisters = getParentRegisters(destRegister);
        for (auto reg : parentRegisters) {

            registerTaintStatus[reg].reset();
            registerTaintStatus[reg] = flag;
        }

        for (auto reg : getSubRegisters(destRegister)) {

            registerTaintStatus[reg].reset();
            registerTaintStatus[reg] = flag;
        }

    }
    void propagateTaintMemory(uintptr_t destMemory, std::bitset<FLAGSET>& flag)
    {

        memoryTaintStatus[destMemory].reset();
        memoryTaintStatus[destMemory] = flag;
    }


    size_t getTaintHash(const bitset<FLAGSET>& Vector) {
        hash<bitset<FLAGSET>> hashFunc;

        // RETURN TAINT FLAG
        std::size_t newTaint_hash = hashFunc(Vector);

        return newTaint_hash;
    }

    int first16(const std::bitset<FLAGSET>& bits) {
        for (int i = 0; i < firstTaints; ++i) {
            if (bits[i]) {
                return i;
            }
        }
        return 0;
    }


    std::bitset<FLAGSET>& getRegisterTaint(ZydisRegister Register) {
        if (Register == ZYDIS_REGISTER_NONE)
            return empty;

        return (registerTaintStatus[Register]);

    }

    std::bitset<FLAGSET>& getMemoryTaint(uintptr_t MemoryAddress) {
        if (memoryTaintStatus.contains(MemoryAddress)) {
            return (memoryTaintStatus[MemoryAddress]);
        }
        return (empty);
    }
        
    std::bitset<FLAGSET>& getRegisterTaint_decrypt(ZydisRegister Register) {
        if (Register == ZYDIS_REGISTER_NONE)
            return empty;

        return (registerTaintStatus_decrypt[Register]);

    }

    std::bitset<FLAGSET>& getMemoryTaint_decrypt(uintptr_t MemoryAddress) {
        if (memoryTaintStatus_decrypt.contains(MemoryAddress)) {
            return (memoryTaintStatus_decrypt[MemoryAddress]);
        }
        return (empty);
    }


    uintptr_t readAddress(uintptr_t address, uintptr_t size, uc_engine* uc) {
        uintptr_t val;

        uc_mem_read(uc, address, &val, size);

        return val;
    }

    uintptr_t getAddress(ZydisDecodedOperand Op, uc_engine* uc) {
        auto base = Op.mem.base;
        auto base_uc = (uc_x86_reg)zydis2Unicorn(base);
        uintptr_t memval;


        uc_reg_read(uc, base_uc, &memval);

        auto indexreg = Op.mem.index;
        if (indexreg != ZYDIS_REGISTER_NONE) {
            int indexval;
            uc_reg_read(uc, (uc_x86_reg)zydis2Unicorn(indexreg), &indexval);
            memval += indexval;
        }

        auto disp = Op.mem.disp.value;

        memval += disp;

        return memval;
    }

    uintptr_t getStackPointer(uc_engine* uc) {

        uintptr_t sp;
        uc_reg_read(uc, UC_X86_REG_RSP, &sp);

        return sp;
    }

    bool isInFlag(const std::bitset<FLAGSET>& bool1, const std::bitset<FLAGSET>& bool2) {

        return (bool1 & bool2).any();
    }

    bool its1On1but0On2(const std::bitset<FLAGSET>& bool1, const std::bitset<FLAGSET>& bool2) {
        for (size_t i = 0; i < 100000; i++) {
            if (bool1[i] && !bool2[i]) {
                return 1;  // Add the value of the flag to the number
            }
        }
        return 0;
    }


    std::bitset<FLAGSET> orFlags(const std::bitset<FLAGSET>& bool1, const std::bitset<FLAGSET>& bool2) {
        return (bool1 | bool2);
    }


    int getVisibleNumber(vector<bool> flags) {
        int number = 0;
        for (size_t i = 0; i < flags.size(); ++i) {
            if (flags[i]) {
                number += (1 << i);  // Add the value of the flag to the number
            }
        }
        return number;
    }

    void printTrueBits(const std::bitset<FLAGSET>& bitset) {
        for (size_t i = 0; i < bitset.size(); i++) {
            if (bitset[i]) {
                cout << i << " ,";
            }
        }
        cout << "\n";
    }

    ZydisDisassembledInstruction* handleInstruction(ZydisDisassembledInstruction* inst, uc_engine* uc, bitset<FLAGSET>& newTaint, uintptr_t rip, std::vector<ZyanU8>* bytes) {

        srcOp = inst->operands[1];
        destOp = inst->operands[0];
        // THE IDEA:
        // we create unique flags for each register and for each instruction whey will interact with each other.
        // example if operand 0 is read/write and operand 1 is read, then new flag will be flag_0|flag_1
        // and we apply this to the instruction, so we can check which flags are being used at the end and remove excess ones.
        // 
        // 
        // 
        // if operand.actions && ZYDIS_OPERAND_ACTION_READ then we read that flag
        // if operand.actions && ZYDIS_OPERAND_ACTION_WRITE then we move the flag to that operand
        // 
        // 
        //
        // xchg op0, op1
        // new_op0 = op1 | unique_inst_flag0;
        // new_op1 = op0 | unique_inst_flag0;
        // op0 = new_op0; 
        // op1 = new_op1;
        // instflag0 = op0 | op1;
        // 
        // 
        // add op0, op1
        // op0 = op1 | op0 | unique_inst_flag1;
        // instflag1 = op0;
        // 
        // mov op0, op1
        // op0 = op1 | unique_inst_flag2;
        // instflag = op0;
        // 
        // in the end, op0 will only have  op0 | unique_inst_flag0 | unique_inst_flag2 and since add has extra flag, unique_inst_flag1 we remove it.
        // 
        // problem:
        // there are some functions that act differently, like below under corner case instructions. xchg is read/write for both operands, but problem is its not like add, where both operands value is written to one operand. Instead they switch.
        // 
        // xchg should switch flags, not OR both flags and write same flag to both. however the instruction flag should be OR of both flags.
        // 
        // major problem1:
        // push has 3 operands, which 2 is hidden.
        // ex:
        // push rax
        // 
        // operand 0: rax
        // operand 1: rsp
        // operand 2: [rsp]
        // 
        // we need to act push rax as if its 
        // sub rsp, 8
        // mov [rsp], rax
        // 
        // 
        // 
        // 
        // 
        // 
        // 
        // 
        // 
        // major problem2:
        // in this instruction:
        //  mov rax, [rsp + rcx]
        // we also need to apply rsp and rcx flag to rax and the instruction so the instructions before that modifies rcx is doesnt seen as extra. 
        // However rsp can be unique, but memory in rsp + rcx might be a constant. In that case we should only care about the memory taint
        // 
        // mov rcx, 8
        // push rdx
        // mov rax, [rsp + rcx] 
        // if we dont spread rcx, 'mov rcx, 8' will be lost.
        // 
        // also
        //  mov [rsp + rcx], rax we need to apply same logic idk rly
        // 
        // actual problem is
        // 
        // mov r8, 0x1337
        // mov esi, 0x7331
        // push r8
        // xor [rsp], esi
        // pop r8
        // mov ecx, 30
        // xor cx, r8d // this should be a constant and resolved automatically.
        // 
        // 
        // 
        // 
        // 
        // 
        // another problem is
        //  please do not read anything in write operand loop, or if ur gonna do u need to create another for loop for reading it bcuz we will miss some taints while reading/writing it.
        // 
        // corner case instructions:
        // xchg - switch two flags with each other - done
        // push - dont flag rsp 
        // pop - dont flag rsp 
        // ret  
        //
        newTaint |= getNewTaint();
        regFlag = empty;
        memval = 0;
        auto holdTaint = newTaint;

        auto decryptTaint = newTaint;

        auto rspTaint = newTaint;

        bitset<FLAGSET> memTaint;

        if (inst->info.meta.branch_type != 0) {

            switch (inst->info.mnemonic) {
                // TODO

            case ZYDIS_MNEMONIC_RET:
            case ZYDIS_MNEMONIC_CALL: {

                if (inst->info.mnemonic == ZYDIS_MNEMONIC_CALL)
                    req.mnemonic = ZYDIS_MNEMONIC_SUB;

                if (inst->info.mnemonic == ZYDIS_MNEMONIC_RET) {
                    cout << "ret??\n";
                    req.mnemonic = ZYDIS_MNEMONIC_ADD;
                }
                req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
                req.operand_count = 2;
                req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
                req.operands[0].reg.value = ZYDIS_REGISTER_RSP;
                req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                req.operands[1].imm.u = 8;
                req.operands[1].mem.base = ZYDIS_REGISTER_NONE;
                req.operands[1].mem.index = ZYDIS_REGISTER_NONE;
                req.operands[1].mem.displacement = ZYDIS_REGISTER_NONE;

                ZyanU8 new_insn[ZYDIS_MAX_INSTRUCTION_LENGTH];
                ZyanUSize new_insn_length = sizeof(new_insn);
                auto eror = ZydisEncoderEncodeInstruction(&req, new_insn, &new_insn_length);

                if (ZYAN_FAILED(eror)) {
                    printf("Failed to encode instruction %s Code: %d \n ", inst->text, ZYAN_STATUS_CODE(eror));
                }
                //cout << "length: " << new_insn_length << endl;

                bytes->clear();

                bytes->resize(0);



                for (int i = 0; i < new_insn_length; ++i) {
                    bytes->push_back(new_insn[i]);
                }

                ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, 0, new_insn, new_insn_length, inst);

                newTaint = getNewTaint() | getRegisterTaint(ZYDIS_REGISTER_RSP);

                propagateTaintRegister(inst->operands[0].reg.value, newTaint);
                memset(&req, 0, sizeof(req));
                return inst;
            }
            default:
                return inst;
            }
        }

        switch (inst->info.mnemonic) {
        case ZYDIS_MNEMONIC_XCHG: {

            if (inst->operands[0].reg.value == inst->operands[1].reg.value) {
                return inst;
            }


            if (inst->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                destTaint = getRegisterTaint(inst->operands[0].reg.value) | newTaint;

            }
            if (inst->operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                memval = getAddress(inst->operands[0], uc);
                destTaint = getMemoryTaint(memval) | newTaint;

            }

            if (inst->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {

                srcTaint = getRegisterTaint(inst->operands[1].reg.value) | newTaint;

                propagateTaintRegister(inst->operands[1].reg.value, destTaint);
            }

            if (inst->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                memval = getAddress(inst->operands[1], uc);
                srcTaint = getMemoryTaint(memval) | newTaint;


                propagateTaintMemory(memval, destTaint);
            }

            if (inst->operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                propagateTaintMemory(getAddress(inst->operands[0], uc), srcTaint);
            }
            if (inst->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                propagateTaintMemory(inst->operands[0].reg.value, srcTaint);
            }


            return inst;
        }
                                /*
        case ZYDIS_MNEMONIC_PUSHFQ:
        case ZYDIS_MNEMONIC_PUSHFD:
        case ZYDIS_MNEMONIC_PUSHF:
        case ZYDIS_MNEMONIC_PUSH: {


            auto memval = getStackPointer(uc);
            bitset<FLAGSET> regTaint;
            if (inst->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                regTaint = getRegisterTaint(inst->operands[0].reg.value) ;
                newTaint |= regTaint;

            }

            propagateTaintMemory(memval - 8, newTaint);

            newTaint |= getRegisterTaint(ZYDIS_REGISTER_RSP);
            propagateTaintRegister(ZYDIS_REGISTER_RSP, newTaint);
            auto a = first16(regTaint);

            if (a) {
                cout << "taint xd?: " << a << endl;
                propagateTaintMemory(memval - 8, newTaint);
            }

            return inst;
        }

                                
        case ZYDIS_MNEMONIC_POPFQ:
        case ZYDIS_MNEMONIC_POPFD:
        case ZYDIS_MNEMONIC_POPF:
        case ZYDIS_MNEMONIC_POP: {
            auto memval = getStackPointer(uc);
            newTaint = getMemoryTaint(memval);
            propagateTaintRegister(inst->operands[0].reg.value, newTaint);
            return inst;
        }
        */
        default: {
            break;
        }
        }


        //UNNECESARY TAINT WHEN MOV


        for (int i = 0; i < inst->info.operand_count; i++) {

            if ((inst->operands[i].actions & ZYDIS_OPERAND_ACTION_READ)) {

                if (inst->operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER) {

                    newTaint |= getRegisterTaint(inst->operands[i].reg.value);
                    if (
                        ( // we should skip getting taint of RSP if instruction is push/pop
                            inst->info.mnemonic == ZYDIS_MNEMONIC_PUSH ||
                            inst->info.mnemonic == ZYDIS_MNEMONIC_POP ||
                            inst->info.mnemonic == ZYDIS_MNEMONIC_PUSHF ||
                            inst->info.mnemonic == ZYDIS_MNEMONIC_PUSHFQ ||
                            inst->info.mnemonic == ZYDIS_MNEMONIC_PUSHFD ||
                            inst->info.mnemonic == ZYDIS_MNEMONIC_POPF ||
                            inst->info.mnemonic == ZYDIS_MNEMONIC_POPFQ ||
                            inst->info.mnemonic == ZYDIS_MNEMONIC_POPFD

                            )
                        &&
                        inst->operands[i].reg.value == ZYDIS_REGISTER_RSP
                        ) {

                        continue;
                    }

                    decryptTaint |= getRegisterTaint_decrypt(inst->operands[i].reg.value);

                }

                if (inst->operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    memval = getAddress(inst->operands[i], uc);
                    memTaint = getMemoryTaint(memval);
                    newTaint |= memTaint;


                    regFlag = getRegisterTaint(inst->operands[i].mem.base) | getRegisterTaint(inst->operands[i].mem.index);
                    newTaint |= regFlag;

                    newTaint ^= holdTaint; // WHY? because for some reason unique tainting memory addresses breaks them 


                    decryptTaint |= getMemoryTaint_decrypt(memval);
                    cout << "read tainting : " << memval << "\n";
                }



            }


        }


        cout << "memval: " << memval;
        cout << " newTaint : " << first16(decryptTaint)  << " memTaint: " << first16(memTaint) << "\n";
        if (((!first16(decryptTaint)) || (decryptTaint).none()) && !first16(memTaint)) {

            // TODO:
            // IF ITS A MEMORY READ, SHOULD CHECK IF ITS IN THE SAME SECTION. USUALLY VM CONSTANTS ARE IN VM SECTION. 
            // .vmp etc.
            // 
            // we will also want to decrypt constants, 
            // to do that, we need to identify constants correctly.
            // 
            // 
            // we have a problem with push and pop
            // example:
            // push r8
            // xor [rsp], rcx
            // pop r8
            // 
            // here we have the problem of tainting r8 register with RSP, which should not happen. RSP should taint instruction, but not R8
            //



            if (destOp.type == ZYDIS_OPERAND_TYPE_REGISTER // && srcOp.type == ZYDIS_OPERAND_TYPE_MEMORY 
                && inst->info.mnemonic != ZYDIS_MNEMONIC_POPF
                && inst->info.mnemonic != ZYDIS_MNEMONIC_POPFQ
                && inst->info.mnemonic != ZYDIS_MNEMONIC_POPFD
                && inst->info.mnemonic != ZYDIS_MNEMONIC_POP
                && inst->info.mnemonic != ZYDIS_MNEMONIC_PUSH
                && destOp.reg.value != ZYDIS_REGISTER_RSP
                && inst->operands[2].reg.value != ZYDIS_REGISTER_RSP
                && inst->info.operand_count_visible >= 1
                ) {

                // Copy registers from the original engine
                // Note: this is specific to x86_64 architecture
                for (int regid = UC_X86_REG_INVALID; regid <= UC_X86_REG_ENDING; regid++) {
                    uint64_t value;

                    if (uc_reg_read(uc, regid, &value) != UC_ERR_OK) {
                        printf("Failed to read register\n");
                        return inst;
                    }

                    if (uc_reg_write(new_uc, regid, &value) != UC_ERR_OK) {
                        printf("Failed to write register\n");
                        return inst;
                    }

                }


                clone_uc_mem_state(uc);
                uc_emu_start(new_uc, rip, rip + 15, 0, 1);
                auto parentreg_zydis = getParentRegisters(destOp.reg.value).back();
                auto parentReg = zydis2Unicorn(parentreg_zydis);




                //cout << "inst: " << inst->text << " value: " << reg_val << " reg: " << parentreg_zydis << endl;

                memset(&req, 0, sizeof(req));

                ZydisEncoderDecodedInstructionToEncoderRequest(
                    &inst->info, inst->operands, inst->info.operand_count, &req);
                req.mnemonic = ZYDIS_MNEMONIC_MOV;
                req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
                req.operand_count = 2;
                req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
                req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;

                // PROBLEM 1
                // WE SHOULD HAVE A GLOBAL THING INSTEAD OF CHECKING SIZES.
                // BECAUSE IF WE JUST MOV EAX, 13371337
                //                    MOV CL, 8
                // THEN ONLY          
                //                    MOV CL, 8 REMAINS
                // BUT WE WANT
                //                    MOV EAX, 13371338 OR SOME SHIT LIKE THAT

                    uint64_t reg_val;
                    uc_reg_read(new_uc, parentReg, &reg_val);
                    req.operands[1].imm.u = reg_val;



                req.operands[0].reg.value = parentreg_zydis;

                req.operands[1].mem.base = ZYDIS_REGISTER_NONE;
                req.operands[1].mem.index = ZYDIS_REGISTER_NONE;
                req.operands[1].mem.displacement = ZYDIS_REGISTER_NONE;

                ZyanU8 new_insn[ZYDIS_MAX_INSTRUCTION_LENGTH];
                ZyanUSize new_insn_length = sizeof(new_insn);
                auto eror = ZydisEncoderEncodeInstruction(&req, new_insn, &new_insn_length);

                if (ZYAN_FAILED(eror)) {
                    printf("Failed to encode instruction %s Code: %d \n ", inst->text, ZYAN_STATUS_CODE(eror));
                }
                //cout << "length: " << new_insn_length << endl;

                bytes->clear();

                bytes->resize(0);



                for (int i = 0; i < new_insn_length; ++i) {
                    bytes->push_back(new_insn[i]);
                }

                ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, 0, new_insn, new_insn_length, inst);

                newTaint = getNewTaint();

                propagateTaintRegister(parentreg_zydis, newTaint);
                propagateTaintRegister_decrypt(parentreg_zydis, newTaint);
                memset(&req, 0, sizeof(req));

                return inst;
            }

        }



        for (int i = 0; i < inst->info.operand_count; i++) {

            if (inst->operands[i].actions & ZYDIS_OPERAND_ACTION_WRITE) {

               

                if (inst->operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {

                    regFlag = getRegisterTaint(inst->operands[i].mem.base) | getRegisterTaint(inst->operands[i].mem.index);
                    newTaint |= regFlag;

                }


            }


        }

        for (int i = 0; i < inst->info.operand_count; i++) {

            if (inst->operands[i].actions & ZYDIS_OPERAND_ACTION_WRITE) {

                if (inst->operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER) {

                    propagateTaintRegister(inst->operands[i].reg.value, newTaint);
                    if (
                        ( // we should propagate RSP with itself + holdTaint if instruction is push/pop
                            inst->info.mnemonic == ZYDIS_MNEMONIC_PUSH ||
                            inst->info.mnemonic == ZYDIS_MNEMONIC_POP ||
                            inst->info.mnemonic == ZYDIS_MNEMONIC_PUSHF ||
                            inst->info.mnemonic == ZYDIS_MNEMONIC_PUSHFQ ||
                            inst->info.mnemonic == ZYDIS_MNEMONIC_PUSHFD ||
                            inst->info.mnemonic == ZYDIS_MNEMONIC_POPF ||
                            inst->info.mnemonic == ZYDIS_MNEMONIC_POPFQ ||
                            inst->info.mnemonic == ZYDIS_MNEMONIC_POPFD

                            )
                        &&
                        inst->operands[i].reg.value == ZYDIS_REGISTER_RSP
                        ) {
                        continue;
                    } 


                    propagateTaintRegister_decrypt(inst->operands[i].reg.value, decryptTaint);
                }

                if (inst->operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {

                    memval = getAddress(inst->operands[i], uc);
                    newTaint ^= holdTaint; // refer line 463
                    propagateTaintMemory(memval, newTaint);
                    propagateTaintMemory_decrypt(memval, decryptTaint);

                }


            }


        }

        //newTaint |= rspTaint;

        return  inst;
    }


};