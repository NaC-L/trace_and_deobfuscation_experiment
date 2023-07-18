#pragma once

#ifndef ADD_H
#define ADD_H

int zydis2Unicorn(ZydisRegister reg);
int unicorn2Zydis(uc_x86_reg reg);
vector<ZydisRegister> getSubRegisters(ZydisRegister reg);

vector<ZydisRegister> getParentRegisters(ZydisRegister reg);

#endif