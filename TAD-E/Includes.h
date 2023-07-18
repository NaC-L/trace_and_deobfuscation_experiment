#pragma once
#include <iostream>
#include <vector>
#include <unicorn/unicorn.h>
#include <Zydis/Zydis.h>
#include <LIEF/LIEF.hpp>
#include <fstream>
#include <map>

#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <bitset>
#include <set>

#include <functional>

using namespace std;


#ifdef DEBUG
#define DEBUGLOG printf
#else
#define DEBUGLOG (...)
#endif