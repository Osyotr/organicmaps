#pragma once

#include "target_os.hpp"

// override byte to prevent clashes with <cstddef>
#define byte win_byte_override

#ifdef OMIM_OS_WINDOWS
#include <windows.h>

#undef min
#undef max
//#undef far
//#undef near

#endif // OMIM_OS_WINDOWS
