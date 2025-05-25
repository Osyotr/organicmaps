#pragma once

#include "target_os.hpp"

#ifdef OMIM_OS_WINDOWS

// override byte to prevent clashes with <cstddef>
#define byte win_byte_override

#include <windows.h>

#undef FindResource

#undef min
#undef max
//#undef far
//#undef near

#endif // OMIM_OS_WINDOWS
