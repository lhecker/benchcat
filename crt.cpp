#ifdef NODEFAULTLIB

#define NOMINMAX
#define UNICODE
#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>

// Floating point support stuff for /NODEFAULTLIB
extern "C" int _fltused = 0;

#pragma function(memcpy)
void* memcpy(void* dst, const void* src, size_t size) {
    __movsb(static_cast<BYTE*>(dst), static_cast<const BYTE*>(src), size);
    return dst;
}

#endif
