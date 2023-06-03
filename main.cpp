#define NOMINMAX
#define UNICODE
#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN

#include <climits>
#include <cstdint>

#include <Shlwapi.h>
#include <Windows.h>
#include <icu.h>

namespace pcg_engines {
    /*
     * PCG Random Number Generation for C++
     *
     * Copyright 2014-2017 Melissa O'Neill <oneill@pcg-random.org>,
     *                     and the PCG Project contributors.
     *
     * SPDX-License-Identifier: (Apache-2.0 OR MIT)
     *
     * Licensed under the Apache License, Version 2.0 (provided in
     * LICENSE-APACHE.txt and at http://www.apache.org/licenses/LICENSE-2.0)
     * or under the MIT license (provided in LICENSE-MIT.txt and at
     * http://opensource.org/licenses/MIT), at your option. This file may not
     * be copied, modified, or distributed except according to those terms.
     *
     * Distributed on an "AS IS" BASIS, WITHOUT WARRANTY OF ANY KIND, either
     * express or implied.  See your chosen license for details.
     *
     * For additional information about the PCG random number generation scheme,
     * visit http://www.pcg-random.org/.
     */

    class oneseq_dxsm_64_32 {
        using xtype = uint32_t;
        using itype = uint64_t;

        itype state_;

        static constexpr uint64_t multiplier() noexcept {
            return 6364136223846793005ULL;
        }

        static constexpr uint64_t increment() noexcept {
            return 1442695040888963407ULL;
        }

        static constexpr itype bump(itype state) noexcept {
            return state * multiplier() + increment();
        }

        constexpr itype base_generate0() noexcept {
            itype old_state = state_;
            state_ = bump(state_);
            return old_state;
        }

    public:
        explicit constexpr oneseq_dxsm_64_32(itype state = 0xcafef00dd15ea5e5ULL) noexcept : state_(bump(state + increment())) {
        }

        constexpr xtype operator()() noexcept {
            constexpr auto xtypebits = uint8_t(sizeof(xtype) * 8);
            constexpr auto itypebits = uint8_t(sizeof(itype) * 8);
            static_assert(xtypebits <= itypebits / 2, "Output type must be half the size of the state type.");

            auto internal = base_generate0();
            auto hi = xtype(internal >> (itypebits - xtypebits));
            auto lo = xtype(internal);

            lo |= 1;
            hi ^= hi >> (xtypebits / 2);
            hi *= xtype(multiplier());
            hi ^= hi >> (3 * (xtypebits / 4));
            hi *= lo;
            return hi;
        }

        constexpr xtype operator()(xtype upper_bound) noexcept {
            uint32_t threshold = (UINT64_MAX + uint32_t(1) - upper_bound) % upper_bound;
            for (;;) {
                auto r = operator()();
                if (r >= threshold)
                    return r % upper_bound;
            }
        }
    };
}// namespace pcg_engines

namespace ucrt {
    // Copyright (c) Microsoft Corporation. All rights reserved.
    //
    // This is a copy of "startup/argv_parsing.cpp" from the Windows SDK (10.0.22000.0).
    // The source code was slightly modified to fit this code style.

    template<typename Character>
    static bool should_copy_another_character(Character) noexcept {
        return false;
    }

    template<typename Character>
    static void __cdecl parse_command_line(Character* cmdstart, Character** argv, Character* args, size_t* argument_count, size_t* character_count) noexcept {
        *character_count = 0;
        *argument_count = 1;// We'll have at least the program name

        Character c;
        int copy_character; /* 1 = copy char to *args */
        unsigned numslash;  /* num of backslashes seen */

        /* first scan the program name, copy it, and count the bytes */
        Character* p = cmdstart;
        if (argv)
            *argv++ = args;

        // A quoted program name is handled here. The handling is much
        // simpler than for other arguments. Basically, whatever lies
        // between the leading double-quote and next one, or a terminal null
        // character is simply accepted. Fancier handling is not required
        // because the program name must be a legal NTFS/HPFS file name.
        // Note that the double-quote characters are not copied, nor do they
        // contribute to character_count.
        bool in_quotes = false;
        do {
            if (*p == '"') {
                in_quotes = !in_quotes;
                c = *p++;
                continue;
            }

            ++*character_count;
            if (args)
                *args++ = *p;

            c = *p++;

            if (should_copy_another_character(c)) {
                ++*character_count;
                if (args)
                    *args++ = *p;// Copy 2nd byte too
                ++p;             // skip over trail byte
            }
        } while (c != '\0' && (in_quotes || (c != ' ' && c != '\t')));

        if (c == '\0') {
            p--;
        } else {
            if (args)
                *(args - 1) = '\0';
        }

        in_quotes = false;

        // Loop on each argument
        for (;;) {
            if (*p) {
                while (*p == ' ' || *p == '\t')
                    ++p;
            }

            if (*p == '\0')
                break;// End of arguments

            // Scan an argument:
            if (argv)
                *argv++ = args;

            ++*argument_count;

            // Loop through scanning one argument:
            for (;;) {
                copy_character = 1;

                // Rules:
                // 2N     backslashes   + " ==> N backslashes and begin/end quote
                // 2N + 1 backslashes   + " ==> N backslashes + literal "
                // N      backslashes       ==> N backslashes
                numslash = 0;

                while (*p == '\\') {
                    // Count number of backslashes for use below
                    ++p;
                    ++numslash;
                }

                if (*p == '"') {
                    // if 2N backslashes before, start/end quote, otherwise
                    // copy literally:
                    if (numslash % 2 == 0) {
                        if (in_quotes && p[1] == '"') {
                            p++;// Double quote inside quoted string
                        } else {
                            // Skip first quote char and copy second:
                            copy_character = 0;// Don't copy quote
                            in_quotes = !in_quotes;
                        }
                    }

                    numslash /= 2;
                }

                // Copy slashes:
                while (numslash--) {
                    if (args)
                        *args++ = '\\';
                    ++*character_count;
                }

                // If at end of arg, break loop:
                if (*p == '\0' || (!in_quotes && (*p == ' ' || *p == '\t')))
                    break;

                // Copy character into argument:
                if (copy_character) {
                    if (args)
                        *args++ = *p;

                    if (should_copy_another_character(*p)) {
                        ++p;
                        ++*character_count;

                        if (args)
                            *args++ = *p;
                    }

                    ++*character_count;
                }

                ++p;
            }

            // Null-terminate the argument:
            if (args)
                *args++ = '\0';// Terminate the string

            ++*character_count;
        }

        // We put one last argument in -- a null pointer:
        if (argv)
            *argv++ = nullptr;

        ++*argument_count;
    }

    char* acrt_allocate_buffer_for_argv(size_t const argument_count, size_t const character_count, size_t const character_size) {
        const size_t argument_array_size = argument_count * sizeof(void*);
        const size_t character_array_size = character_count * character_size;
        const size_t total_size = argument_array_size + character_array_size;
        return reinterpret_cast<char*>(VirtualAlloc(nullptr, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    }

    static void common_configure_argv(const char*** argv, int* argc) {
        const auto command_line = GetCommandLineA();

        size_t argument_count = 0;
        size_t character_count = 0;
        ucrt::parse_command_line<char>(command_line, nullptr, nullptr, &argument_count, &character_count);

        const auto buffer = ucrt::acrt_allocate_buffer_for_argv(argument_count, character_count, sizeof(char));
        const auto first_argument = reinterpret_cast<char**>(buffer);
        const auto first_string = reinterpret_cast<char*>(buffer + argument_count * sizeof(char*));
        ucrt::parse_command_line(command_line, first_argument, first_string, &argument_count, &character_count);

        *argv = const_cast<const char**>(first_argument);
        *argc = argument_count - 1;
    }
}// namespace ucrt

constexpr LONGLONG fract_round(LONGLONG dividend, LONGLONG divisor) {
    return ((dividend + divisor / 2) / divisor) % 1000;
}

static unsigned long int parse_decimal(const char* str, const char** endptr) noexcept {
    static constexpr unsigned long maximumValue = ULONG_MAX / 10;

    unsigned long accumulator = 0;

    for (;; ++str) {
        if (*str == '\0' || *str < '0' || *str > '9') {
            break;
        }

        accumulator = accumulator * 10 + *str - '0';
        if (accumulator >= maximumValue) {
            accumulator = ULONG_MAX;
            break;
        }
    }

    if (endptr) {
        *endptr = str;
    }

    return accumulator;
}

static bool has_prefix(const char* str, const char* prefix) noexcept {
    for (; *prefix != '\0'; ++prefix, ++str) {
        if (*str != *prefix) {
            return false;
        }
    }
    return true;
}

static void eprintf(const char* format, ...) noexcept {
    char buffer[256];

    va_list vl;
    va_start(vl, format);
    const auto length = wvnsprintfA(buffer, sizeof(buffer), format, vl);
    va_end(vl);

    if (length > 0) {
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), buffer, length, nullptr, nullptr);
    }
}

static void printLastError(const char* what) noexcept {
    eprintf("\r\nfailed to %s with 0x%08lx\r\n", what, GetLastError());
}

static DWORD parseNumber(const char* str, const char** end) noexcept {
    const char* strEnd = nullptr;
    auto value = parse_decimal(str, &strEnd);

    if (value && strEnd) {
        switch (*strEnd) {
            case 'g':
                value *= 1000;
                [[fallthrough]];
            case 'm':
                value *= 1000;
                [[fallthrough]];
            case 'k':
                value *= 1000;
                ++strEnd;
                break;
            case 'G':
                value *= 1024;
                [[fallthrough]];
            case 'M':
                value *= 1024;
                [[fallthrough]];
            case 'K':
                value *= 1024;
                ++strEnd;
                break;
        }
    }

    if (end) {
        *end = strEnd;
    }

    return value;
}

static size_t enableLockMemoryPrivilege() noexcept {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
        printLastError("open process token");
        return 0;
    }

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = {4, 0};// SE_LOCK_MEMORY_PRIVILEGE is a well known LUID and always {4, 0}
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    const bool success = AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
    if (!success) {
        printLastError("adjust token privileges");
        return 0;
    }

    CloseHandle(token);
    return GetLargePageMinimum();
}

static size_t largePageMinimum = 0;

static char* allocate(size_t size) {
    char* address = nullptr;
    if (largePageMinimum) {
        address = static_cast<char*>(VirtualAlloc(nullptr, (size + largePageMinimum - 1) & ~(largePageMinimum - 1), MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, PAGE_READWRITE));
    }
    if (!address) {
        address = static_cast<char*>(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!address) {
            printLastError("allocate memory");
            ExitProcess(1);
        }
    }
    return address;
}

inline char* memcpyAppend(char* dst, const void* src, size_t size) {
    memcpy(dst, src, size);
    return dst + size;
}

inline char* memcpyAppend(char* dst, const char* src) {
    return memcpyAppend(dst, src, __builtin_strlen(src));
}

static constexpr char stringTable256[]{"0123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899100101102103104105106107108109110111112113114115116117118119120121122123124125126127128129130131132133134135136137138139140141142143144145146147148149150151152153154155156157158159160161162163164165166167168169170171172173174175176177178179180181182183184185186187188189190191192193194195196197198199200201202203204205206207208209210211212213214215216217218219220221222223224225226227228229230231232233234235236237238239240241242243244245246247248249250251252253254255"};
static constexpr uint16_t stringTable256Offsets[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158, 160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190, 193, 196, 199, 202, 205, 208, 211, 214, 217, 220, 223, 226, 229, 232, 235, 238, 241, 244, 247, 250, 253, 256, 259, 262, 265, 268, 271, 274, 277, 280, 283, 286, 289, 292, 295, 298, 301, 304, 307, 310, 313, 316, 319, 322, 325, 328, 331, 334, 337, 340, 343, 346, 349, 352, 355, 358, 361, 364, 367, 370, 373, 376, 379, 382, 385, 388, 391, 394, 397, 400, 403, 406, 409, 412, 415, 418, 421, 424, 427, 430, 433, 436, 439, 442, 445, 448, 451, 454, 457, 460, 463, 466, 469, 472, 475, 478, 481, 484, 487, 490, 493, 496, 499, 502, 505, 508, 511, 514, 517, 520, 523, 526, 529, 532, 535, 538, 541, 544, 547, 550, 553, 556, 559, 562, 565, 568, 571, 574, 577, 580, 583, 586, 589, 592, 595, 598, 601, 604, 607, 610, 613, 616, 619, 622, 625, 628, 631, 634, 637, 640, 643, 646, 649, 652, 655, 658};

char* decimalAppend256(char* dst, size_t val) {
    const auto off0 = stringTable256Offsets[val];
    const auto off1 = stringTable256Offsets[val + 1];

    for (auto i = off0; i < off1; ++i) {
        *dst++ = stringTable256[i];
    }

    return dst;
}


enum class VtMode {
    Off,
    On,
    Italic,
    Color
};

#ifdef NODEFAULTLIB
void __stdcall mainCRTStartup() noexcept {
#else
int main() noexcept {
#endif
    SetConsoleOutputCP(CP_UTF8);

    const char* path = nullptr;
    DWORD chunkSizeBeg = 1073741824;// maximum buffer size WriteFile seems to accept
    DWORD chunkSizeEnd = 1073741824;
    DWORD repeat = 1;
    VtMode vt = VtMode::Off;
    uint64_t seed = 0;
    bool seedParam = false;

    {
        const auto command_line = GetCommandLineA();

        size_t argument_count = 0;
        size_t character_count = 0;
        ucrt::parse_command_line<char>(command_line, nullptr, nullptr, &argument_count, &character_count);

        const auto buffer = ucrt::acrt_allocate_buffer_for_argv(argument_count, character_count, sizeof(char));
        const auto first_argument = reinterpret_cast<char**>(buffer);
        const auto first_string = reinterpret_cast<char*>(buffer + argument_count * sizeof(char*));
        ucrt::parse_command_line(command_line, first_argument, first_string, &argument_count, &character_count);

        const char** argv;
        int argc;
        ucrt::common_configure_argv(&argv, &argc);

        for (int i = 1; i < argc; ++i) {
            if (has_prefix(argv[i], "-chunk=")) {
                const char* str = nullptr;
                chunkSizeBeg = parseNumber(argv[i] + 7, &str);
                if (*str == '-') {
                    chunkSizeEnd = parseNumber(str + 1, nullptr);
                } else {
                    chunkSizeEnd = chunkSizeBeg;
                }
            } else if (has_prefix(argv[i], "-repeat=")) {
                repeat = parseNumber(argv[i] + 8, nullptr);
            } else if (has_prefix(argv[i], "-vt=on")) {
                vt = VtMode::On;
            } else if (has_prefix(argv[i], "-vt=italic")) {
                vt = VtMode::Italic;
            } else if (has_prefix(argv[i], "-vt=color")) {
                vt = VtMode::Color;
            } else if (has_prefix(argv[i], "-seed=")) {
                seed = parseNumber(argv[i] + 6, nullptr);
                seedParam = true;
            } else if (path) {
                path = nullptr;
                break;
            } else {
                path = argv[i];
            }
        }
    }

    if (!path || !chunkSizeBeg || !chunkSizeEnd || !repeat) {
        eprintf(
            "bc <filename>\r\n"
            "\t-chunk={d}[kKmMgG][-{d}[kKmMgG]]\r\n"
            "\t\tThe argument may be given as an range (inclusive) to randomize chunk sizes.\r\n"
            "\t\tDefaults to writing the file in a single WriteFile() call.\r\n"
            "\t-repeat={d}[kKmMgG]\r\n"
            "\t-vt=(on|italic|color)\r\n"
            "\t-seed={d}\r\n"
            "\r\n"
            "{b} is a single bit (0 or 1)\r\n"
            "{d} are base-10 digits\r\n"
            "\tk,m,g are base-10 units\r\n"
            "\tK,M,G are base-2 units\r\n");
        ExitProcess(1);
    }

    largePageMinimum = enableLockMemoryPrivilege();

    if (!seedParam) {
        const auto cryptbase = LoadLibraryExA("cryptbase.dll", nullptr, 0);
        if (!cryptbase) {
            printLastError("get handle to cryptbase.dll");
            ExitProcess(1);
        }

        const auto RtlGenRandom = reinterpret_cast<BOOLEAN(APIENTRY*)(PVOID, ULONG)>(GetProcAddress(cryptbase, "SystemFunction036"));
        if (!RtlGenRandom) {
            printLastError("get handle to RtlGenRandom");
            ExitProcess(1);
        }

        RtlGenRandom(&seed, sizeof(seed));
    }

    pcg_engines::oneseq_dxsm_64_32 rng{seed};

    DWORD chunkSizeRange = 0;
    if (chunkSizeBeg > chunkSizeEnd) {
        const auto tmp = chunkSizeBeg;
        chunkSizeBeg = chunkSizeEnd;
        chunkSizeEnd = tmp;
    }
    if (chunkSizeEnd != chunkSizeBeg) {
        chunkSizeRange = chunkSizeEnd - chunkSizeBeg + 1;
    }

    const auto stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    const auto fileHandle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        printLastError("open file");
        ExitProcess(1);
    }

    const auto fileSize = GetFileSize(fileHandle, nullptr);
    const auto fileData = allocate(fileSize);
    auto writeSize = fileSize;
    auto writeData = fileData;

    // read file
    {
        auto readAddress = fileData;
        for (DWORD remaining = fileSize, read = 0; remaining > 0; remaining -= read, readAddress += read) {
            if (!ReadFile(fileHandle, readAddress, remaining, &read, nullptr)) {
                printLastError("read");
                ExitProcess(1);
            }
        }
    }

    // enable/disable VT
    {
        DWORD consoleMode = 0;
        if (!GetConsoleMode(stdoutHandle, &consoleMode)) {
            printLastError("get console mode");
        }

        auto consoleModeNew = consoleMode;
        consoleModeNew &= ~(ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN);
        consoleModeNew |= vt != VtMode::Off ? ENABLE_VIRTUAL_TERMINAL_PROCESSING : 0;

        if (consoleModeNew != consoleMode && !SetConsoleMode(stdoutHandle, consoleModeNew)) {
            printLastError("set console mode");
        }
    }

    // preprocess file with vt options
    switch (vt) {
        case VtMode::Italic: {
            writeData = allocate(fileSize + 16);
            auto p = writeData;
            p = memcpyAppend(p, "\x1b[3m");
            p = memcpyAppend(p, fileData, fileSize);
            p = memcpyAppend(p, "\x1b[0m");
            writeSize = p - writeData;
            break;
        }
        case VtMode::Color: {
            const auto icu = LoadLibraryExW(L"icuuc.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (icu) {
                writeData = allocate(fileSize * 20 + 8);
                auto p = writeData;

                const auto utextOpenUTF8 = reinterpret_cast<decltype(&utext_openUTF8)>(GetProcAddress(icu, "utext_openUTF8"));
                const auto ubrkOpen = reinterpret_cast<decltype(&ubrk_open)>(GetProcAddress(icu, "ubrk_open"));
                const auto ubrkSetUText = reinterpret_cast<decltype(&ubrk_setUText)>(GetProcAddress(icu, "ubrk_setUText"));
                const auto ubrkNext = reinterpret_cast<decltype(&ubrk_next)>(GetProcAddress(icu, "ubrk_next"));

                auto error = U_ZERO_ERROR;

                UText text = UTEXT_INITIALIZER;
                utextOpenUTF8(&text, fileData, fileSize, &error);

                const auto it = ubrkOpen(UBRK_CHARACTER, "", nullptr, 0, &error);
                ubrkSetUText(it, &text, &error);

                for (int32_t ubrk0 = 0, ubrk1; (ubrk1 = ubrkNext(it)) != UBRK_DONE; ubrk0 = ubrk1) {
                    p = memcpyAppend(p, "\x1b[38;2");
                    for (int i = 0; i < 3; i++) {
                        const auto v = rng(256);
                        *p++ = ';';
                        p = decimalAppend256(p, v);
                    }
                    p = memcpyAppend(p, "m");
                    p = memcpyAppend(p, fileData + ubrk0, ubrk1 - ubrk0);
                }

                p = memcpyAppend(p, "\x1b[39;49m");
                writeSize = p - writeData;
            }
            break;
        }
        default:
            break;
    }

    LARGE_INTEGER frequency, beg, end;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&beg);

    // write file
    for (DWORD iteration = 0; iteration < repeat; ++iteration) {
        auto writeAddress = writeData;
        for (DWORD remaining = writeSize, written = 0; remaining > 0; remaining -= written, writeAddress += written) {
            auto chunkSize = chunkSizeBeg;
            if (chunkSizeRange) {
                chunkSize += rng(chunkSizeRange);
            }

            written = remaining;
            if (written > chunkSize) {
                written = chunkSize;
            }

            if (!WriteFile(stdoutHandle, writeAddress, written, &written, nullptr)) {
                printLastError("write");
                ExitProcess(1);
            }
        }
    }

    QueryPerformanceCounter(&end);

    const auto elapsedCounter = end.QuadPart - beg.QuadPart;
    const auto elapsedUS = (elapsedCounter * 1'000'000) / frequency.QuadPart;
    const auto written = static_cast<LONGLONG>(writeSize) * repeat;
    const auto bytesPerSecond = (written * frequency.QuadPart) / elapsedCounter;

    LONGLONG duration;
    LONGLONG durationFract;
    const char* durationSuffix;
    if (elapsedUS >= 1'000'000) {
        duration = elapsedUS / 1'000'000;
        durationFract = fract_round(elapsedUS, 1'000);
        durationSuffix = "";
    } else {
        duration = elapsedUS / 1'000;
        durationFract = elapsedUS % 1'000;
        durationSuffix = "m";
    }

    LONGLONG throughput;
    LONGLONG throughputFract;
    const char* throughputSuffix;
    if (bytesPerSecond >= 1'000'000'000) {
        throughput = bytesPerSecond / 1'000'000'000;
        throughputFract = fract_round(bytesPerSecond, 1'000'000);
        throughputSuffix = "G";
    } else if (bytesPerSecond >= 1'000'000) {
        throughput = bytesPerSecond / 1'000'000;
        throughputFract = fract_round(bytesPerSecond, 1'000);
        throughputSuffix = "M";
    } else if (bytesPerSecond >= 1'000) {
        throughput = bytesPerSecond / 1'000;
        throughputFract = bytesPerSecond % 1'000;
        throughputSuffix = "k";
    } else {
        throughput = 0;
        throughputFract = bytesPerSecond;
        throughputSuffix = "";
    }

    eprintf("\r\n------------------------\r\n%lld.%03lld%ss (%lld.%03lld %sB/s)\r\n", duration, durationFract, durationSuffix, throughput, throughputFract, throughputSuffix);
    ExitProcess(0);

#ifndef NDEBUG
    return 0;
#endif
}
