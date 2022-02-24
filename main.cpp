#define NOMINMAX
#define UNICODE
#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN

#include <climits>
#include <cstdint>

#include <Shlwapi.h>
#include <Windows.h>

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

// Floating point support stuff for /NODEFAULTLIB
extern "C" int _fltused = 0;

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
    char buffer[1024];
    va_list vl;
    va_start(vl, format);
    const auto length = wvnsprintfA(buffer, sizeof(buffer), format, vl);
    va_end(vl);

    if (length) {
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), buffer, length, nullptr, nullptr);
    }
}

static void printLastError(const char* what) noexcept {
    eprintf("\nfailed to %s with 0x%08lx\n", what, GetLastError());
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
    privileges.Privileges[0].Luid = {4, 0};// SE_LOCK_MEMORY_NAME is a well known LUID and always {4, 0}
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    const bool success = AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
    if (!success) {
        printLastError("adjust token privileges");
        return 0;
    }

    CloseHandle(token);
    return GetLargePageMinimum();
}

#ifdef NDEBUG
void __stdcall mainCRTStartup() noexcept {
#else
int main() noexcept {
#endif
    SetConsoleOutputCP(CP_UTF8);

    const char* path = nullptr;
    DWORD chunkSizeBeg = -1;
    DWORD chunkSizeEnd = -1;
    DWORD repeat = 1;
    DWORD vt = 0;

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
            } else if (has_prefix(argv[i], "-vt=")) {
                vt = parseNumber(argv[i] + 4, nullptr);
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
            "bc <filename>\n"
            "\t-chunk={d}[kKmMgG][-{d}[kKmMgG]]\n"
            "\t\tThe argument may be given as an range (inclusive) to randomize chunk sizes.\n"
            "\t\tDefaults to writing the file in a single WriteFile() call.\n"
            "\t-repeat={d}[kKmMgG]\n"
            "\t-vt={b}\n"
            "\n"
            "{b} is a single bit (0 or 1)\n"
            "{d} are base-10 digits\n"
            "\tk,m,g are base-10 units\n"
            "\tK,M,G are base-2 units\n");
        ExitProcess(1);
    }

    if (chunkSizeBeg > chunkSizeEnd) {
        const auto tmp = chunkSizeBeg;
        chunkSizeBeg = chunkSizeEnd;
        chunkSizeEnd = tmp;
    }

    pcg_engines::oneseq_dxsm_64_32 rng;
    DWORD chunkSizeRange = 0;

    if (chunkSizeEnd != chunkSizeBeg) {
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

        uint64_t seed;
        RtlGenRandom(&seed, sizeof(seed));

        rng = pcg_engines::oneseq_dxsm_64_32{seed};
        chunkSizeRange = chunkSizeEnd - chunkSizeBeg + 1;
    }

    const auto stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    const auto fileHandle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        printLastError("open file");
        ExitProcess(1);
    }

    const auto fileSize = GetFileSize(fileHandle, nullptr);

    uint8_t* address = nullptr;
    if (const auto min = enableLockMemoryPrivilege()) {
        address = reinterpret_cast<uint8_t*>(VirtualAlloc(nullptr, (fileSize + min - 1) & ~(min - 1), MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, PAGE_READWRITE));
    }
    if (!address) {
        address = reinterpret_cast<uint8_t*>(VirtualAlloc(nullptr, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!address) {
            printLastError("allocate memory");
            ExitProcess(1);
        }
    }

    // read file
    {
        auto readAddress = address;
        for (DWORD remaining = fileSize, read = 0; remaining > 0; remaining -= read, readAddress += read) {
            if (!ReadFile(fileHandle, readAddress, remaining, &read, nullptr)) {
                printLastError("read");
                ExitProcess(1);
            }
        }
    }

    {
        DWORD consoleMode;
        if (!GetConsoleMode(stdoutHandle, &consoleMode)) {
            printLastError("get console mode");
        }

        consoleMode = (consoleMode & ~(ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN)) | (vt ? ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN : 0);

        if (!SetConsoleMode(stdoutHandle, consoleMode)) {
            printLastError("set console mode");
        }
    }

    LARGE_INTEGER frequency, beg, end;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&beg);

    // write file
    for (DWORD iteration = 0; iteration < repeat; ++iteration) {
        auto writeAddress = address;
        for (DWORD remaining = fileSize, written = 0; remaining > 0; remaining -= written, writeAddress += written) {
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

    const auto elapsedCounter = uint64_t(end.QuadPart - beg.QuadPart);
    const auto elapsedMS = (elapsedCounter * 1000) / frequency.QuadPart;
    const auto duration = elapsedMS / 1000;     // whole seconds
    const auto durationFract = elapsedMS % 1000;// remaining milliseconds

    const auto written = uint64_t(fileSize) * repeat;
    const auto throughput = (written * frequency.QuadPart) / (elapsedCounter * 1000000000);// whole GB
    const auto throughputFract = (written * frequency.QuadPart) / (elapsedCounter * 1000); // remaining KB

    eprintf("\r\n--------------------\r\n%d.%03ds (%d.%06d GB/s)\r\n", duration, durationFract, throughput, throughputFract);
    ExitProcess(0);

#ifndef NDEBUG
    return 0;
#endif
}
