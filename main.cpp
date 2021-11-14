#define NOMINMAX
#define UNICODE
#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN

#include <cstdint>
#include <cstdio>
#include <cstdlib>

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

static DWORD parseNumber(const char* str, char** end) noexcept {
    char* strEnd = nullptr;
    auto value = strtoul(str, &strEnd, 10);

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

static bool enableLockMemoryPrivilege() noexcept {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
        fprintf(stderr, "failed to open process token with 0x%08lx\n", GetLastError());
        return false;
    }

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = {4, 0}; // SE_LOCK_MEMORY_NAME is a well known LUID and always {4, 0}
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    const bool success = AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
    if (!success) {
        fprintf(stderr, "failed to adjust token privileges with 0x%08lx\n", GetLastError());
    }

    CloseHandle(token);
    return success;
}

int main(int argc, const char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);

    const char* path = nullptr;
    DWORD chunkSizeBeg = -1;
    DWORD chunkSizeEnd = -1;
    DWORD repeat = 1;

    for (int i = 1; i < argc; ++i) {
        if (strncmp(argv[i], "-chunk=", 7) == 0) {
            char* str = nullptr;
            chunkSizeBeg = parseNumber(argv[i] + 7, &str);
            if (*str == '-') {
                chunkSizeEnd = parseNumber(str + 1, nullptr);
            } else {
                chunkSizeEnd = chunkSizeBeg;
            }
        } else if (strncmp(argv[i], "-repeat=", 8) == 0) {
            repeat = parseNumber(argv[i] + 8, nullptr);
        } else {
            path = argv[i];
        }
    }

    if (!path || !chunkSizeBeg || !chunkSizeEnd || !repeat) {
        fprintf(stderr, "Usage: bc <filename>\n");
        fprintf(stderr, "Flags:\n");
        fprintf(stderr, "-chunk=xxx[kKmMgG][-xxx[kKmMgG]]:\n");
        fprintf(stderr, "\tk,m,g for power-of-10 units\n");
        fprintf(stderr, "\tK,M,G for power-of-2 units\n");
        fprintf(stderr, "\tthe argument may be given as an inclusive range to randomize chunk sizes\n");
        return 1;
    }

    if (chunkSizeBeg > chunkSizeEnd) {
        const auto tmp = chunkSizeBeg;
        chunkSizeBeg = chunkSizeEnd;
        chunkSizeEnd = tmp;
    }

    pcg_engines::oneseq_dxsm_64_32 rng;
    DWORD chunkSizeRange = 0;

    if (chunkSizeEnd != chunkSizeBeg) {
        const auto cryptbase = LoadLibraryExW(L"cryptbase.dll", nullptr, 0);
        if (!cryptbase) {
            fprintf(stderr, "failed to get handle to cryptbase.dll with 0x%08lx\n", GetLastError());
            return 1;
        }

        const auto RtlGenRandom = reinterpret_cast<BOOLEAN(APIENTRY*)(PVOID, ULONG)>(GetProcAddress(cryptbase, "SystemFunction036"));
        if (!RtlGenRandom) {
            fprintf(stderr, "failed to get handle to RtlGenRandom with 0x%08lx\n", GetLastError());
            return 1;
        }

        uint64_t seed;
        RtlGenRandom(&seed, sizeof(seed));

        rng = pcg_engines::oneseq_dxsm_64_32{seed};
        chunkSizeRange = chunkSizeEnd - chunkSizeBeg + 1;
    }

    const auto stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    const auto fileHandle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "failed to open file with 0x%08lx at: %s\n", GetLastError(), path);
        return 1;
    }

    DWORD allocationType = MEM_COMMIT | MEM_RESERVE;
    if (enableLockMemoryPrivilege() && GetLargePageMinimum() != 0) {
        allocationType |= MEM_LARGE_PAGES;
    }

    const auto fileSize = GetFileSize(fileHandle, nullptr);
    const auto address = reinterpret_cast<uint8_t*>(VirtualAlloc(nullptr, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    // read file
    {
        auto readAddress = address;
        for (DWORD remaining = fileSize, read = 0; remaining > 0; remaining -= read, readAddress += read) {
            if (!ReadFile(fileHandle, readAddress, remaining, &read, nullptr)) {
                fprintf(stderr, "\nfailed to read with 0x%08lx\n", GetLastError());
                return 1;
            }
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
                fprintf(stderr, "\nfailed to write with 0x%08lx\n", GetLastError());
                return 1;
            }
        }
    }

    QueryPerformanceCounter(&end);
    const auto elapsed = double(end.QuadPart - beg.QuadPart) / double(frequency.QuadPart);
    fprintf(stdout, "\n--------------------\n%.03fs (%.06f GB/s)\n", elapsed, fileSize / (1'000'000'000.0 * elapsed / double(repeat)));
    return 0;
}
