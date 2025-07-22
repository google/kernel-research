/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

class HexDump {
public:
    // 16 bytes are converted into: "00 11 22 33 44 55 66 77   88 99 AA BB CC DD EE FF  |  0123456789ABCDEF\n" (70 bytes)
    static void Dump(char* dst, const uint8_t* buf, int len) {
        char text[17] = { };
        for (int i = 0; i < len; i++) {
            dst += sprintf(dst, "%02X ", buf[i]);
            int o = i % 16;
            text[o] = ' ' <= buf[i] && buf[i] <= '~' ? buf[i] : '.';
            if (i == len - 1)
                dst += sprintf(dst, "%*s |  %.*s\n", 3 * (15 - o) + (o < 8 ? 1 : 0), "", o + 1, text);
            else if (o == 7)
                        dst += sprintf(dst, " ");
            else if (o == 15)
                dst += sprintf(dst, " |  %s\n", text);
        }
    }

    static std::string Dump(const void* buf, int len) {
        std::string result(((len - 1) / 16 + 1) * 70, 0);
        Dump(result.data(), (const uint8_t*) buf, len);
        return result;
    }

    static std::string Dump(const std::vector<uint8_t>& data) {
        return Dump(data.data(), data.size());
    }

    static void Print(const void* buf, int len) {
        printf("%s", Dump(buf, len).c_str());
    }

    static void Print(const std::vector<uint8_t>& data) {
        Print(data.data(), data.size());
    }
};
