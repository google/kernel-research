#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

/**
 * @brief Utility class for generating hexadecimal dumps of memory.
 */
class HexDump {
public:
    /**
     * @brief Generates a hexadecimal dump of a memory buffer into a character array.
     * @param dst The destination character array to write the dump to.
     * @param buf The buffer containing the data to dump.
     * @param len The number of bytes to dump.
     */
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

    /**
     * @brief Generates a hexadecimal dump of a memory buffer into a string.
     * @param buf The buffer containing the data to dump.
     * @param len The number of bytes to dump.
     * @return A string containing the hexadecimal dump.
     */
    static std::string Dump(const void* buf, int len) {
        std::string result(((len - 1) / 16 + 1) * 70, 0);
        Dump(result.data(), (const uint8_t*) buf, len);
        return result;
    }

    /**
     * @brief Generates a hexadecimal dump of a vector of bytes into a string.
     * @param data The vector of bytes to dump.
     * @return A string containing the hexadecimal dump.
     */
    static std::string Dump(const std::vector<uint8_t>& data) {
        return Dump(data.data(), data.size());
    }

    /**
     * @brief Prints a hexadecimal dump of a memory buffer to the standard output.
     * @param buf The buffer containing the data to dump.
     * @param len The number of bytes to dump.
     */
    static void Print(const void* buf, int len) {
        printf("%s", Dump(buf, len).c_str());
    }

    /**
     * @brief Prints a hexadecimal dump of a vector of bytes to the standard output.
     * @param data The vector of bytes to dump.
     */
    static void Print(const std::vector<uint8_t>& data) {
        Print(data.data(), data.size());
    }
};