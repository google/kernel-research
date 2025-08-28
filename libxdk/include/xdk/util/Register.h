#pragma once

/**
 * @defgroup util_classes Utility Classes
 * @brief Helper classes for various utilities.
 */

/**
 * @ingroup util_classes
 * @brief Enum representing x86-64 general-purpose registers.
 */
enum class Register { RAX = 0, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8, R9, R10, R11, R12, R13, R14, R15 };

/**
 * @ingroup util_classes
 * @brief An array of human-readable names for the Register enum values.
 */
extern const char* register_names[];
