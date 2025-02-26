#pragma once

template <typename T>
T align(T number, T alignment) {
    return (number + alignment - 1) & ~(alignment - 1);
}