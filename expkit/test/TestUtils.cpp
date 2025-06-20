#include <cstring>
#include "test/TestUtils.hpp"

void TestUtils::eq(const char* expected, const char* actual, const char* name) {
  if (strcmp(expected, actual))
    throw ExpKitError("expected '%s' but got '%s' for %s", expected, actual,
                      name);
}
