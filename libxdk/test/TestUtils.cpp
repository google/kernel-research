#include <cstring>
#include "test/TestUtils.h"

void TestUtils::eq(const char* expected, const char* actual, const char* name) {
  if (strcmp(expected, actual))
    throw ExpKitError("expected '%s' but got '%s' for %s", expected, actual,
                      name);
}
