#define LITCHI_IMPLEMENTATION
#include "litchi.h"

#define CFLAGS "-Wall", "-Wextra", "-std=c99", "-pedantic"

int main(int argc, char **argv) {
  TCHI_GO_REBUILD_URSELF(argc, argv);

  TCHI_CMD("gcc", "-o", "test", "test.c", CFLAGS);
  TCHI_CMD("./test");

  return 0;
}
