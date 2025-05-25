#include "kernel/types.h"
#include "user/user.h"

int main() {
  trace();             // Enable tracing
  printf("Hello\n");   // Test a syscall
  exit(0);
}
