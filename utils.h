#pragma once


#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

#define ARRAY_PRINT_SIZE_BYTES(x, s)                                           \
  {                                                                            \
    for (uint32_t i = 0; i < (s); i++) {                                       \
      printf("0x%02x ", x[i]);                                                 \
    }                                                                          \
    printf("\n");                                                              \
  }

#define ARRAY_PRINT_BYTES(x) ARRAY_PRINT_SIZE_BYTES(x, ARRAY_SIZE(x))