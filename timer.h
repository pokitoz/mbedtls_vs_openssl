#pragma once

#include <stdlib.h>


typedef struct {
  double time_spent_ca_load;
  double time_spent_cert_load;
  double time_spent_key_load;
  double time_spent_sign;
  double time_spent_hmac;
} TTimerResult;


#define C_TIMER_CLOCK(func, var) \
  { \
    const clock_t begin = clock(); \
    func; \
    var += (double)(clock() - begin) / CLOCKS_PER_SEC; \
  }
