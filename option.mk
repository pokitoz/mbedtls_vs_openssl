
CFLAGS = -std=c11

ifeq ($(DEBUG), 1)
	CFLAGS += -Wall -g3 -O0
else
	CFLAGS += -Wall -O2
endif

LFLAGS= -ldl -lz -lpthread
