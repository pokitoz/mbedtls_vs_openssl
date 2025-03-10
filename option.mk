ifeq ($(DEBUG), 1)
	CFLAGS= -Wall -g3 -std=c11
else
	CFLAGS= -Wall -O2 -std=c11
endif

LFLAGS= -ldl -lz