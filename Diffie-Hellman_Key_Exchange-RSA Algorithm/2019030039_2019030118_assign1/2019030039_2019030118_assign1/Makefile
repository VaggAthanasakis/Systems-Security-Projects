CC = gcc
CFLAGS = -I.
LDFLAGS = -lm -lgmp
DEPS = stdio.h stdlib.h string.h stdbool.h math.h gmp.h time.h 

SRC_DH = DiffieHellman.c
OBJS_DH = $(SRC_DH:.c=.o)
TARGET_DH = dh_assign_1

SRC_RSA = RSA.c
OBJS_RSA = $(SRC_RSA:.c=.o)
TARGET_RSA = rsa_assign_1

.PHONY: all clean

all: $(TARGET_DH) $(TARGET_RSA)

$(TARGET_DH): $(OBJS_DH)
	$(CC) -o $@ $^ $(LDFLAGS)

$(TARGET_RSA): $(OBJS_RSA)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f $(OBJS_DH) $(TARGET_DH) $(OBJS_RSA) $(TARGET_RSA)
