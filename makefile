CC       := gcc
CFLAGS   := -std=c99 -Wall -Wextra -g
LDFLAGS  := -lm

INCLUDE  := -Iinclude
SRC      := vmcache_sim3.c
OBJ      := $(SRC:.c=.o)
TARGET   := VMCacheSim3

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(INCLUDE) -o $(TARGET) $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)