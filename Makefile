CC = gcc
CFLAGS = -Wall -Wextra -O3
LDFLAGS = -lcurl -luv

ifeq ($(OS),Windows_NT)
    LDFLAGS += -lws2_32
endif
SRC = main.c
TARGET = http1-to-http3
all: $(TARGET)
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)
clean:
	rm -f $(TARGET)
.PHONY: all clean
