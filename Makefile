CC = gcc
CFLAGS = -Wall -Wextra -O3
LDFLAGS = -lcurl -luv
SRC = main.c
TARGET = http1-to-http3
all: $(TARGET)
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)
clean:
	rm -f $(TARGET)
.PHONY: all clean
