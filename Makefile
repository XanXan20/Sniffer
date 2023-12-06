TARGET = sniffer
CC = gcc
CFLAGS = -Wall -Wextra -Werror
RM = rm -rf
SRCS = main.c net_access_layer.c network_layer.c transport_layer.c application_layer.c
BUILD_DIR = build
OBJS = $(patsubst %.c, $(BUILD_DIR)/%.o, $(SRCS))

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/%.o: %.c include | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	$(RM) $(BUILD_DIR) $(TARGET)