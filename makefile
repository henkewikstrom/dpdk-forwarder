CC      := gcc
CFLAGS  := -Wall -Wextra -O3 $(EXTRA_CFLAGS)
LDFLAGS :=

LOG_LEVEL    ?= RTE_LOG_INFO
LOG_LEVEL_DP ?= RTE_LOG_NOTICE

CFLAGS += -DAPP_LOG_LEVEL=$(LOG_LEVEL) -DRTE_LOG_DP_LEVEL=$(LOG_LEVEL_DP)

PKGS    := libdpdk

CFLAGS  += $(shell pkg-config --cflags $(PKGS))
LDFLAGS += $(shell pkg-config --libs   $(PKGS))

SRC_DIR := src
OBJ_DIR := build
BIN_DIR := bin

TARGET  := $(BIN_DIR)/dpdk_forwarder

SRCS    := $(wildcard $(SRC_DIR)/*.c)
OBJS    := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

DEPS    := $(OBJS:.o=.d)

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $^ $(LDFLAGS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(DEPS)

$(OBJ_DIR) $(BIN_DIR):
	mkdir -p $@

.PHONY: debug
debug:
	$(MAKE) re LOG_LEVEL=RTE_LOG_DEBUG LOG_LEVEL_DP=RTE_LOG_DEBUG \
				EXTRA_CFLAGS="-O0 -g"

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: purge
purge: clean
	rm -rf flow_stats_core*.csv

.PHONY: re
re: clean all

.PHONY: print-%
print-%:
	@echo $* = $($*)