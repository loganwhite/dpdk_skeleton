export RTE_SDK=/home/ubuntu/dpdk-stable-19.11.14
export RTE_TARGET=x86_64-native-linuxapp-gcc

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc
RTE_LOG_LEVEL=RTE_LOG_DEBUG
RTE_LIBRTE_ETHDEV_DEBUG=n

include $(RTE_SDK)/mk/rte.vars.mk

ifneq ($(CONFIG_RTE_EXEC_ENV),"linuxapp")
$(error This application can only operate in a linuxapp environment, \
please change the definition of the RTE_TARGET environment variable)
endif

# binary name
APP = sketchlet

# all source are in the current directory
SRCS-y := main.c


INC := $(sort $(wildcard *.h))

CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I$(SRCDIR)/../shared

#LDFLAGS = -lhiredis
LDFLAGS=-libverbs

# for newer gcc, e.g. 4.4, no-strict-aliasing may not be necessary
# and so the next line can be removed in those cases.
EXTRA_CFLAGS += -fno-strict-aliasing
EXTRA_CFLAGS += -pthread
# EXTRA_CFLAGS += -g
EXTRA_CFLAGS += -O3
#EXTRA_CFLAGS += -DTIMERSTAT
#EXTRA_CFLAGS += -DTIMEFUNC
EXTRA_CFLAGS += -DXSTATS_ENABLE

include $(RTE_SDK)/mk/rte.extapp.mk
