SKYNET_PATH = skynet

include $(SKYNET_PATH)/platform.mk

CC ?= gcc
SHARED := -fPIC --shared
CFLAGS = -g -O2 -Wall

LUA_INC ?= $(SKYNET_PATH)/3rd/lua

# https : turn on TLS_MODULE to add https support

TLS_MODULE=ltls
TLS_INC=/usr/local/include
TLS_LIB=/usr/local/lib


LUA_CLIB_PATH ?= lib/c
CSERVICE_PATH ?= service/c

CSERVICE = mmlogger
LUA_CLIB = $(TLS_MODULE)

all : \
  $(foreach v, $(CSERVICE), $(CSERVICE_PATH)/$(v).so) \
  $(foreach v, $(LUA_CLIB), $(LUA_CLIB_PATH)/$(v).so) 

$(LUA_CLIB_PATH) :
	mkdir $(LUA_CLIB_PATH)

$(CSERVICE_PATH) :
	mkdir $(CSERVICE_PATH)

define CSERVICE_TEMP
  $$(CSERVICE_PATH)/$(1).so : src/service_$(1).c | $$(CSERVICE_PATH)
	$$(CC) $$(CFLAGS) $$(SHARED) $$< -o $$@ -I$(SKYNET_PATH)/skynet-src
endef

$(foreach v, $(CSERVICE), $(eval $(call CSERVICE_TEMP,$(v))))

$(LUA_CLIB_PATH)/ltls.so : $(SKYNET_PATH)/lualib-src/ltls.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) -I$(TLS_INC) -L$(TLS_LIB) $^ -o $@ -lssl


clean :
	rm -rf $(CSERVICE_PATH)/*
	rm -rf $(LUA_CLIB_PATH)/*
