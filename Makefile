SKYNET_PATH = skynet

include $(SKYNET_PATH)/platform.mk

CC ?= gcc
SHARED := -fPIC --shared
CFLAGS = -g -O2 -Wall

LUA_INC ?= $(SKYNET_PATH)/3rd/lua

LUA_CLIB_PATH ?= lib/c
CSERVICE_PATH ?= service/c

CSERVICE = mmlogger
LUA_CLIB = ssl

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

$(LUA_CLIB_PATH)/ssl.so : src/lua-ssl.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC) -I/usr/local/include -lssl -L/usr/local/lib

clean :
	rm -rf $(CSERVICE_PATH)/*
	rm -rf $(LUA_CLIB_PATH)/*
