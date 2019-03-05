#include "skynet.h"
#include "skynet_timer.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

struct mmlogger {
	FILE * handle;
	char * filename;
	int close;
};

struct mmlogger *
mmlogger_create(void) {
	struct mmlogger * inst = skynet_malloc(sizeof(*inst));
	inst->handle = NULL;
	inst->close = 0;
	inst->filename = NULL;

	return inst;
}

void
mmlogger_release(struct mmlogger * inst) {
	if (inst->close) {
		fclose(inst->handle);
	}
	skynet_free(inst->filename);
	skynet_free(inst);
}

static int
mmlogger_cb(struct skynet_context * context, void *ud, int type, int session, uint32_t source, const void * msg, size_t sz) {
	struct mmlogger * inst = ud;
	switch (type) {
	case PTYPE_SYSTEM:
		if (inst->filename) {
			inst->handle = freopen(inst->filename, "a", inst->handle);
		}
		break;
	case PTYPE_TEXT: 
		{
			uint32_t starttime = skynet_starttime();
			uint64_t currenttime = skynet_now();
			time_t ti = starttime + currenttime/100;

			struct tm *date= NULL;
			date = localtime(&ti);

			fprintf(inst->handle, "[:%08x][%d/%d %.2d:%.2d:%.2d-%lu] ", source, date->tm_mon, date->tm_mday, date->tm_hour, date->tm_min, date->tm_sec, ti);
			fwrite(msg, sz , 1, inst->handle);
			fprintf(inst->handle, "\n");
			fflush(inst->handle);
		}
		break;
	}

	return 0;
}

int
mmlogger_init(struct mmlogger * inst, struct skynet_context *ctx, const char * parm) {
	if (parm) {
		inst->handle = fopen(parm,"w");
		if (inst->handle == NULL) {
			return 1;
		}
		inst->filename = skynet_malloc(strlen(parm)+1);
		strcpy(inst->filename, parm);
		inst->close = 1;
	} else {
		inst->handle = stdout;
	}
	if (inst->handle) {
		skynet_callback(ctx, inst, mmlogger_cb);
		skynet_command(ctx, "REG", ".logger");
		return 0;
	}
	return 1;
}
