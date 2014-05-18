#include<stdio.h>
#include<stdlib.h>
#include<stdarg.h>

FILE *logfp = NULL;
char *logfn = NULL;

void bf_logger_init(char *filename)
{
	logfn = filename;
	logfp = fopen(logfn, "w");
	if(!logfp)
	{
		fprintf(stderr, "[FROM LOGGER]: unable to create log file.\n");
		logfn = NULL;
		return;
	}
	fprintf(logfp, "Start of log file.\n\n");
	fclose(logfp);
}

int bf_log(const char *format, ...)
{
	if(!logfn)
	{
		fprintf(stderr, "[FROM LOGGER]: unable to log the message as the log file has not been initialised.\n");
		return -1;
	}

	logfp = fopen(logfn, "a");
	if(!logfp)
	{
		fprintf(stderr, "[FROM LOGGER]: unable to open log file.\n");
		return -1;
	}

	va_list argptr;
	va_start(argptr, format);
	vfprintf(logfp, format, argptr);
	// output to standard output too
	printf(format);
	va_end(argptr);
	
	fclose(logfp);

	return 0;
}

void bf_logger_end()
{
	bf_log("\nEnd of log file.\n");
	logfn = NULL;
}
