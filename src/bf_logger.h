#include<stdio.h>
#include<stdlib.h>
#include<stdarg.h>
#include<time.h>
#include<string.h>
#include<stdint.h>
#include<pthread.h>

FILE *logfp = NULL;
char *logfn = NULL;
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;

void print_time(FILE *fp)
{
	time_t timer;
	time(&timer);
	char *timestr = ctime(&timer);
	timestr[strlen(timestr) - 2] = '\0'; // remove the \n
	fprintf(fp, "[%s] ", timestr);
}

void bf_logger_init(char *filename)
{

	pthread_mutex_lock(&mutex1);

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

	pthread_mutex_unlock(&mutex1);
}

int bf_log(const char *format, ...)
{
	pthread_mutex_lock(&mutex1);
	
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
	
	print_time(logfp);

	va_list argptr;
	va_start(argptr, format);
	vfprintf(logfp, format, argptr);
	// output to standard output too
	printf(format);
	va_end(argptr);
	
	fclose(logfp);

	pthread_mutex_unlock(&mutex1);

	return 0;
}

int bf_log_binary(const char *description, uint8_t *data, int len)
{
	pthread_mutex_lock(&mutex1);
	
	if(!logfn)
	{
		fprintf(stderr, "[FROM LOGGER]: bf_log_binary: unable to log the message as the log file has not been initialised.\n");
		return -1;
	}

	logfp = fopen(logfn, "a");
	if(!logfp)
	{
		fprintf(stderr, "[FROM LOGGER]: bf_log_binary: unable to open log file.\n");
		return -1;
	}

	print_time(logfp);
	
	fprintf(logfp, description);
	int i;
	for(i=0; i<len; i++)
	{
		fprintf(logfp, "%x", data[i]);
	}

	pthread_mutex_unlock(&mutex1);	

	return 0;
}

void bf_logger_end()
{
	bf_log("\nEnd of log file.\n");
	logfn = NULL;
}
