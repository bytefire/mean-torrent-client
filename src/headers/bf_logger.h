#ifndef BF_LOGGER_H
#define BF_LOGGER_H

#pragma once

void print_time(FILE *fp);

void print_thread_id(FILE *fp);

void bf_logger_init(char *filename);

int bf_log(const char *format, ...);

int bf_log_binary(const char *description, uint8_t *data, int len);

void bf_logger_end();

#endif // BF_LOGGER_H
