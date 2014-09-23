#ifndef UTIL_H
#define UTIL_H

#pragma once

int util_read_whole_file(char *filename, uint8_t **contents, int *file_len);

int util_hex_to_ba(char *hex, uint8_t *ba);

void util_append_to_file(char *filename, char *str, int len);

int util_create_file_of_size(const char *file_name, long bytes);

int util_read_file_chunk(char *filename, int start_idx, int chunk_len,  uint8_t *contents);

// concatenates the two null terminated strings and returns a newly malloc'd combined string.
char *util_concatenate(char *str1, char *str2);

int util_copy_file(char *src_path, char *dest_path);

char *util_extract_filename(char *path);

int util_write_new_file(char *filename, uint8_t *contents, int len);

#endif // UTIL_H
