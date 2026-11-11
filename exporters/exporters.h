#ifndef FILETRACE_EXPORTERS_H
#define FILETRACE_EXPORTERS_H

#include <stdio.h>

/* Writes s as a JSON string literal, including the quotes. */
void ft_json_string(FILE *out, const char *s);

/* Writes s as one CSV field, quoting it when RFC 4180 requires. */
void ft_csv_field(FILE *out, const char *s);

#endif
