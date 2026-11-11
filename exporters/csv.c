#include "exporters/exporters.h"

#include <string.h>

void ft_csv_field(FILE *out, const char *s)
{
    if (!strpbrk(s, ",\"\r\n")) {
        fputs(s, out);
        return;
    }
    fputc('"', out);
    for (; *s; s++) {
        if (*s == '"')
            fputc('"', out);
        fputc(*s, out);
    }
    fputc('"', out);
}
