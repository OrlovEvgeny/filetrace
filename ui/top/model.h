#ifndef FILETRACE_TOP_MODEL_H
#define FILETRACE_TOP_MODEL_H

#include "filetrace/wire.h"

struct ft_top_model;

/* "512B", "51K", "38.4M", "2.1G", "1.84T": powers of 1024. */
void ft_top_format_size(uint64_t bytes, char *buf, size_t size);
/* The same with "/s". */
void ft_top_format_rate(uint64_t bytes_per_second, char *buf, size_t size);
/* "0.3s", "21s", "4:57", "1h00", "3d04". */
void ft_top_format_age(uint64_t ns, char *buf, size_t size);
/* " 63%", "100%": four columns; 100% only for a whole. */
void ft_top_format_percent(double share, char *buf, size_t size);

#endif
