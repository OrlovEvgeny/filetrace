#ifndef FILETRACE_TOP_DOCUMENT_H
#define FILETRACE_TOP_DOCUMENT_H

#include "ui/top/model.h"

#include <stdio.h>

/*
 * A mode's rows as the screen shows them, with what the meters show, as one JSON document ending
 * in a newline: indented, or on one line. Returns the rows written.
 */
size_t ft_top_write_document(const struct ft_top_model *m, enum ft_top_mode mode, bool indent,
                             FILE *out);

/* The same rows as CSV under a header line. Returns the rows written. */
size_t ft_top_write_csv(const struct ft_top_model *m, enum ft_top_mode mode, FILE *out);

#endif
