#ifndef FILETRACE_CLIENT_H
#define FILETRACE_CLIENT_H

#include "filetrace/wire.h"

#include <signal.h>

struct ft_client;

/* Returns nullptr and fills err on failure. */
struct ft_client *ft_client_connect(const char *socket_path, struct ft_error *err);

/* The client takes ownership of fd. */
struct ft_client *ft_client_adopt(int fd);

void ft_client_close(struct ft_client *c);

typedef void ft_client_row_fn(void *ctx, uint16_t type, const void *payload, size_t size);

int ft_client_query(struct ft_client *c, const struct ft_query *q, ft_client_row_fn *on_row,
                    void *ctx, struct ft_msg_end *end, struct ft_error *err);

/* A query that is waiting for rows returns FT_EXIT_OK soon after *stop becomes nonzero.
   The connection is then out of step and good only for closing. */
void ft_client_stop_on(struct ft_client *c, const volatile sig_atomic_t *stop);

int ft_client_shutdown(struct ft_client *c, struct ft_error *err);

bool ft_wire_send(int fd, uint16_t type, const void *payload, size_t size);

#endif
