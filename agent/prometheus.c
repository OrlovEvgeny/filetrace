#include "agent/telemetry.h"

#include "exporters/exporters.h"
#include "filetrace/clock.h"
#include "filetrace/net.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

constexpr size_t MAX_CONNECTIONS = 8;
constexpr uint64_t TIMEOUT_NS = 5 * FT_NS_PER_SEC;

struct connection {
    int fd;
    size_t slot;
    uint64_t deadline_ns;
    size_t in_len;
    char in[2048];
    char *out; /* the whole response, once the request is read */
    size_t out_len;
    size_t out_off;
};

struct ft_scrape {
    struct ft_telemetry_source src;
    int listen_fd;
    size_t listen_slot;
    struct connection conns[MAX_CONNECTIONS];
    size_t count;
};

struct ft_scrape *ft_scrape_open(const struct ft_prometheus_config *cfg,
                                 const struct ft_telemetry_source *src, struct ft_error *err)
{
    struct ft_net_addr addr;
    struct ft_error why = {0};

    if (!ft_net_addr_parse(cfg->listen, &addr) || ft_net_addr_is_unix(&addr)) {
        ft_error_set(err, FT_EXIT_CONFIG,
                     "[prometheus] listen = \"%s\" is not an address and port, such as "
                     "\"127.0.0.1:9464\".",
                     cfg->listen);
        return nullptr;
    }
    struct ft_scrape *s = calloc(1, sizeof(*s));
    if (!s) {
        ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
        return nullptr;
    }
    s->src = *src;
    s->listen_fd = ft_net_listen(&addr, &why);
    if (s->listen_fd < 0) {
        ft_error_set(err, FT_EXIT_EXPORTER, "Cannot serve metrics on %s: %s", cfg->listen, why.msg);
        free(s);
        return nullptr;
    }
    ft_log(FT_LOG_INFO, "serving metrics on http://%s/metrics", cfg->listen);
    return s;
}

static void drop(struct ft_scrape *s, size_t index)
{
    close(s->conns[index].fd);
    free(s->conns[index].out);
    s->conns[index] = s->conns[--s->count];
}

void ft_scrape_close(struct ft_scrape *s)
{
    if (!s)
        return;
    while (s->count)
        drop(s, s->count - 1);
    close(s->listen_fd);
    free(s);
}

static void respond(struct ft_scrape *s, struct connection *c, uint64_t now_ns)
{
    static const char page[] = "/metrics";
    const char *target = strchr(c->in, ' ');
    const char *status = "404 Not Found";
    char *body = nullptr;
    size_t body_len = 0;

    target = target ? target + 1 : "";
    size_t target_len = strcspn(target, " ?\r\n");
    if (strncmp(c->in, "GET ", 4) != 0) {
        status = "405 Method Not Allowed";
    } else if (target_len == sizeof(page) - 1 && strncmp(target, page, target_len) == 0) {
        FILE *f = open_memstream(&body, &body_len);
        if (f) {
            struct ft_metric_attr resource[FT_RESOURCE_ATTRS];
            struct ft_prometheus writer;

            ft_telemetry_resource(&s->src, resource);
            ft_prometheus_begin(&writer, f, resource, FT_RESOURCE_ATTRS);
            ft_telemetry_collect(&s->src, now_ns, ft_prometheus_point, &writer);
            fclose(f);
            status = "200 OK";
        } else {
            status = "500 Internal Server Error";
        }
    }

    FILE *f = open_memstream(&c->out, &c->out_len);
    if (f) {
        fprintf(f,
                "HTTP/1.1 %s\r\n"
                "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n"
                "\r\n",
                status, body_len);
        if (body_len)
            fwrite(body, 1, body_len, f);
        fclose(f);
    }
    free(body);
}

/* Returns false once the connection has nothing more to do. */
static bool advance(struct ft_scrape *s, struct connection *c, short revents, uint64_t now_ns)
{
    if (!c->out && (revents & (POLLIN | POLLHUP | POLLERR))) {
        ssize_t n = read(c->fd, c->in + c->in_len, sizeof(c->in) - 1 - c->in_len);
        if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
            return false;
        if (n > 0) {
            c->in_len += (size_t)n;
            c->in[c->in_len] = '\0';
        }
        if (strstr(c->in, "\r\n\r\n"))
            respond(s, c, now_ns);
        else if (c->in_len == sizeof(c->in) - 1)
            return false;
        if (!c->out)
            return true;
    }
    while (c->out && c->out_off < c->out_len) {
        ssize_t n = write(c->fd, c->out + c->out_off, c->out_len - c->out_off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return errno == EAGAIN || errno == EWOULDBLOCK;
        }
        c->out_off += (size_t)n;
    }
    return !c->out;
}

void ft_scrape_poll(struct ft_scrape *s, struct ft_poller *p)
{
    if (!s)
        return;
    s->listen_slot =
        s->count < MAX_CONNECTIONS ? ft_poller_add(p, s->listen_fd, POLLIN) : FT_POLLER_NONE;
    for (size_t i = 0; i < s->count; i++) {
        struct connection *c = &s->conns[i];
        c->slot = ft_poller_add(p, c->fd, c->out ? POLLOUT : POLLIN);
        ft_poller_wake_by(p, c->deadline_ns);
    }
}

void ft_scrape_dispatch(struct ft_scrape *s, const struct ft_poller *p, uint64_t now_ns)
{
    if (!s)
        return;
    for (size_t i = s->count; i-- > 0;) {
        struct connection *c = &s->conns[i];
        short revents = ft_poller_revents(p, c->slot);

        if (now_ns >= c->deadline_ns || (revents && !advance(s, c, revents, now_ns)))
            drop(s, i);
    }
    while (s->count < MAX_CONNECTIONS && (ft_poller_revents(p, s->listen_slot) & POLLIN)) {
        int fd = ft_net_accept(s->listen_fd);
        if (fd < 0)
            break;
        s->conns[s->count++] = (struct connection){
            .fd = fd,
            .slot = FT_POLLER_NONE,
            .deadline_ns = now_ns + TIMEOUT_NS,
        };
    }
}
