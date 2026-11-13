#include "backends/linux/linux.h"

#include "filetrace/format.h"

#include <bpf/libbpf.h>
#include <inttypes.h>
#include <string.h>

static bool starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/* libssl, by the name its package installs and the SONAME other builds map it under. */
static bool openssl_mapped(const char *path, const char *name)
{
    (void)path;
    return starts_with(name, "libssl.so");
}

static bool gnutls_mapped(const char *path, const char *name)
{
    (void)path;
    return starts_with(name, "libgnutls.so");
}

static bool exports_all(int fd, const char *const *names, size_t count)
{
    bool found[8];
    if (count > FT_ARRAY_LEN(found) || !ft_linux_elf_exports(fd, names, count, found, nullptr))
        return false;
    for (size_t i = 0; i < count; i++) {
        if (!found[i])
            return false;
    }
    return true;
}

static uint64_t openssl_cookie(int fd)
{
    static const char *const names[] = {"SSL_ctrl", "SSL_connect", "SSL_do_handshake", "SSL_free"};
    return exports_all(fd, names, FT_ARRAY_LEN(names));
}

static uint64_t gnutls_cookie(int fd)
{
    static const char *const names[] = {"gnutls_server_name_set", "gnutls_handshake",
                                        "gnutls_deinit"};
    return exports_all(fd, names, FT_ARRAY_LEN(names));
}

static void tls_probed(const char *name, uint32_t pid, uint64_t cookie)
{
    (void)cookie;
    ft_log(FT_LOG_INFO, "probing TLS server names in %s, as process %" PRIu32 " maps it", name,
           pid);
}

bool ft_linux_tls_open(struct bpf_object *obj, struct ft_linux_prober *prober, size_t ssl_capacity,
                       size_t gnutls_capacity, struct ft_linux_tls *out)
{
    struct bpf_program *ctrl = bpf_object__find_program_by_name(obj, "ft_ssl_ctrl");
    struct bpf_program *connect = bpf_object__find_program_by_name(obj, "ft_ssl_connect");
    struct bpf_program *connect_ret =
        bpf_object__find_program_by_name(obj, "ft_ssl_connect_return");
    struct bpf_program *handshake = bpf_object__find_program_by_name(obj, "ft_ssl_do_handshake");
    struct bpf_program *handshake_ret =
        bpf_object__find_program_by_name(obj, "ft_ssl_do_handshake_return");
    struct bpf_program *free_ssl = bpf_object__find_program_by_name(obj, "ft_ssl_free");
    struct bpf_program *name_set =
        bpf_object__find_program_by_name(obj, "ft_gnutls_server_name_set");
    struct bpf_program *gnutls_hs = bpf_object__find_program_by_name(obj, "ft_gnutls_handshake");
    struct bpf_program *gnutls_hs_ret =
        bpf_object__find_program_by_name(obj, "ft_gnutls_handshake_return");
    struct bpf_program *deinit = bpf_object__find_program_by_name(obj, "ft_gnutls_deinit");
    if (!ctrl || !connect || !connect_ret || !handshake || !handshake_ret || !free_ssl ||
        !name_set || !gnutls_hs || !gnutls_hs_ret || !deinit)
        return false;

    struct ft_linux_probe_kind openssl = {
        .one = "the OpenSSL library",
        .many = "OpenSSL libraries",
        .capacity = ssl_capacity,
        .probes = {{ctrl, "SSL_ctrl", false},
                   {connect, "SSL_connect", false},
                   {connect_ret, "SSL_connect", true},
                   {handshake, "SSL_do_handshake", false},
                   {handshake_ret, "SSL_do_handshake", true},
                   {free_ssl, "SSL_free", false}},
        .every_process = true,
        .mapped = openssl_mapped,
        .cookie = openssl_cookie,
        .probed = tls_probed,
    };
    struct ft_linux_probe_kind gnutls = {
        .one = "the GnuTLS library",
        .many = "GnuTLS libraries",
        .capacity = gnutls_capacity,
        .probes = {{name_set, "gnutls_server_name_set", false},
                   {gnutls_hs, "gnutls_handshake", false},
                   {gnutls_hs_ret, "gnutls_handshake", true},
                   {deinit, "gnutls_deinit", false}},
        .every_process = true,
        .mapped = gnutls_mapped,
        .cookie = gnutls_cookie,
        .probed = tls_probed,
    };
    out->openssl = ft_linux_prober_add(prober, &openssl);
    out->gnutls = ft_linux_prober_add(prober, &gnutls);
    return out->openssl >= 0 && out->gnutls >= 0;
}
