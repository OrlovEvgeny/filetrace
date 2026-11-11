#include "backends/backend.h"

#include <stdio.h>

#if defined(__APPLE__)
#define FT_MISSING_BACKEND                                                                         \
    "collection on macOS needs an Endpoint Security system extension, "                            \
    "which this build does not include"
#elif defined(__FreeBSD__)
#define FT_MISSING_BACKEND                                                                         \
    "collection on FreeBSD needs a DTrace backend, which this build does not include"
#else
#define FT_MISSING_BACKEND "this build has no collection backend for this operating system"
#endif

static void diagnose(const struct ft_backend_config *cfg, struct ft_diagnosis *out)
{
    (void)cfg;
    snprintf(out->backend, sizeof(out->backend), "none");
    ft_diagnosis_add(out, FT_CHECK_FAIL, false, "Collection backend", "%s", FT_MISSING_BACKEND);
    ft_capability_set_all(&out->caps, FT_CAP_UNAVAILABLE, FT_MISSING_BACKEND);
    out->exit_code = FT_EXIT_UNSUPPORTED;
    snprintf(out->result, sizeof(out->result), "Monitoring unavailable");
    snprintf(out->advice, sizeof(out->advice),
             "This build collects on Linux only. Here the filetrace command can still\n"
             "query a daemon whose socket is reachable and report diagnostics.");
}

static struct ft_backend *open_backend(const struct ft_backend_config *cfg,
                                       const struct ft_sink *sink, struct ft_error *err)
{
    (void)cfg;
    (void)sink;
    ft_error_set(err, FT_EXIT_UNSUPPORTED, "Monitoring is unavailable: " FT_MISSING_BACKEND ".");
    return nullptr;
}

static const struct ft_backend_ops ops = {
    .name = "none",
    .diagnose = diagnose,
    .open = open_backend,
};

const struct ft_backend_ops *ft_backend_native(void)
{
    return &ops;
}
