#include "unit/test.h"

#include "filetrace/process.h"

/* Arguments are written with '|' between them and stand for the kernel's NULs. */
static size_t args_of(const char *spec, char *out, size_t size)
{
    size_t n = 0;
    for (; *spec && n + 1 < size; spec++)
        out[n++] = *spec == '|' ? '\0' : *spec;
    if (n + 1 < size)
        out[n++] = '\0';
    out[n] = '\0';
    return n;
}

static void derives_scripts(void)
{
    static const struct {
        const char *exe;
        const char *args;
        const char *cwd;
        const char *script; /* nullptr: none */
    } cases[] = {
        /* Python */
        {"/usr/bin/python3.11", "python3|/srv/app/export.py|--all", "/home/u",
         "/srv/app/export.py"},
        {"/usr/bin/python3.11", "python3|export.py", "/srv/app", "/srv/app/export.py"},
        {"/usr/bin/python3.11", "python3|./bin/../export.py", "/srv/app", "/srv/app/export.py"},
        {"/usr/bin/python3.11", "python3|../../etc/x.py", "/srv/app", "/etc/x.py"},
        {"/usr/bin/python3.11", "python3|-W|ignore|x.py", "/srv/app", "/srv/app/x.py"},
        {"/usr/bin/python3.11", "python3|-Wignore|-X|dev|-u|x.py", "/srv", "/srv/x.py"},
        {"/usr/bin/python3.11", "python3|--check-hash-based-pycs|never|x.py", "/srv", "/srv/x.py"},
        {"/usr/bin/python3.11", "python3|-m|mypkg.cli|run", "/srv", "module:mypkg.cli"},
        {"/usr/bin/python3.11", "python3|-mhttp.server", "/srv", "module:http.server"},
        {"/usr/bin/python3.11", "python3|-um|pkg", "/srv", "module:pkg"},
        {"/usr/bin/python3.11", "python3|-c|import os; os.system('x.py')", "/srv", nullptr},
        {"/usr/bin/python3.11", "python3|-", "/srv", nullptr},
        {"/usr/bin/python3.11", "python3", "/srv", nullptr},
        {"/usr/bin/python3.11", "python3|-W", "/srv", nullptr},
        {"/usr/bin/python3.11", "python3|--|-dash.py", "/srv", "/srv/-dash.py"},
        {"/usr/bin/python3.13t", "python3.13t|x.py", "/srv", "/srv/x.py"},
        {"/opt/pypy/bin/pypy3", "pypy3|x.py", "/srv", "/srv/x.py"},
        {"/usr/bin/python3.11 (deleted)", "python3|x.py", "/srv", "/srv/x.py"},
        {"/usr/bin/python3.11", "/tmp/ftlab-py|send.py", "/srv", "/srv/send.py"},
        {"", "python3|x.py", "/tmp", "/tmp/x.py"},
        {"/usr/bin/python3.11", "python3|x.py", "", "x.py"},
        /* A title the process set for itself, padded as setproctitle leaves it. */
        {"/usr/bin/python3.11", "gunicorn: worker [app]|||", "/srv", nullptr},
        {"/usr/bin/python3.11", "worker||||", "/srv", nullptr},
        /* PHP */
        {"/usr/bin/php8.2", "php|artisan|queue:work", "/var/www/site1", "/var/www/site1/artisan"},
        {"/usr/bin/php8.2", "php|-d|memory_limit=1G|-f|/var/www/cron.php", "/",
         "/var/www/cron.php"},
        {"/usr/bin/php", "php|-dmemory_limit=1G|-n|run.php|--force", "/srv", "/srv/run.php"},
        {"/usr/bin/php", "php|-r|echo 1;", "/srv", nullptr},
        {"/usr/bin/php", "php|--|args", "/srv", nullptr},
        {"/usr/bin/php", "php|-S|0.0.0.0:8000|router.php", "/srv", "/srv/router.php"},
        {"/usr/bin/php-cgi8.2", "php-cgi|index.php", "/var/www", "/var/www/index.php"},
        /* PHP-FPM workers, whatever the executable is called. */
        {"/usr/sbin/php-fpm8.2", "php-fpm: pool site1||||", "/", "pool:site1"},
        {"/usr/sbin/php-fpm", "php-fpm: pool www", "/", "pool:www"},
        {"/usr/bin/perl", "php-fpm: pool site1|          |", "/", "pool:site1"},
        {"/usr/sbin/php-fpm8.2", "php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)", "/",
         nullptr},
        {"/usr/sbin/php-fpm8.2", "php-fpm: pool ", "/", nullptr},
        /* Node.js */
        {"/usr/bin/node", "node|--require|./tracing.js|server.js", "/srv/api",
         "/srv/api/server.js"},
        {"/usr/bin/node", "node|-r|dotenv/config|server.js", "/srv/api", "/srv/api/server.js"},
        {"/usr/bin/node", "node|--max-old-space-size=4096|dist/main.js", "/srv/api",
         "/srv/api/dist/main.js"},
        {"/usr/bin/node", "node|--inspect|app.js", "/srv/api", "/srv/api/app.js"},
        {"/usr/bin/node", "node|-e|require('x')", "/srv/api", nullptr},
        {"/usr/bin/node", "node|--eval=1", "/srv/api", nullptr},
        {"/usr/bin/nodejs", "nodejs|/usr/lib/node_modules/npm/bin/npm-cli.js|start", "/srv",
         "/usr/lib/node_modules/npm/bin/npm-cli.js"},
        /* Ruby */
        {"/usr/bin/ruby3.1", "ruby|-Ilib|-r|json|bin/sync.rb", "/srv", "/srv/bin/sync.rb"},
        {"/usr/bin/ruby", "ruby|-W0|-C|/srv|sync.rb", "/srv", "/srv/sync.rb"},
        {"/usr/bin/ruby", "ruby|-e|puts 1", "/srv", nullptr},
        /* Perl */
        {"/usr/bin/perl", "perl|-I|lib|-w|send.pl|/data/x", "/srv", "/srv/send.pl"},
        {"/usr/bin/perl", "perl|-MData::Dumper|-T|send.pl", "/srv", "/srv/send.pl"},
        {"/usr/bin/perl", "perl|-le|print 1", "/srv", nullptr},
        {"/usr/bin/perl", "perl|-0777|-ne|print|file", "/srv", nullptr},
        {"/usr/bin/perl", "perl|-pi.bak|-e|s/a/b/|file", "/srv", nullptr},
        {"/usr/bin/perl5.36.0", "perl|-x|script", "/srv", "/srv/script"},
        /* Shells */
        {"/usr/bin/dash", "sh|-c|tar cf - /data | nc host 9", "/", nullptr},
        {"/usr/bin/dash", "/bin/sh|-e|./backup.sh", "/root", "/root/backup.sh"},
        {"/usr/bin/bash", "bash|-o|pipefail|+x|run.sh", "/opt", "/opt/run.sh"},
        {"/usr/bin/bash", "bash|--rcfile|rc|-lc|make", "/opt", nullptr},
        {"/usr/bin/bash", "bash|-s|arg", "/opt", nullptr},
        {"/usr/bin/bash", "-bash", "/root", nullptr},
        {"/bin/busybox", "sh|job.sh", "/etc/cron.d", "/etc/cron.d/job.sh"},
        /* Lua */
        {"/usr/bin/lua5.4", "lua5.4|-l|socket|send.lua", "/srv", "/srv/send.lua"},
        /* Not interpreters */
        {"/usr/sbin/nginx", "nginx: worker process", "/", nullptr},
        {"/usr/bin/rsync", "rsync|-av|/data|backup:/", "/", nullptr},
        {"/usr/bin/python3-config", "python3-config|x.py", "/", nullptr},
        {"/usr/bin/phpize", "phpize|x.php", "/", nullptr},
    };
    char args[512];
    char out[FT_PATH_MAX];

    for (size_t i = 0; i < FT_ARRAY_LEN(cases); i++) {
        size_t len = args_of(cases[i].args, args, sizeof(args));
        out[0] = '\0';
        bool found = ft_script_derive(cases[i].exe, args, len, cases[i].cwd, out, sizeof(out));
        ft_test_checks++;
        if (found != (cases[i].script != nullptr) || (found && strcmp(out, cases[i].script) != 0)) {
            ft_test_failures++;
            fprintf(stderr, "%s:%d: case %zu (%s): got %s \"%s\", expected \"%s\"\n", __FILE__,
                    __LINE__, i, cases[i].args, found ? "script" : "none", out,
                    cases[i].script ? cases[i].script : "(none)");
        }
    }
}

static void joins_command_lines(void)
{
    char args[256];
    char out[256];
    size_t len;

    len = args_of("python3|-W|ignore|/srv/x.py", args, sizeof(args));
    CHECK_U64(ft_command_line(args, len, true, out, sizeof(out)), 27);
    CHECK_STR(out, "python3 -W ignore /srv/x.py");

    /* Without arguments a password or token in them stays out. */
    len = args_of("mysql|-uroot|-pS3cret|db", args, sizeof(args));
    ft_command_line(args, len, false, out, sizeof(out));
    CHECK_STR(out, "mysql");
    len = args_of("php-fpm: pool site1||||", args, sizeof(args));
    ft_command_line(args, len, true, out, sizeof(out));
    CHECK_STR(out, "php-fpm: pool site1");
    ft_command_line(args, len, false, out, sizeof(out));
    CHECK_STR(out, "php-fpm:");

    /* Control characters would break a table row. */
    len = args_of("python3|-c|import x\nx.run()\t", args, sizeof(args));
    ft_command_line(args, len, true, out, sizeof(out));
    CHECK_STR(out, "python3 -c import x x.run()");
    CHECK_U64(ft_command_line(args, 0, true, out, sizeof(out)), 0);
    CHECK_STR(out, "");
}

static void stays_within_bounds(void)
{
    static char args[FT_CMDLINE_MAX];
    static char cwd[FT_PATH_MAX];
    char small[16];
    char out[FT_PATH_MAX];

    memset(args, 'a', sizeof(args) - 1);
    args[sizeof(args) - 1] = '\0';
    CHECK_U64(ft_command_line(args, sizeof(args) - 1, true, small, sizeof(small)), 15);
    CHECK_U64(strlen(small), 15);
    CHECK_U64(ft_command_line(args, sizeof(args) - 1, true, out, sizeof(out)), FT_PATH_MAX - 1);

    /* A working directory as long as a path can be leaves no room for the script's name. */
    memset(cwd, 'd', sizeof(cwd) - 1);
    cwd[0] = '/';
    size_t len = args_of("python3|export.py", args, sizeof(args));
    CHECK(ft_script_derive("/usr/bin/python3", args, len, cwd, out, sizeof(out)));
    CHECK_STR(out, "export.py");
    CHECK(
        ft_script_derive("/usr/bin/python3", args, len, "/srv/application", small, sizeof(small)));
    CHECK_STR(small, "export.py");

    len = args_of("python3|-m|a.very.long.module.name", args, sizeof(args));
    CHECK(ft_script_derive("/usr/bin/python3", args, len, "/srv", small, sizeof(small)));
    CHECK_U64(strlen(small), sizeof(small) - 1);
}

void test_process(void)
{
    derives_scripts();
    joins_command_lines();
    stays_within_bounds();
}
