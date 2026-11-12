#include "sim/scenario.h"

#include <stdlib.h>
#include <string.h>

#define KIB(n) ((uint64_t)(n) * 1024)
#define MIB(n) (KIB(n) * 1024)
#define GIB(n) (MIB(n) * 1024)

#define MINUTE 60u
#define HOUR (60u * MINUTE)
#define DAY (24u * HOUR)

/* Far from the ids a desktop system gives its own accounts, so no name is shown for them. */
enum : uint32_t {
    ROOT = 0,
    EVGENII = 10000,
    DEPLOY = 10001,
    APP = 10002,
    KAFKA = 10003,
    CLICKHOUSE = 10004,
    WWW_DATA = 10033,
    BACKUP = 10034,
    POSTGRES = 10114,
};

/* The tables are written a few rows to a line so that a process or a flavor takes few lines. */
/* clang-format off */

/* edge: a web and data host */

static const struct ft_sim_process edge_processes[] = {
    {.pid = 2210, .ppid = 1, .uid = ROOT, .comm = "nginx", .exe = "/usr/sbin/nginx",
     .cmdline = "nginx: master process /usr/sbin/nginx", .title = true, .cwd = "/",
     .service = "nginx.service", .listen_port = 443, .age_s = 12 * DAY},
    {.pid = 2214, .count = 5, .ppid = 2210, .uid = WWW_DATA, .comm = "nginx",
     .exe = "/usr/sbin/nginx", .cmdline = "nginx: worker process", .title = true, .forked = true,
     .cwd = "/", .age_s = 12 * DAY - 3 * HOUR},
    {.pid = 18800, .ppid = 1, .uid = ROOT, .comm = "php-fpm8.3", .exe = "/usr/sbin/php-fpm8.3",
     .cmdline = "php-fpm: master process (/etc/php/8.3/fpm/php-fpm.conf)", .title = true,
     .cwd = "/", .service = "php8.3-fpm.service", .age_s = 12 * DAY},
    {.pid = 18822, .count = 15, .ppid = 18800, .uid = WWW_DATA, .comm = "php-fpm8.3",
     .exe = "/usr/sbin/php-fpm8.3", .cmdline = "php-fpm: pool www", .title = true, .forked = true,
     .cwd = "/srv/app", .age_s = 2 * HOUR},
    {.pid = 12044, .ppid = 1, .uid = KAFKA, .comm = "java",
     .exe = "/usr/lib/jvm/java-21-openjdk-amd64/bin/java",
     .cmdline = "java -Xmx6g kafka.Kafka /opt/kafka/config/server.properties", .cwd = "/opt/kafka",
     .service = "kafka.service", .listen_port = 9092, .age_s = 31 * DAY},
    {.pid = 40112, .ppid = 1, .uid = BACKUP, .comm = "rclone", .exe = "/usr/bin/rclone",
     .cmdline = "rclone copy /srv/backups/pg s3:pg-backups", .cwd = "/srv/backups",
     .service = "backup-pg.service", .age_s = 6 * MINUTE},
    {.pid = 5120, .ppid = 1, .uid = DEPLOY, .comm = "rsync", .exe = "/usr/bin/rsync",
     .cmdline = "rsync -az --partial /srv/releases/ rsync://10.0.7.0/releases",
     .cwd = "/srv/releases", .service = "session-31.scope", .age_s = 2 * MINUTE},
    {.pid = 1190, .ppid = 1, .uid = POSTGRES, .comm = "postgres",
     .exe = "/usr/lib/postgresql/16/bin/postgres",
     .cmdline = "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main "
                "-c config_file=/etc/postgresql/16/main/postgresql.conf",
     .cwd = "/var/lib/postgresql/16/main", .service = "postgresql@16-main.service",
     .listen_port = 5432, .age_s = 45 * DAY},
    {.pid = 31877, .ppid = 1190, .uid = POSTGRES, .comm = "postgres",
     .exe = "/usr/lib/postgresql/16/bin/postgres",
     .cmdline = "postgres: 16/main: walsender replicator 10.0.4.12(41870)", .title = true,
     .forked = true, .cwd = "/var/lib/postgresql/16/main", .age_s = 9 * DAY},
    {.pid = 40877, .ppid = 1, .uid = CLICKHOUSE, .comm = "clickhouse-serv",
     .exe = "/usr/bin/clickhouse-server",
     .cmdline = "clickhouse-server --config=/etc/clickhouse-server/config.xml",
     .cwd = "/var/lib/clickhouse", .service = "clickhouse-server.service", .listen_port = 9009,
     .age_s = 20 * DAY},
    {.pid = 24410, .ppid = 1, .uid = DEPLOY, .comm = "python3", .exe = "/usr/bin/python3.12",
     .cmdline = "python3 /srv/ml/push_model.py --model brand-ner-v3", .cwd = "/srv/ml",
     .service = "session-33.scope", .age_s = 3 * MINUTE},
    {.pid = 988, .ppid = 1, .uid = ROOT, .comm = "sshd", .exe = "/usr/sbin/sshd",
     .cmdline = "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups", .title = true,
     .cwd = "/", .service = "ssh.service", .listen_port = 22, .age_s = 45 * DAY},
    {.pid = 9931, .ppid = 988, .uid = EVGENII, .comm = "sshd", .exe = "/usr/sbin/sshd",
     .cmdline = "sshd: evgenii@notty", .title = true, .forked = true, .cwd = "/home/evgenii",
     .service = "session-41.scope", .age_s = 8 * MINUTE},
    {.pid = 7702, .ppid = 1, .uid = APP, .comm = "node", .exe = "/usr/bin/node",
     .cmdline = "node /srv/media/server.js", .cwd = "/srv/media", .service = "media.service",
     .listen_port = 3000, .age_s = 6 * DAY},
    {.pid = 3301, .ppid = 1, .uid = ROOT, .comm = "filebeat",
     .exe = "/usr/share/filebeat/bin/filebeat", .cmdline = "filebeat -c /etc/filebeat/filebeat.yml",
     .cwd = "/", .service = "filebeat.service", .age_s = 45 * DAY},
    {0},
};

static const uint32_t kafka_pids[] = {12044, 0};
static const uint32_t rclone_pids[] = {40112, 0};
static const uint32_t rsync_pids[] = {5120, 0};
static const uint32_t walsender_pids[] = {31877, 0};
static const uint32_t clickhouse_pids[] = {40877, 0};
static const uint32_t python_pids[] = {24410, 0};
static const uint32_t sshd_pids[] = {9931, 0};
static const uint32_t node_pids[] = {7702, 0};
static const uint32_t filebeat_pids[] = {3301, 0};

static const struct ft_sim_flavor nginx_video[] = {
    {.weight = 6, .path = "/var/www/cdn/video/launch-2026-hd.mp4", .size_min = MIB(2140),
     .size_max = MIB(2140), .rate_min = 6144, .rate_max = 49152},
    {.weight = 2, .path = "/var/www/cdn/video/trailer-launch-2026.mp4", .size_min = MIB(96),
     .size_max = MIB(96), .rate_min = 4096, .rate_max = 30720},
    {.weight = 1, .path = "/var/www/cdn/video/ep12-1080p.mp4", .size_min = MIB(1430),
     .size_max = MIB(1430), .rate_min = 8192, .rate_max = 40960},
    {0},
};

static const struct ft_sim_flavor nginx_hls[] = {
    {.weight = 1, .path = "/var/www/cdn/video/hls/ep12/seg_%05llu.ts",
     .numbering = FT_SIM_NUMBER_EPOCH, .first = 418, .period_ms = 6000, .size_min = MIB(4),
     .size_max = MIB(4), .rate_min = 5120, .rate_max = 16384},
    {0},
};

static const struct ft_sim_flavor nginx_assets[] = {
    {.weight = 5, .path = "/var/www/cdn/assets/app.8f3c1a.js", .size_min = KIB(1434),
     .size_max = KIB(1434), .rate_min = 400, .rate_max = 9000},
    {.weight = 4, .path = "/var/www/cdn/assets/vendor.21ab9e.js", .size_min = KIB(2355),
     .size_max = KIB(2355), .rate_min = 400, .rate_max = 9000},
    {.weight = 3, .path = "/var/www/cdn/img/hero@2x.webp", .size_min = KIB(1229),
     .size_max = KIB(1229), .rate_min = 400, .rate_max = 9000},
    {.weight = 4, .path = "/var/www/cdn/fonts/inter-var.woff2", .size_min = KIB(300),
     .size_max = KIB(300), .rate_min = 400, .rate_max = 9000},
    {.weight = 3, .path = "/var/www/cdn/assets/app.8f3c1a.css", .size_min = KIB(184),
     .size_max = KIB(184), .rate_min = 400, .rate_max = 9000},
    {.weight = 2, .path = "/var/www/cdn/img/logo.svg", .size_min = KIB(14), .size_max = KIB(14),
     .rate_min = 400, .rate_max = 9000},
    {0},
};

static const struct ft_sim_flavor php_requests[] = {
    {.weight = 6, .path = "/srv/app/storage/invoices/2026/11/INV-%05llu.pdf",
     .numbering = FT_SIM_NUMBER_RANDOM, .first = 48000, .last = 48999, .size_min = KIB(280),
     .size_max = KIB(450), .rate_min = 400, .rate_max = 3000,
     .script = "/srv/app/public/download.php"},
    {.weight = 2, .path = "/srv/app/storage/exports/users-2026-11.xlsx", .size_min = KIB(3890),
     .size_max = KIB(3890), .rate_min = 700, .rate_max = 2500,
     .script = "/srv/app/public/admin/export.php"},
    {.weight = 1, .path = "/srv/app/storage/exports/orders-2026-11.csv", .size_min = MIB(18),
     .size_max = MIB(18), .rate_min = 1000, .rate_max = 4000,
     .script = "/srv/app/public/admin/export.php"},
    {.weight = 2, .path = "/srv/app/storage/attachments/2026/11/att-%05llu.pdf",
     .numbering = FT_SIM_NUMBER_RANDOM, .first = 10000, .last = 19999, .size_min = KIB(60),
     .size_max = MIB(6), .rate_min = 300, .rate_max = 3000,
     .script = "/srv/app/public/api/attachments.php"},
    {0},
};

static const struct ft_sim_dest kafka_dests[] = {{"10.0.5.22", 45910}, {"10.0.5.23", 45122}, {}};

static const struct ft_sim_flavor kafka_segments[] = {
    {.weight = 1, .path = "/var/lib/kafka/data/events-7/%020llu.log", .fs_type = "xfs",
     .numbering = FT_SIM_NUMBER_SEQUENCE, .first = 184220311, .step = 1048576,
     .size_min = GIB(1), .size_max = GIB(1), .rate_min = 63488, .rate_max = 75776},
    {.weight = 1, .path = "/var/lib/kafka/data/events-3/%020llu.log", .fs_type = "xfs",
     .numbering = FT_SIM_NUMBER_SEQUENCE, .first = 183990127, .step = 1048576,
     .size_min = GIB(1), .size_max = GIB(1), .rate_min = 59392, .rate_max = 65536},
    {0},
};

static const struct ft_sim_dest s3_dests[] = {{"52.219.170.52", 443}, {}};

static const struct ft_sim_flavor pg_backups[] = {
    {.weight = 7, .path = "/srv/backups/pg/base-2026-11-12.tar.zst", .size_min = MIB(42100),
     .size_max = MIB(42100), .rate_min = 58368, .rate_max = 64512},
    {.weight = 2, .path = "/srv/backups/pg/base-2026-11-11.tar.zst", .size_min = MIB(41160),
     .size_max = MIB(41160), .rate_min = 55296, .rate_max = 64512},
    {.weight = 1, .path = "/srv/backups/pg/wal-archive-2026-11-12.tar.zst",
     .size_min = MIB(11264), .size_max = MIB(11264), .rate_min = 58368, .rate_max = 65536},
    {0},
};

static const struct ft_sim_dest rsync_dests[] = {{"10.0.7.31", 873}, {"10.0.7.32", 873}, {}};

static const struct ft_sim_flavor release_archives[] = {
    {.weight = 1, .path = "/srv/releases/api-v4.18.%llu.tar.gz", .numbering = FT_SIM_NUMBER_EPOCH,
     .first = 2, .period_ms = 3 * MINUTE * 1000, .size_min = MIB(388), .size_max = MIB(388),
     .rate_min = 38912, .rate_max = 49152},
    {0},
};

static const struct ft_sim_dest replica_dests[] = {{"10.0.4.12", 41870}, {}};

static const struct ft_sim_flavor wal_segments[] = {
    {.weight = 1, .path = "/var/lib/postgresql/16/main/pg_wal/0000000100000A2B%08llX",
     .numbering = FT_SIM_NUMBER_SEQUENCE, .first = 0xF3, .step = 1, .size_min = MIB(16),
     .size_max = MIB(16), .rate_min = 18432, .rate_max = 28672},
    {0},
};

static const struct ft_sim_dest clickhouse_dests[] = {
    {"10.0.6.14", 9009}, {"fd00:10:6::15", 9009}, {},
};

static const struct ft_sim_flavor clickhouse_parts[] = {
    {.weight = 1, .path = "/var/lib/clickhouse/store/3c1/3c1e9a7b/all_1_%llu_9/data.bin",
     .fs_type = "xfs", .numbering = FT_SIM_NUMBER_SEQUENCE, .first = 412, .step = 1,
     .size_min = MIB(2310), .size_max = MIB(2310), .rate_min = 28672, .rate_max = 38912},
    {0},
};

static const struct ft_sim_dest registry_dests[] = {{"10.0.8.40", 443}, {}};

static const struct ft_sim_flavor models[] = {
    {.weight = 7, .path = "/srv/ml/models/brand-ner-v3.safetensors", .size_min = MIB(4480),
     .size_max = MIB(4480), .rate_min = 25600, .rate_max = 32768},
    {.weight = 3, .path = "/srv/ml/models/intent-clf-v7.safetensors", .size_min = MIB(1230),
     .size_max = MIB(1230), .rate_min = 25600, .rate_max = 32768},
    {0},
};

static const struct ft_sim_flavor dumps[] = {
    {.weight = 6, .path = "/home/evgenii/dumps/heap-2026-11-12.hprof", .size_min = MIB(1900),
     .size_max = MIB(1900), .rate_min = 10240, .rate_max = 14336},
    {.weight = 2, .path = "/home/evgenii/dumps/heap-2026-11-11.hprof", .size_min = MIB(1710),
     .size_max = MIB(1710), .rate_min = 9216, .rate_max = 13312},
    {.weight = 2, .path = "/home/evgenii/dumps/thread-dump-2026-11-12.txt", .size_min = KIB(3277),
     .size_max = KIB(3277), .rate_min = 3072, .rate_max = 8192},
    {0},
};

static const struct ft_sim_flavor media_requests[] = {
    {.weight = 1, .path = "/srv/media/exports/report-q3.csv", .size_min = MIB(120),
     .size_max = MIB(120), .rate_min = 8192, .rate_max = 12288},
    {.weight = 4, .path = "/srv/media/uploads/u/%04llx/avatar.png",
     .numbering = FT_SIM_NUMBER_RANDOM, .first = 0x1000, .last = 0xffff, .size_min = KIB(40),
     .size_max = KIB(120), .rate_min = 200, .rate_max = 2000},
    {0},
};

static const struct ft_sim_dest logstash_dests[] = {{"10.0.9.4", 5044}, {}};

static const struct ft_sim_flavor access_log[] = {
    {.weight = 1, .path = "/var/log/nginx/access.log", .size_min = MIB(15872),
     .size_max = MIB(15872), .rate_min = 4096, .rate_max = 4915},
    {0},
};

static const struct ft_sim_generator edge_generators[] = {
    {.name = "nginx-video", .parent = 2210, .method = FT_METHOD_SENDFILE, .slots = 4,
     .pause_min_ms = 4000, .pause_max_ms = 25000, .dest_kind = FT_SIM_DEST_PUBLIC,
     .local_port = 443, .chunk = MIB(2), .flavors = nginx_video},
    {.name = "nginx-hls", .parent = 2210, .method = FT_METHOD_SENDFILE, .slots = 8,
     .pause_min_ms = 600, .pause_max_ms = 2600, .dest_kind = FT_SIM_DEST_PUBLIC,
     .local_port = 443, .chunk = MIB(2), .flavors = nginx_hls},
    {.name = "nginx-assets", .parent = 2210, .method = FT_METHOD_SENDFILE, .slots = 5,
     .pause_min_ms = 400, .pause_max_ms = 5000, .dest_kind = FT_SIM_DEST_PUBLIC,
     .local_port = 443, .chunk = MIB(2), .flavors = nginx_assets},
    {.name = "php-fpm", .parent = 18800, .method = FT_METHOD_READ_SEND, .slots = 3,
     .pause_min_ms = 600, .pause_max_ms = 6000, .dest_kind = FT_SIM_DEST_PUBLIC,
     .local_port = 443, .chunk = KIB(8), .flavors = php_requests},
    {.name = "kafka", .pids = kafka_pids, .method = FT_METHOD_SENDFILE, .keep_socket = true,
     .steady = true, .flavor_by_slot = true, .slots = 2, .dest_kind = FT_SIM_DEST_LIST,
     .dests = kafka_dests, .local_port = 9092, .chunk = MIB(1), .flavors = kafka_segments},
    {.name = "rclone", .pids = rclone_pids, .method = FT_METHOD_READ_SEND, .outbound = true,
     .steady = true, .slots = 1, .pause_min_ms = 3000, .pause_max_ms = 10000,
     .dest_kind = FT_SIM_DEST_LIST, .dests = s3_dests, .chunk = MIB(1), .flavors = pg_backups},
    {.name = "rsync", .pids = rsync_pids, .method = FT_METHOD_READ_SEND, .outbound = true,
     .slots = 2, .pause_min_ms = 4000, .pause_max_ms = 20000, .dest_kind = FT_SIM_DEST_LIST,
     .dests = rsync_dests, .chunk = KIB(128), .flavors = release_archives},
    {.name = "walsender", .pids = walsender_pids, .method = FT_METHOD_READ_SEND,
     .keep_socket = true, .slots = 1, .pause_min_ms = 300, .pause_max_ms = 1500,
     .dest_kind = FT_SIM_DEST_LIST, .dests = replica_dests, .local_port = 5432,
     .chunk = KIB(128), .flavors = wal_segments},
    {.name = "clickhouse", .pids = clickhouse_pids, .method = FT_METHOD_READ_SEND,
     .outbound = true, .slots = 2, .pause_min_ms = 3000, .pause_max_ms = 25000,
     .dest_kind = FT_SIM_DEST_LIST, .dests = clickhouse_dests, .chunk = MIB(1),
     .flavors = clickhouse_parts},
    {.name = "model-push", .pids = python_pids, .method = FT_METHOD_READ_SEND, .outbound = true,
     .slots = 1, .pause_min_ms = 30000, .pause_max_ms = 90000, .dest_kind = FT_SIM_DEST_LIST,
     .dests = registry_dests, .chunk = MIB(1), .flavors = models},
    {.name = "sshd", .pids = sshd_pids, .method = FT_METHOD_READ_SEND, .slots = 1,
     .pause_min_ms = 40000, .pause_max_ms = 120000, .dest_kind = FT_SIM_DEST_PUBLIC,
     .local_port = 22, .chunk = KIB(32), .flavors = dumps},
    {.name = "node-media", .pids = node_pids, .method = FT_METHOD_READ_SEND, .slots = 3,
     .pause_min_ms = 3000, .pause_max_ms = 30000, .dest_kind = FT_SIM_DEST_PUBLIC,
     .local_port = 3000, .chunk = KIB(64), .flavors = media_requests},
    {.name = "filebeat", .pids = filebeat_pids, .method = FT_METHOD_READ_SEND, .outbound = true,
     .keep_socket = true, .rotates = true, .slots = 1, .dest_kind = FT_SIM_DEST_LIST,
     .dests = logstash_dests, .chunk = KIB(16), .flavors = access_log},
    {},
};

/* quiet: three processes and little to do */

static const struct ft_sim_process quiet_processes[] = {
    {.pid = 2210, .ppid = 1, .uid = ROOT, .comm = "nginx", .exe = "/usr/sbin/nginx",
     .cmdline = "nginx: master process /usr/sbin/nginx", .title = true, .cwd = "/",
     .service = "nginx.service", .listen_port = 443, .age_s = 12 * DAY},
    {.pid = 2214, .ppid = 2210, .uid = WWW_DATA, .comm = "nginx", .exe = "/usr/sbin/nginx",
     .cmdline = "nginx: worker process", .title = true, .forked = true, .cwd = "/",
     .age_s = 12 * DAY},
    {.pid = 5120, .ppid = 1, .uid = DEPLOY, .comm = "rsync", .exe = "/usr/bin/rsync",
     .cmdline = "rsync -az --partial /srv/releases/ rsync://10.0.7.0/releases",
     .cwd = "/srv/releases", .service = "session-31.scope", .age_s = 2 * MINUTE},
    {0},
};

static const struct ft_sim_flavor quiet_assets[] = {
    {.weight = 5, .path = "/var/www/cdn/assets/app.8f3c1a.js", .size_min = KIB(1434),
     .size_max = KIB(1434), .rate_min = 800, .rate_max = 6000},
    {.weight = 4, .path = "/var/www/cdn/assets/vendor.21ab9e.js", .size_min = KIB(2355),
     .size_max = KIB(2355), .rate_min = 800, .rate_max = 6000},
    {.weight = 3, .path = "/var/www/cdn/img/hero@2x.webp", .size_min = KIB(1229),
     .size_max = KIB(1229), .rate_min = 800, .rate_max = 6000},
    {0},
};

static const struct ft_sim_flavor quiet_video[] = {
    {.weight = 1, .path = "/var/www/cdn/video/trailer-launch-2026.mp4", .size_min = MIB(96),
     .size_max = MIB(96), .rate_min = 4096, .rate_max = 10240},
    {0},
};

static const struct ft_sim_generator quiet_generators[] = {
    {.name = "nginx-assets", .parent = 2210, .method = FT_METHOD_SENDFILE, .slots = 2,
     .pause_min_ms = 20000, .pause_max_ms = 60000, .spread_ms = 15000,
     .dest_kind = FT_SIM_DEST_PUBLIC, .local_port = 443, .chunk = MIB(2), .flavors = quiet_assets},
    {.name = "nginx-video", .parent = 2210, .method = FT_METHOD_SENDFILE, .slots = 1,
     .pause_min_ms = 40000, .pause_max_ms = 120000, .spread_ms = 20000,
     .dest_kind = FT_SIM_DEST_PUBLIC, .local_port = 443, .chunk = MIB(2), .flavors = quiet_video},
    {.name = "rsync", .pids = rsync_pids, .method = FT_METHOD_READ_SEND, .outbound = true,
     .slots = 1, .pause_min_ms = 30000, .pause_max_ms = 90000, .spread_ms = 20000,
     .dest_kind = FT_SIM_DEST_LIST, .dests = rsync_dests, .chunk = KIB(128),
     .flavors = release_archives},
    {},
};

/* storm: many short transfers from a few dozen processes to thousands of destinations */

static const struct ft_sim_process storm_processes[] = {
    {.pid = 3000, .ppid = 1, .uid = ROOT, .comm = "nginx", .exe = "/usr/sbin/nginx",
     .cmdline = "nginx: master process /usr/sbin/nginx", .title = true, .cwd = "/",
     .service = "nginx.service", .listen_port = 443, .age_s = 3 * DAY},
    {.pid = 3001, .count = 40, .ppid = 3000, .uid = WWW_DATA, .comm = "nginx",
     .exe = "/usr/sbin/nginx", .cmdline = "nginx: worker process", .title = true, .forked = true,
     .cwd = "/", .age_s = 3 * DAY},
    {.pid = 3100, .ppid = 1, .uid = APP, .comm = "node", .exe = "/usr/bin/node",
     .cmdline = "node /srv/media/server.js", .cwd = "/srv/media", .service = "media.service",
     .listen_port = 3000, .age_s = 3 * DAY},
    {.pid = 3101, .count = 8, .ppid = 3100, .uid = APP, .comm = "node", .exe = "/usr/bin/node",
     .cmdline = "node /srv/media/server.js", .forked = true, .cwd = "/srv/media",
     .age_s = 3 * DAY},
    {0},
};

static const struct ft_sim_flavor storm_static[] = {
    {.weight = 1, .path = "/var/www/cdn/vod/part-%04llx.m4s", .numbering = FT_SIM_NUMBER_RANDOM,
     .first = 0, .last = 4095, .size_min = KIB(256), .size_max = MIB(8), .rate_min = 40,
     .rate_max = 300},
    {0},
};

static const struct ft_sim_flavor storm_cache[] = {
    {.weight = 1, .path = "/srv/media/cache/%05llx.bin", .numbering = FT_SIM_NUMBER_RANDOM,
     .first = 0, .last = 8191, .size_min = KIB(256), .size_max = MIB(8), .rate_min = 40,
     .rate_max = 250},
    {0},
};

static const struct ft_sim_generator storm_generators[] = {
    {.name = "storm-static", .parent = 3000, .method = FT_METHOD_SENDFILE, .pause_max_ms = 200,
     .spread_ms = 12000, .dest_kind = FT_SIM_DEST_PUBLIC_RANDOM, .local_port = 443,
     .chunk = MIB(1), .flavors = storm_static},
    {.name = "storm-cache", .parent = 3100, .method = FT_METHOD_READ_SEND, .pause_max_ms = 200,
     .spread_ms = 12000, .dest_kind = FT_SIM_DEST_PUBLIC_RANDOM, .local_port = 3000,
     .chunk = KIB(32), .flavors = storm_cache},
    {},
};

static const struct {
    const char *name;
    const struct ft_sim_process *processes;
    const struct ft_sim_generator *generators;
    struct ft_sim_recycle recycle;
    bool scaled; /* the transfers asked for are split among the generators */
} known[] = {
    {"edge", edge_processes, edge_generators, {18800, 240, 600, 18837}, false},
    {"quiet", quiet_processes, quiet_generators, {0}, false},
    {"storm", storm_processes, storm_generators, {0}, true},
};

/* clang-format on */

static struct ft_sim_generator *copy_generators(const struct ft_sim_generator *table)
{
    size_t n = 0;

    while (table[n].name)
        n++;
    struct ft_sim_generator *copy = calloc(n + 1, sizeof(*copy));
    if (copy)
        memcpy(copy, table, n * sizeof(*copy));
    return copy;
}

bool ft_sim_scenario_known(const char *name)
{
    for (size_t i = 0; i < FT_ARRAY_LEN(known); i++) {
        if (strcmp(name, known[i].name) == 0)
            return true;
    }
    return false;
}

struct ft_sim_scenario *ft_sim_scenario_create(const char *name, uint32_t transfers)
{
    for (size_t i = 0; i < FT_ARRAY_LEN(known); i++) {
        if (strcmp(name, known[i].name) != 0)
            continue;
        struct ft_sim_scenario *sc = calloc(1, sizeof(*sc));
        if (!sc)
            return nullptr;
        *sc = (struct ft_sim_scenario){
            .name = known[i].name,
            .processes = known[i].processes,
            .generators = copy_generators(known[i].generators),
            .recycle = known[i].recycle,
        };
        if (!sc->generators) {
            free(sc);
            return nullptr;
        }
        if (known[i].scaled) {
            /* Finished transfers stay active for another five seconds, a sixth of their life. */
            uint32_t running = transfers - transfers / 7;
            uint32_t cache = running / 6;
            sc->generators[0].slots = running - cache;
            sc->generators[1].slots = cache;
        }
        return sc;
    }
    return nullptr;
}

void ft_sim_scenario_free(struct ft_sim_scenario *sc)
{
    if (!sc)
        return;
    free(sc->generators);
    free(sc);
}
