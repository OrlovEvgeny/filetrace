#ifndef FILETRACE_SCHEMA_H
#define FILETRACE_SCHEMA_H

/*
 * Attribute keys of exported telemetry. OpenTelemetry's semantic conventions name whatever they
 * cover; the rest is under "filetrace.".
 */

#define FT_ATTR_SERVICE_NAME "service.name"
#define FT_ATTR_SERVICE_VERSION "service.version"
#define FT_ATTR_HOST_NAME "host.name"
#define FT_ATTR_OS_TYPE "os.type"

#define FT_ATTR_PROCESS_PID "process.pid"
#define FT_ATTR_PROCESS_PARENT_PID "process.parent_pid"
#define FT_ATTR_PROCESS_NAME "process.executable.name" /* the kernel's name for the task */
#define FT_ATTR_PROCESS_PATH "process.executable.path"
#define FT_ATTR_PROCESS_USER_ID "process.user.id"
#define FT_ATTR_PROCESS_EXIT_CODE "process.exit.code"
#define FT_ATTR_PROCESS_EXIT_SIGNAL "filetrace.process.exit_signal"

#define FT_ATTR_FILE_PATH "file.path"
#define FT_ATTR_FILE_INODE "file.inode"
#define FT_ATTR_FILE_SIZE "file.size"
#define FT_ATTR_FILE_DEVICE "filetrace.file.device"
#define FT_ATTR_FILE_DELETED "filetrace.file.deleted"

#define FT_ATTR_NETWORK_TRANSPORT "network.transport"
#define FT_ATTR_NETWORK_TYPE "network.type"
#define FT_ATTR_NETWORK_LOCAL_ADDRESS "network.local.address"
#define FT_ATTR_NETWORK_LOCAL_PORT "network.local.port"
#define FT_ATTR_NETWORK_PEER_ADDRESS "network.peer.address"
#define FT_ATTR_NETWORK_PEER_PORT "network.peer.port"
#define FT_ATTR_NETWORK_DIRECTION "network.io.direction"
#define FT_ATTR_NETWORK_BYTES "filetrace.network.bytes"

#define FT_ATTR_EVENT_TYPE "filetrace.event.type"
#define FT_ATTR_SOCKET_ID "filetrace.socket.id"
#define FT_ATTR_TRANSFER_METHOD "filetrace.transfer.method"
#define FT_ATTR_TRANSFER_CONFIDENCE "filetrace.transfer.confidence"
#define FT_ATTR_TRANSFER_BYTES "filetrace.transfer.bytes"
#define FT_ATTR_TRANSFER_BYTES_READ "filetrace.transfer.bytes_read"
#define FT_ATTR_LOSS_KIND "filetrace.loss.kind"
#define FT_ATTR_LOSS_EVENTS "filetrace.loss.events"

/* Set on the series that sums the label sets beyond the limit, as OpenTelemetry SDKs do. */
#define FT_ATTR_OVERFLOW "otel.metric.overflow"

#endif
