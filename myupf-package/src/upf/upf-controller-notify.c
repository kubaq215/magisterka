/*
    * UPF Controller Notify Implementation
 */

#include "upf-controller-notify.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define UPF_CONTROLLER_DEFAULT_HOST "127.0.0.1"
#define UPF_CONTROLLER_DEFAULT_PORT 8080
#define UPF_CONTROLLER_CONFIG_FILE_REL "configs/upf-controller.conf"
#define UPF_CONTROLLER_CONFIG_FILE_ETC "/etc/open5gs/upf-controller.conf"
#define UPF_CONTROLLER_JSON_BUF_SIZE 32768

static char upf_controller_host[INET6_ADDRSTRLEN] =
    UPF_CONTROLLER_DEFAULT_HOST;
static int upf_controller_port = UPF_CONTROLLER_DEFAULT_PORT;
static bool upf_controller_config_loaded = false;

static char *trim_ws(char *s)
{
    char *end;

    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')
        s++;

    if (*s == '\0')
        return s;

    end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' ||
                *end == '\n' || *end == '\r')) {
        *end = '\0';
        end--;
    }

    return s;
}

static void parse_upf_controller_config_file(const char *path)
{
    FILE *fp;
    char line[512];

    ogs_assert(path);

    fp = fopen(path, "r");
    if (!fp)
        return;

    while (fgets(line, sizeof(line), fp)) {
        char *eq;
        char *key;
        char *val;

        key = trim_ws(line);
        if (*key == '\0' || *key == '#')
            continue;

        eq = strchr(key, '=');
        if (!eq)
            continue;
        *eq = '\0';

        val = trim_ws(eq + 1);
        key = trim_ws(key);

        if (strcmp(key, "host") == 0) {
            if (*val) {
                (void)snprintf(upf_controller_host,
                        sizeof(upf_controller_host), "%s", val);
            }
        } else if (strcmp(key, "port") == 0) {
            char *endp = NULL;
            long p = strtol(val, &endp, 10);
            if (endp != val && *trim_ws(endp) == '\0' && p > 0 && p <= 65535)
                upf_controller_port = (int)p;
        }
    }

    fclose(fp);
}

static void load_upf_controller_config_once(void)
{
    const char *env_path;

    if (upf_controller_config_loaded)
        return;

    upf_controller_config_loaded = true;

    parse_upf_controller_config_file(UPF_CONTROLLER_CONFIG_FILE_REL);
    parse_upf_controller_config_file(UPF_CONTROLLER_CONFIG_FILE_ETC);

    env_path = getenv("UPF_CONTROLLER_CONFIG");
    if (env_path && *env_path)
        parse_upf_controller_config_file(env_path);

    ogs_info("UPF controller endpoint from config: %s:%d",
            upf_controller_host, upf_controller_port);
}

static const char *interface_name_api(ogs_pfcp_interface_t interface)
{
    switch (interface) {
        case OGS_PFCP_INTERFACE_ACCESS:
            return "ACCESS";
        case OGS_PFCP_INTERFACE_CORE:
            return "CORE";
        case OGS_PFCP_INTERFACE_SGI_N6_LAN:
            return "N6";
        case OGS_PFCP_INTERFACE_CP_FUNCTION:
            return "CP_FUNCTION";
        case OGS_PFCP_INTERFACE_LI_FUNCTION:
            return "LI_FUNCTION";
        case OGS_PFCP_INTERFACE_UNKNOWN:
        default:
            return "UNKNOWN";
    }
}

static const char *apply_action_name_api(ogs_pfcp_apply_action_t action)
{
    if (action & OGS_PFCP_APPLY_ACTION_FORW)
        return "FORW";
    if (action & OGS_PFCP_APPLY_ACTION_BUFF)
        return "BUFF";
    if (action & OGS_PFCP_APPLY_ACTION_DROP)
        return "DROP";
    return "UNKNOWN";
}

static const char *ue_ip_to_str(const ogs_pfcp_pdr_t *pdr)
{
    static char str[INET6_ADDRSTRLEN];

    if (!pdr || pdr->ue_ip_addr_len == 0)
        return "0.0.0.0";

    if (pdr->ue_ip_addr.ipv4) {
        struct in_addr addr;
        addr.s_addr = pdr->ue_ip_addr.addr;
        if (inet_ntop(AF_INET, &addr, str, sizeof(str)) == NULL)
            return "0.0.0.0";
        return str;
    }

    if (pdr->ue_ip_addr.ipv6) {
        if (inet_ntop(AF_INET6, pdr->ue_ip_addr.addr6, str, sizeof(str)) == NULL)
            return "::";
        return str;
    }

    return "0.0.0.0";
}

static const char *far_dest_ip_to_str(const ogs_pfcp_far_t *far)
{
    static char str[INET6_ADDRSTRLEN];

    if (!far)
        return "";

    if (far->outer_header_creation.ip6 || far->outer_header_creation.gtpu6 ||
        far->outer_header_creation.udp6) {
        if (inet_ntop(AF_INET6, far->outer_header_creation.addr6, str,
                    sizeof(str)) == NULL)
            return "";
        return str;
    }

    if (far->outer_header_creation.ip4 || far->outer_header_creation.gtpu4 ||
        far->outer_header_creation.udp4 || far->outer_header_creation.addr) {
        struct in_addr addr;
        addr.s_addr = far->outer_header_creation.addr;
        if (inet_ntop(AF_INET, &addr, str, sizeof(str)) == NULL)
            return "";
        return str;
    }

    return "";
}

static bool json_append(char *buf, size_t buflen, size_t *offset,
        const char *fmt, ...)
{
    va_list ap;
    int written;

    ogs_assert(buf);
    ogs_assert(offset);
    ogs_assert(fmt);

    if (*offset >= buflen)
        return false;

    va_start(ap, fmt);
    written = vsnprintf(buf + *offset, buflen - *offset, fmt, ap);
    va_end(ap);

    if (written < 0)
        return false;
    if ((size_t)written >= (buflen - *offset))
        return false;

    *offset += written;
    return true;
}

static int send_http_json_to_upf_controller(
        const char *method, const char *path, const char *json)
{
    int fd;
    struct sockaddr_in addr;
    struct timeval timeout;
    char request[UPF_CONTROLLER_JSON_BUF_SIZE + 1024];
    ssize_t sent;
    size_t req_len;

    ogs_assert(method);
    ogs_assert(path);
    ogs_assert(json);

    load_upf_controller_config_once();

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        ogs_warn("UPF controller socket() failed: %s", strerror(errno));
        return OGS_ERROR;
    }

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(upf_controller_port);
    if (inet_pton(AF_INET, upf_controller_host, &addr.sin_addr) != 1) {
        ogs_warn("UPF controller inet_pton() failed");
        close(fd);
        return OGS_ERROR;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ogs_warn("UPF controller connect() failed: %s", strerror(errno));
        close(fd);
        return OGS_ERROR;
    }

    req_len = (size_t)snprintf(request, sizeof(request),
            "%s %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            method, path, upf_controller_host, upf_controller_port,
            strlen(json), json);

    if (req_len >= sizeof(request)) {
        ogs_warn("UPF controller request too large");
        close(fd);
        return OGS_ERROR;
    }

    sent = send(fd, request, req_len, 0);
    if (sent < 0 || (size_t)sent != req_len) {
        ogs_warn("UPF controller send() failed: %s", strerror(errno));
        close(fd);
        return OGS_ERROR;
    }

    while (1) {
        char response_buf[512];
        ssize_t r = recv(fd, response_buf, sizeof(response_buf), 0);
        if (r <= 0)
            break;
    }

    close(fd);
    return OGS_OK;
}

int upf_controller_notify_session_establish(upf_sess_t *sess)
{
    char json[UPF_CONTROLLER_JSON_BUF_SIZE];
    size_t off = 0;
    bool first;
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;

    ogs_assert(sess);

    if (!json_append(json, sizeof(json), &off,
                "{\"session_id\":\"sess-%" PRIu64 "\",",
                sess->smf_n4_f_seid.seid))
        return OGS_ERROR;

    if (!json_append(json, sizeof(json), &off, "\"pdrs\":["))
        return OGS_ERROR;

    first = true;
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        if (!first) {
            if (!json_append(json, sizeof(json), &off, ","))
                return OGS_ERROR;
        }
        first = false;

        if (!json_append(json, sizeof(json), &off,
                    "{\"pdr_id\":%d,\"precedence\":%u,"
                    "\"source_interface\":\"%s\","
                    "\"ue_ip\":\"%s\","
                    "\"far_id\":%u,"
                    "\"outer_header_removal\":%s}",
                    pdr->id,
                    pdr->precedence,
                    interface_name_api(pdr->src_if),
                    ue_ip_to_str(pdr),
                    pdr->far ? pdr->far->id : 0,
                    pdr->outer_header_removal_len ? "true" : "false"))
            return OGS_ERROR;
    }

    if (!json_append(json, sizeof(json), &off, "],\"fars\":["))
        return OGS_ERROR;

    first = true;
    ogs_list_for_each(&sess->pfcp.far_list, far) {
        if (!first) {
            if (!json_append(json, sizeof(json), &off, ","))
                return OGS_ERROR;
        }
        first = false;

        if (!json_append(json, sizeof(json), &off,
                    "{\"far_id\":%u,"
                    "\"apply_action\":\"%s\","
                    "\"destination_interface\":\"%s\"",
                    far->id,
                    apply_action_name_api(far->apply_action),
                    interface_name_api(far->dst_if)))
            return OGS_ERROR;

        if (far->outer_header_creation.teid) {
            if (!json_append(json, sizeof(json), &off,
                ",\"outer_header_creation\":{"
                "\"teid\":%u,"
                "\"dest_ip\":\"%s\"}",
                far->outer_header_creation.teid,
                far_dest_ip_to_str(far)))
            return OGS_ERROR;
        }

        if (!json_append(json, sizeof(json), &off, "}"))
            return OGS_ERROR;
    }

    if (!json_append(json, sizeof(json), &off, "]}"))
        return OGS_ERROR;

    return send_http_json_to_upf_controller("POST", "/session/establish", json);
}

int upf_controller_notify_session_modify(upf_sess_t *sess,
        ogs_pfcp_pdr_t **modified_pdr, int num_modified_pdr,
        ogs_pfcp_far_t **modified_far, int num_modified_far)
{
    char json[UPF_CONTROLLER_JSON_BUF_SIZE];
    size_t off = 0;
    int i;
    bool first;

    ogs_assert(sess);

    if (!json_append(json, sizeof(json), &off,
                "{\"session_id\":\"sess-%" PRIu64 "\",",
                sess->smf_n4_f_seid.seid))
        return OGS_ERROR;

    if (!json_append(json, sizeof(json), &off, "\"update_pdrs\":["))
        return OGS_ERROR;

    first = true;
    for (i = 0; i < num_modified_pdr; i++) {
        ogs_pfcp_pdr_t *pdr = modified_pdr[i];
        if (!pdr)
            continue;

        if (!first) {
            if (!json_append(json, sizeof(json), &off, ","))
                return OGS_ERROR;
        }
        first = false;

        if (!json_append(json, sizeof(json), &off,
                    "{\"pdr_id\":%d,\"precedence\":%u,"
                    "\"source_interface\":\"%s\","
                    "\"ue_ip\":\"%s\","
                    "\"far_id\":%u,"
                    "\"outer_header_removal\":%s}",
                    pdr->id,
                    pdr->precedence,
                    interface_name_api(pdr->src_if),
                    ue_ip_to_str(pdr),
                    pdr->far ? pdr->far->id : 0,
                    pdr->outer_header_removal_len ? "true" : "false"))
            return OGS_ERROR;
    }

    if (!json_append(json, sizeof(json), &off, "],\"update_fars\":["))
        return OGS_ERROR;

    first = true;
    for (i = 0; i < num_modified_far; i++) {
        ogs_pfcp_far_t *far = modified_far[i];
        if (!far)
            continue;

        if (!first) {
            if (!json_append(json, sizeof(json), &off, ","))
                return OGS_ERROR;
        }
        first = false;

        if (!json_append(json, sizeof(json), &off,
                    "{\"far_id\":%u,"
                    "\"apply_action\":\"%s\","
                    "\"destination_interface\":\"%s\"",
                    far->id,
                    apply_action_name_api(far->apply_action),
                    interface_name_api(far->dst_if)))
            return OGS_ERROR;

        if (far->outer_header_creation.teid) {
            if (!json_append(json, sizeof(json), &off,
                        ",\"outer_header_creation\":{"
                        "\"teid\":%u,"
                        "\"dest_ip\":\"%s\"}",
                        far->outer_header_creation.teid,
                        far_dest_ip_to_str(far)))
                return OGS_ERROR;
        }

        if (!json_append(json, sizeof(json), &off, "}"))
            return OGS_ERROR;
    }

    if (!json_append(json, sizeof(json), &off, "]}"))
        return OGS_ERROR;

    return send_http_json_to_upf_controller("PUT", "/session/modify", json);
}

int upf_controller_notify_session_delete(upf_sess_t *sess)
{
    char json[256];
    int n;

    ogs_assert(sess);

    n = snprintf(json, sizeof(json),
            "{\"session_id\":\"sess-%" PRIu64 "\"}",
            sess->smf_n4_f_seid.seid);
    if (n < 0 || (size_t)n >= sizeof(json))
        return OGS_ERROR;

    return send_http_json_to_upf_controller("DELETE", "/session/delete", json);
}
