/*
 * UPF Controller Notify Implementation
 *
 * Uses cJSON for safe JSON serialization.
 */

#include "upf-controller-notify.h"
#include "cJSON.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
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

static void ue_ip_to_str(const ogs_pfcp_pdr_t *pdr, char *buf, size_t buflen)
{
    ogs_assert(buf);

    if (!pdr || pdr->ue_ip_addr_len == 0) {
        snprintf(buf, buflen, "0.0.0.0");
        return;
    }

    if (pdr->ue_ip_addr.ipv4) {
        struct in_addr addr;
        addr.s_addr = pdr->ue_ip_addr.addr;
        if (inet_ntop(AF_INET, &addr, buf, buflen) == NULL)
            snprintf(buf, buflen, "0.0.0.0");
        return;
    }

    if (pdr->ue_ip_addr.ipv6) {
        if (inet_ntop(AF_INET6, pdr->ue_ip_addr.addr6, buf, buflen) == NULL)
            snprintf(buf, buflen, "::");
        return;
    }

    snprintf(buf, buflen, "0.0.0.0");
}

static void far_dest_ip_to_str(const ogs_pfcp_far_t *far,
        char *buf, size_t buflen)
{
    ogs_assert(buf);

    if (!far) {
        buf[0] = '\0';
        return;
    }

    if (far->outer_header_creation.ip6 || far->outer_header_creation.gtpu6 ||
        far->outer_header_creation.udp6) {
        if (inet_ntop(AF_INET6, far->outer_header_creation.addr6, buf,
                    buflen) == NULL)
            buf[0] = '\0';
        return;
    }

    if (far->outer_header_creation.ip4 || far->outer_header_creation.gtpu4 ||
        far->outer_header_creation.udp4 || far->outer_header_creation.addr) {
        struct in_addr addr;
        addr.s_addr = far->outer_header_creation.addr;
        if (inet_ntop(AF_INET, &addr, buf, buflen) == NULL)
            buf[0] = '\0';
        return;
    }

    buf[0] = '\0';
}

static cJSON *build_pdr_json(const ogs_pfcp_pdr_t *pdr)
{
    cJSON *obj;
    char ip_buf[INET6_ADDRSTRLEN];

    obj = cJSON_CreateObject();
    if (!obj) return NULL;

    cJSON_AddNumberToObject(obj, "pdr_id", pdr->id);
    cJSON_AddNumberToObject(obj, "precedence", pdr->precedence);
    cJSON_AddStringToObject(obj, "source_interface",
            interface_name_api(pdr->src_if));

    ue_ip_to_str(pdr, ip_buf, sizeof(ip_buf));
    cJSON_AddStringToObject(obj, "ue_ip", ip_buf);

    cJSON_AddNumberToObject(obj, "far_id", pdr->far ? pdr->far->id : 0);
    cJSON_AddBoolToObject(obj, "outer_header_removal",
            pdr->outer_header_removal_len ? 1 : 0);

    return obj;
}

static cJSON *build_far_json(const ogs_pfcp_far_t *far)
{
    cJSON *obj;
    char ip_buf[INET6_ADDRSTRLEN];

    obj = cJSON_CreateObject();
    if (!obj) return NULL;

    cJSON_AddNumberToObject(obj, "far_id", far->id);
    cJSON_AddStringToObject(obj, "apply_action",
            apply_action_name_api(far->apply_action));
    cJSON_AddStringToObject(obj, "destination_interface",
            interface_name_api(far->dst_if));

    if (far->outer_header_creation.teid) {
        cJSON *ohc = cJSON_CreateObject();
        if (ohc) {
            cJSON_AddNumberToObject(ohc, "teid",
                    far->outer_header_creation.teid);
            far_dest_ip_to_str(far, ip_buf, sizeof(ip_buf));
            cJSON_AddStringToObject(ohc, "dest_ip", ip_buf);
            cJSON_AddItemToObject(obj, "outer_header_creation", ohc);
        }
    }

    return obj;
}

#define UPF_CONTROLLER_MAX_RETRIES 3
static const int retry_delays_ms[] = { 0, 100, 500 };

static int parse_http_status(const char *buf, size_t len)
{
    /* Minimal parse: "HTTP/1.x NNN ..." */
    if (len < 12)
        return -1;
    if (strncmp(buf, "HTTP/1.", 7) != 0)
        return -1;

    const char *sp = memchr(buf + 8, ' ', len - 8);
    if (!sp)
        sp = buf + 8;
    else
        sp = buf + 9; /* skip "HTTP/1.x " */

    return atoi(sp);
}

static int send_http_json_once(
        const char *method, const char *path, const char *json_body)
{
    int fd;
    struct sockaddr_in addr;
    struct timeval timeout;
    char *request = NULL;
    ssize_t sent;
    size_t req_len;
    size_t json_len;
    size_t alloc_size;
    char response_buf[1024];
    size_t resp_len = 0;
    int http_status;

    json_len = strlen(json_body);
    alloc_size = json_len + 1024;
    request = (char *)malloc(alloc_size);
    if (!request) {
        ogs_warn("UPF controller malloc() failed");
        return OGS_ERROR;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        ogs_warn("UPF controller socket() failed: %s", strerror(errno));
        free(request);
        return OGS_ERROR;
    }

    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(upf_controller_port);
    if (inet_pton(AF_INET, upf_controller_host, &addr.sin_addr) != 1) {
        ogs_warn("UPF controller inet_pton() failed");
        close(fd);
        free(request);
        return OGS_ERROR;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ogs_warn("UPF controller connect() failed: %s", strerror(errno));
        close(fd);
        free(request);
        return OGS_ERROR;
    }

    req_len = (size_t)snprintf(request, alloc_size,
            "%s %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            method, path, upf_controller_host, upf_controller_port,
            json_len, json_body);

    if (req_len >= alloc_size) {
        ogs_warn("UPF controller request too large");
        close(fd);
        free(request);
        return OGS_ERROR;
    }

    sent = send(fd, request, req_len, 0);
    free(request);
    if (sent < 0 || (size_t)sent != req_len) {
        ogs_warn("UPF controller send() failed: %s", strerror(errno));
        close(fd);
        return OGS_ERROR;
    }

    /* Read response and check HTTP status */
    while (resp_len < sizeof(response_buf) - 1) {
        ssize_t r = recv(fd, response_buf + resp_len,
                sizeof(response_buf) - 1 - resp_len, 0);
        if (r <= 0)
            break;
        resp_len += (size_t)r;
    }
    response_buf[resp_len] = '\0';
    close(fd);

    http_status = parse_http_status(response_buf, resp_len);
    if (http_status < 200 || http_status >= 300) {
        ogs_warn("UPF controller returned HTTP %d for %s %s",
                http_status, method, path);
        return OGS_ERROR;
    }

    return OGS_OK;
}

static int send_http_json_to_upf_controller(
        const char *method, const char *path, const char *json_body)
{
    int rv;
    int attempt;

    ogs_assert(method);
    ogs_assert(path);
    ogs_assert(json_body);

    load_upf_controller_config_once();

    for (attempt = 0; attempt < UPF_CONTROLLER_MAX_RETRIES; attempt++) {
        if (attempt > 0) {
            int delay_ms = retry_delays_ms[attempt];
            ogs_warn("UPF controller retry %d/%d after %dms for %s %s",
                    attempt + 1, UPF_CONTROLLER_MAX_RETRIES,
                    delay_ms, method, path);
            if (delay_ms > 0)
                usleep((useconds_t)delay_ms * 1000);
        }

        rv = send_http_json_once(method, path, json_body);
        if (rv == OGS_OK)
            return OGS_OK;
    }

    ogs_error("UPF controller notification failed after %d attempts: %s %s",
            UPF_CONTROLLER_MAX_RETRIES, method, path);
    return OGS_ERROR;
}

int upf_controller_notify_session_establish(upf_sess_t *sess)
{
    cJSON *root = NULL;
    cJSON *pdrs_arr = NULL;
    cJSON *fars_arr = NULL;
    char *json_str = NULL;
    char session_id_buf[64];
    int rv = OGS_ERROR;
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;

    ogs_assert(sess);

    root = cJSON_CreateObject();
    if (!root) return OGS_ERROR;

    snprintf(session_id_buf, sizeof(session_id_buf),
            "sess-%" PRIu64, sess->smf_n4_f_seid.seid);
    cJSON_AddStringToObject(root, "session_id", session_id_buf);

    pdrs_arr = cJSON_AddArrayToObject(root, "pdrs");
    if (!pdrs_arr) goto cleanup;

    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        cJSON *pdr_obj = build_pdr_json(pdr);
        if (!pdr_obj) goto cleanup;
        cJSON_AddItemToArray(pdrs_arr, pdr_obj);
    }

    fars_arr = cJSON_AddArrayToObject(root, "fars");
    if (!fars_arr) goto cleanup;

    ogs_list_for_each(&sess->pfcp.far_list, far) {
        cJSON *far_obj = build_far_json(far);
        if (!far_obj) goto cleanup;
        cJSON_AddItemToArray(fars_arr, far_obj);
    }

    json_str = cJSON_PrintUnformatted(root);
    if (!json_str) goto cleanup;

    rv = send_http_json_to_upf_controller("POST", "/session/establish",
            json_str);

cleanup:
    if (json_str) cJSON_free(json_str);
    if (root) cJSON_Delete(root);
    return rv;
}

int upf_controller_notify_session_modify(upf_sess_t *sess,
        ogs_pfcp_pdr_t **modified_pdr, int num_modified_pdr,
        ogs_pfcp_far_t **modified_far, int num_modified_far)
{
    cJSON *root = NULL;
    cJSON *pdrs_arr = NULL;
    cJSON *fars_arr = NULL;
    char *json_str = NULL;
    char session_id_buf[64];
    int rv = OGS_ERROR;
    int i;

    ogs_assert(sess);

    root = cJSON_CreateObject();
    if (!root) return OGS_ERROR;

    snprintf(session_id_buf, sizeof(session_id_buf),
            "sess-%" PRIu64, sess->smf_n4_f_seid.seid);
    cJSON_AddStringToObject(root, "session_id", session_id_buf);

    pdrs_arr = cJSON_AddArrayToObject(root, "update_pdrs");
    if (!pdrs_arr) goto cleanup;

    for (i = 0; i < num_modified_pdr; i++) {
        ogs_pfcp_pdr_t *pdr = modified_pdr[i];
        cJSON *pdr_obj;
        if (!pdr) continue;
        pdr_obj = build_pdr_json(pdr);
        if (!pdr_obj) goto cleanup;
        cJSON_AddItemToArray(pdrs_arr, pdr_obj);
    }

    fars_arr = cJSON_AddArrayToObject(root, "update_fars");
    if (!fars_arr) goto cleanup;

    for (i = 0; i < num_modified_far; i++) {
        ogs_pfcp_far_t *far = modified_far[i];
        cJSON *far_obj;
        if (!far) continue;
        far_obj = build_far_json(far);
        if (!far_obj) goto cleanup;
        cJSON_AddItemToArray(fars_arr, far_obj);
    }

    json_str = cJSON_PrintUnformatted(root);
    if (!json_str) goto cleanup;

    rv = send_http_json_to_upf_controller("PUT", "/session/modify", json_str);

cleanup:
    if (json_str) cJSON_free(json_str);
    if (root) cJSON_Delete(root);
    return rv;
}

int upf_controller_notify_session_delete(upf_sess_t *sess)
{
    cJSON *root = NULL;
    char *json_str = NULL;
    char session_id_buf[64];
    int rv = OGS_ERROR;

    ogs_assert(sess);

    root = cJSON_CreateObject();
    if (!root) return OGS_ERROR;

    snprintf(session_id_buf, sizeof(session_id_buf),
            "sess-%" PRIu64, sess->smf_n4_f_seid.seid);
    cJSON_AddStringToObject(root, "session_id", session_id_buf);

    json_str = cJSON_PrintUnformatted(root);
    if (!json_str) goto cleanup;

    rv = send_http_json_to_upf_controller("DELETE", "/session/delete",
            json_str);

cleanup:
    if (json_str) cJSON_free(json_str);
    if (root) cJSON_Delete(root);
    return rv;
}
