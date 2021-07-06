/*
Copyright NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * @file ziti_tunneler.h
 * @brief Defines the macros, functions, typedefs and constants required to implement a Ziti
 * tunneler application.
 */

#ifndef ZITI_TUNNELER_SDK_ZITI_TUNNEL_H
#define ZITI_TUNNELER_SDK_ZITI_TUNNEL_H

#include <stdbool.h>
#include "uv.h"
#include "sys/queue.h"
#include "ziti/netif_driver.h"
#include "lwip/ip_addr.h"

#ifdef __cplusplus
extern "C" {
#endif

/** keys used in app_data model map */
extern const char *DST_PROTO_KEY; // "dst_protocol"
extern const char *DST_IP_KEY;    // "dst_ip"
extern const char *DST_PORT_KEY;  // "dst_port"
extern const char *DST_HOST_KEY;  // "dst_hostname"
extern const char *SRC_PROTO_KEY; // "src_protocol"
extern const char *SRC_IP_KEY;    // "src_ip"
extern const char *SRC_PORT_KEY;  // "src_port"
extern const char *SOURCE_IP_KEY; // "source_ip"

typedef struct tunneler_ctx_s *tunneler_context;
typedef struct tunneler_io_ctx_s *tunneler_io_context;
const char * get_intercepted_address(const struct tunneler_io_ctx_s * tnlr_io);
const char * get_client_address(const struct tunneler_io_ctx_s * tnlr_io);

typedef void (*tunnel_logger_f)(int level, const char *file, unsigned int line, const char *func, const char *fmt, ...);

typedef enum {
    CLIENT_CFG_V1,    // ziti-tunnel-client.v1
    SERVER_CFG_V1,    // ziti-tunnel-server.v1
    INTERCEPT_CFG_V1, // intercept.v1
    HOST_CFG_V1       // host.v1
} cfg_type_e;

typedef enum {
    tun_tcp,
    tun_udp
} tunneler_proto_type;

extern tunneler_proto_type get_protocol_id(const char *protocol);
extern const char *get_protocol_str(tunneler_proto_type protocol);

typedef struct protocol_s {
    char *protocol;
    STAILQ_ENTRY(protocol_s) entries;
} protocol_t;
typedef STAILQ_HEAD(protocol_list_s, protocol_s) protocol_list_t;

typedef struct address_s {
    char       str[UV_MAXHOSTNAMESIZE]; // hostname || ip || ip/prefix
    bool       is_hostname;
    ip_addr_t  ip;
    ip_addr_t  _netmask;
    uint8_t    prefix_len;
    STAILQ_ENTRY(address_s) entries;
} address_t;
typedef STAILQ_HEAD(address_list_s, address_s) address_list_t;

typedef struct port_range_s {
    int low;
    int high;
    char str[16]; // [123456-123456]
    STAILQ_ENTRY(port_range_s) entries;
} port_range_t;
typedef STAILQ_HEAD(port_range_list_s, port_range_s) port_range_list_t;

/** data needed to intercept packets and dial the associated ziti service */
typedef struct intercept_ctx_s intercept_ctx_t;
extern intercept_ctx_t* intercept_ctx_new(tunneler_context tnlr_ctx, const char *app_id, void *app_intercept_ctx);

extern void intercept_ctx_add_protocol(intercept_ctx_t *ctx, const char *protocol);
/** parse address string as hostname|ip|cidr and add result to list of intercepted addresses */
extern address_t *intercept_ctx_add_address(intercept_ctx_t *i_ctx, const char *address);
extern port_range_t *intercept_ctx_add_port_range(intercept_ctx_t *i_ctx, uint16_t low, uint16_t high);

typedef struct host_ctx_s host_ctx_t;

typedef struct io_ctx_s {
    tunneler_io_context   tnlr_io;
    void *                ziti_io; // context specific to ziti SDK being used by the app.
    const void *          ziti_ctx;
    union {
        intercept_ctx_t *intercept_ctx;
        host_ctx_t      *host_ctx;
    } service;
} io_ctx_t;

struct io_ctx_list_entry_s {
    struct io_ctx_s *io;
    SLIST_ENTRY(io_ctx_list_entry_s) entries;
};
SLIST_HEAD(io_ctx_list_s, io_ctx_list_entry_s);

extern tunneler_io_context tunneler_io_new(tunneler_context tnlr_ctx, tunneler_proto_type proto, void *lwip_pcb);

typedef struct host_ctx_s host_ctx_t;
extern host_ctx_t *host_ctx_new(tunneler_context tnlr_ctx, const char *app_id, void *app_host_ctx);
extern void host_ctx_free(host_ctx_t *h_ctx);
extern void *get_app_host_ctx(host_ctx_t *h_ctx);
extern void host_ctx_set_protocol(host_ctx_t *h_ctx, const char *protocol);
extern void host_ctx_set_address(host_ctx_t *h_ctx, const char *address);
extern void host_ctx_set_port(host_ctx_t *h_ctx, uint16_t port);

extern void host_ctx_add_allowed_protocol(host_ctx_t *h_ctx, const char *protocol);
extern const address_t *host_ctx_add_allowed_address(host_ctx_t *h_ctx, const char *address);
extern void host_ctx_add_allowed_port_range(host_ctx_t *h_ctx, uint16_t low, uint16_t high);
extern const address_t *host_ctx_add_allowed_source_address(host_ctx_t *h_ctx, const char *address);
extern void host_ctx_set_display_address(host_ctx_t *h_ctx);
extern const char *host_ctx_get_display_address(host_ctx_t *h_ctx);

typedef struct tunneled_service_s {
    intercept_ctx_t *intercept;
    host_ctx_t      *host;
} tunneled_service_t;

/**
 * called when a client connection is intercepted.
 * implementations are expected to dial the service and return
 * context that will be passed to ziti_read/ziti_write */
typedef void * (*ziti_sdk_dial_cb)(const void *app_intercept_ctx, io_ctx_t *io);
typedef int (*ziti_sdk_close_cb)(void *ziti_io_ctx);
typedef ssize_t (*ziti_sdk_write_cb)(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len);
typedef bool (*ziti_sdk_accept_cb)(const void *app_host_ctx, io_ctx_t *io);

typedef struct tunneler_sdk_options_s {
    netif_driver   netif_driver;
    ziti_sdk_dial_cb    ziti_dial;   // called by tsdk when a ziti service needs to be dialed
    ziti_sdk_accept_cb  ziti_accept; // called by tsdk when a hosted service connection is completed
    ziti_sdk_close_cb   ziti_close;
    ziti_sdk_close_cb   ziti_close_write;
    ziti_sdk_write_cb   ziti_write;
} tunneler_sdk_options;

typedef struct dns_manager_s dns_manager;

typedef int (*dns_fallback_cb)(const char *name, void *ctx, struct in_addr* addr);

typedef void (*dns_answer_cb)(uint8_t *a_packet, size_t a_len, void *ctx);
typedef int (*dns_query)(dns_manager *dns, const uint8_t *q_packet, size_t q_len, dns_answer_cb cb, void *ctx);

struct dns_manager_s {
    bool internal_dns;
    uint32_t dns_ip;
    uint16_t dns_port;

    int (*apply)(dns_manager *dns, const char *host, const char *ip);
    dns_query query;

    uv_loop_t *loop;
    dns_fallback_cb fb_cb;
    void *fb_ctx;
    void *data;
};

// fallback will be called on the worker thread to avoid blocking event loop
extern dns_manager *get_tunneler_dns(uv_loop_t *l, uint32_t dns_ip, dns_fallback_cb cb, void *ctx);

extern bool parse_address_r(address_t *addr, const char *hn_or_ip_or_cidr, dns_manager *dns);
extern address_t *parse_address(const char *hn_or_ip_or_cidr, dns_manager *dns);
extern port_range_t *parse_port_range(uint16_t low, uint16_t high);

extern bool protocol_match(const char *protocol, const protocol_list_t *protocols);
extern bool address_match(const ip_addr_t *addr, const address_list_t *addresses);
extern bool port_match(int port, const port_range_list_t *port_ranges);

extern tunneler_context ziti_tunneler_init(tunneler_sdk_options *opts, uv_loop_t *loop);

/** called by tunneler application when it is done with a tunneler_context.
 * calls `stop_intercepting` for each intercepted service. */
extern void ziti_tunneler_shutdown(tunneler_context tnlr_ctx);

extern void ziti_tunneler_set_dns(tunneler_context tnlr_ctx, dns_manager *dns);

extern int ziti_tunneler_intercept(tunneler_context tnlr_ctx, intercept_ctx_t *i_ctx);

extern void ziti_tunneler_stop_intercepting(tunneler_context tnlr_ctx, void *zi_ctx);

/** called by tunneler application when ziti_dial completes for an intercepted connection */
extern void ziti_tunneler_ziti_dial_completed(io_ctx_t *io, bool ok);

typedef struct hosted_client_info_s {
    const char *identity;
    const char *dst_protocol;
    const char *dst_ip;
    const char *dst_hostname;
    const char *dst_port;
    const char *src_protocol;
    const char *src_ip;
    const char *src_port;
    const char *source_addr; // source ip[:port] as specified in intercept configuration
} hosted_client_info_t;

extern void hosted_client_info_init(hosted_client_info_t *client,
                                    const char *identity,
                                    const char *dst_protocol, const char *dst_ip, const char *dst_port,
                                    const char *dst_hostname,
                                    const char *src_protocol, const char *src_ip, const char *src_port,
                                    const char *source_addr);

extern hosted_client_info_t *hosted_client_info_new(const char *identity,
                                                    const char *dst_protocol, const char *dst_ip, const char *dst_port,
                                                    const char *dst_hostname,
                                                    const char *src_protocol, const char *src_ip, const char *src_port,
                                                    const char *source_addr);

/** initiate connection to a hosted server. called by application when a ziti client connects to a hosted service. */
extern tunneler_io_context ziti_tunneler_dial_host(host_ctx_t *h_ctx, hosted_client_info_t *client, io_ctx_t *io);

/** called by tunneler application when ziti_accept completes for the client of a hosted connection */
extern void ziti_tunneler_ziti_accept_completed(io_ctx_t *io, bool ok);

extern void ziti_tunneler_stop_hosting(tunneler_context tnlr_ctx, void *zh_ctx);

extern ssize_t ziti_tunneler_write(tunneler_io_context tnlr_io_ctx, const void *data, size_t len);

struct write_ctx_s;
extern void ziti_tunneler_ack(struct write_ctx_s *write_ctx);

extern int ziti_tunneler_close(tunneler_io_context tnlr_io_ctx);

extern int ziti_tunneler_close_write(tunneler_io_context tnlr_io_ctx);

extern const char* ziti_tunneler_version();

extern void ziti_tunneler_init_dns(uint32_t mask, int bits);

extern void ziti_tunnel_set_logger(tunnel_logger_f logger);
extern void ziti_tunnel_set_log_level(int lvl);

#ifdef __cplusplus
}
#endif

#endif /* ZITI_TUNNELER_SDK_ZITI_TUNNEL_H */