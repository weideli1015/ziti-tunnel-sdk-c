/*
Copyright 2019-2020 NetFoundry, Inc.

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

// something wrong with lwip_xxxx byteorder functions
#ifdef _WIN32
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1
#endif

#if defined(__mips) || defined(__mips__)
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1
#endif

#include "uv.h"

#include "lwip/init.h"
#include "lwip/raw.h"
#include "lwip/timeouts.h"
#include "netif_shim.h"
#include "ziti/ziti_tunnel.h"
#include "ziti_tunnel_priv.h"
#include "tunnel_tcp.h"
#include "tunnel_udp.h"

#include <string.h>

const char *DST_PROTO_KEY = "dst_protocol";
const char *DST_IP_KEY = "dst_ip";
const char *DST_PORT_KEY = "dst_port";
const char *DST_HOST_KEY = "dst_hostname";
const char *SRC_PROTO_KEY = "src_protocol";
const char *SRC_IP_KEY = "src_ip";
const char *SRC_PORT_KEY = "src_port";
const char *SOURCE_IP_KEY = "source_ip";

struct resolve_req {
    ip_addr_t addr;
    u16_t port;
    tunneler_context tnlr_ctx;
};

static void run_packet_loop(uv_loop_t *loop, tunneler_context tnlr_ctx);

STAILQ_HEAD(tlnr_ctx_list_s, tunneler_ctx_s) tnlr_ctx_list_head = STAILQ_HEAD_INITIALIZER(tnlr_ctx_list_head);

tunneler_context ziti_tunneler_init(tunneler_sdk_options *opts, uv_loop_t *loop) {
    TNL_LOG(INFO, "Ziti Tunneler SDK (%s)", ziti_tunneler_version());

    if (opts == NULL) {
        TNL_LOG(ERR, "invalid tunneler options");
        return NULL;
    }

    struct tunneler_ctx_s *ctx = calloc(1, sizeof(struct tunneler_ctx_s));
    if (ctx == NULL) {
        TNL_LOG(ERR, "failed to allocate tunneler context");
        return NULL;
    }
    ctx->loop = loop;
    memcpy(&ctx->opts, opts, sizeof(ctx->opts));
    STAILQ_INIT(&ctx->intercepts);
    run_packet_loop(loop, ctx);

    return ctx;
}

static void tunneler_kill_active(const void *ztx);

void ziti_tunneler_shutdown(tunneler_context tnlr_ctx) {
    TNL_LOG(DEBUG, "tnlr_ctx %p", tnlr_ctx);

    while (!STAILQ_EMPTY(&tnlr_ctx->intercepts)) {
        intercept_ctx_t *i = STAILQ_FIRST(&tnlr_ctx->intercepts);
        tunneler_kill_active(i->app_intercept_ctx);
        STAILQ_REMOVE_HEAD(&tnlr_ctx->intercepts, entries);
    }
}

/** called by tunneler application when data has been successfully written to ziti */
void ziti_tunneler_ack(struct write_ctx_s *write_ctx) {
    write_ctx->ack(write_ctx);
}

const char *get_intercepted_address(const struct tunneler_io_ctx_s * tnlr_io) {
    if (tnlr_io == NULL) {
        return NULL;
    }
    return tnlr_io->intercepted;
}

const char *get_client_address(const struct tunneler_io_ctx_s * tnlr_io) {
    if (tnlr_io == NULL) {
        return NULL;
    }
    return tnlr_io->client;
}

tunneler_io_context tunneler_io_new(tunneler_context tnlr_ctx, tunneler_proto_type proto, void *lwip_pcb) {
    tunneler_io_context tnlr_io = calloc(1, sizeof(struct tunneler_io_ctx_s));
    tnlr_io->tnlr_ctx = tnlr_ctx;
    tnlr_io->proto = proto;
    switch (proto) {
        case tun_tcp:
            tnlr_io->tcp = lwip_pcb;
            break;
        case tun_udp:
            tnlr_io->udp.pcb = lwip_pcb;
            tnlr_io->udp.queued = NULL;
        default:
            TNL_LOG(ERR, "unsupported protocol %d", proto);
            free(tnlr_io);
            return NULL;
    }

    return tnlr_io;
}

void free_tunneler_io_context(tunneler_io_context *tnlr_io_ctx_p) {
    if (tnlr_io_ctx_p == NULL) {
        return;
    }

    if (*tnlr_io_ctx_p != NULL) {
        free(*tnlr_io_ctx_p);
        *tnlr_io_ctx_p = NULL;
    }
}

/**
 * called by tunneler application when a service dial has completed
 * - let the client know that we have a connection (e.g. send SYN/ACK)
 */
void ziti_tunneler_ziti_dial_completed(io_ctx_t *io, bool ok) {
    if (io == NULL) {
        TNL_LOG(ERR, "null io");
        return;
    }
    if (io->ziti_io == NULL || io->tnlr_io == NULL) {
        TNL_LOG(ERR, "null ziti_io or tnlr_io");
    }
    const char *status = ok ? "succeeded" : "failed";
    TNL_LOG(INFO, "ziti dial %s: service=%s, client=%s", status, io->tnlr_io->service_name, io->tnlr_io->client);

    switch (io->tnlr_io->proto) {
        case tun_tcp:
            tunneler_tcp_dial_completed(io, ok);
            break;
        case tun_udp:
            tunneler_udp_dial_completed(io, ok);
            break;
        default:
            TNL_LOG(ERR, "unknown proto %d", io->tnlr_io->proto);
            break;
    }
}

host_ctx_t *host_ctx_new(tunneler_context tnlr_ctx, const char *app_id, void *app_host_ctx) {
    host_ctx_t *hctx = calloc(1, sizeof(intercept_ctx_t));
    hctx->tnlr_ctx = tnlr_ctx;
    hctx->service_name = app_id;
    hctx->app_host_ctx = app_host_ctx;
    STAILQ_INIT(&hctx->proto_u.allowed_protocols);
    STAILQ_INIT(&hctx->addr_u.allowed_addresses);
    STAILQ_INIT(&hctx->port_u.allowed_port_ranges);

    return hctx;
}

#define safe_free(p) if ((p) != NULL) free((p))

#define STAILQ_CLEAR(slist_head, free_fn) do { \
    while (!STAILQ_EMPTY(slist_head)) { \
        void *elem = STAILQ_FIRST(slist_head); \
        STAILQ_REMOVE_HEAD((slist_head), entries); \
        free_fn(elem); \
    } \
} while(0);

void host_ctx_free(host_ctx_t *h_ctx) {
    if (h_ctx == NULL) {
        return;
    }

    if (h_ctx->forward_protocol) {
        STAILQ_CLEAR(&h_ctx->proto_u.allowed_protocols, safe_free);
    }

    if (h_ctx->forward_address) {
        STAILQ_CLEAR(&h_ctx->addr_u.allowed_addresses, safe_free);
    }

    if (h_ctx->forward_port) {
        STAILQ_CLEAR(&h_ctx->port_u.allowed_port_ranges, safe_free);
    }

    STAILQ_CLEAR(&h_ctx->allowed_source_addresses, safe_free);
}

void *get_app_host_ctx(host_ctx_t *h_ctx) {
    return h_ctx->app_host_ctx;
}

void host_ctx_set_protocol(host_ctx_t *h_ctx, const char *protocol) {
    h_ctx->forward_protocol = false;
    h_ctx->proto_u.protocol = strdup(protocol);
}

void host_ctx_set_address(host_ctx_t *h_ctx, const char *address) {
    h_ctx->forward_address = false;
    h_ctx->addr_u.address = strdup(address);
}

void host_ctx_set_port(host_ctx_t *h_ctx, uint16_t port) {
    h_ctx->forward_port = false;
    h_ctx->port_u.port = port;
}

void host_ctx_add_allowed_protocol(host_ctx_t *h_ctx, const char *protocol) {
    h_ctx->forward_protocol = true;
    protocol_t *p = calloc(1, sizeof(protocol_t));
    p->protocol = strdup(protocol);
    STAILQ_INSERT_TAIL(&h_ctx->proto_u.allowed_protocols, p, entries);
}

const address_t *host_ctx_add_allowed_address(host_ctx_t *h_ctx, const char *address) {
    address_t *a = parse_address(address, NULL);
    if (a != NULL) {
        STAILQ_INSERT_TAIL(&h_ctx->addr_u.allowed_addresses, a, entries);
    }
    return a;
}

void host_ctx_add_allowed_port_range(host_ctx_t *h_ctx, uint16_t low, uint16_t high) {
    h_ctx->forward_port = true;
    port_range_t *pr = parse_port_range(low, high);
    STAILQ_INSERT_TAIL(&h_ctx->port_u.allowed_port_ranges, pr, entries);
}

const address_t *host_ctx_add_allowed_source_address(host_ctx_t *h_ctx, const char *address){
    address_t *a = parse_address(address, NULL);
    if (a == NULL) {
        return NULL;
    }
    STAILQ_INSERT_TAIL(&h_ctx->allowed_source_addresses, a, entries);
    return a;
}

void host_ctx_set_display_address(host_ctx_t *h_ctx) {
    /* construct display address based on configuration */
    char *display_proto = "?", *display_addr = "?", display_port[12] = { '?', '\0' };
    if (!h_ctx->forward_protocol) {
        display_proto = h_ctx->proto_u.protocol;
    }
    if (!h_ctx->forward_address) {
        display_addr = h_ctx->addr_u.address;
    }
    if (!h_ctx->forward_port) {
        snprintf(display_port, sizeof(display_port), "%d", h_ctx->port_u.port);
    }

    snprintf(h_ctx->display_address, sizeof(h_ctx->display_address), "%s:%s:%s", display_proto, display_addr, display_port);
}

const char *host_ctx_get_display_address(host_ctx_t *h_ctx) {
    const char *s = h_ctx ? h_ctx->display_address : "<null host_ctx>";
    return s;
}

tunneler_proto_type get_protocol_id(const char *protocol) {
    if (strcasecmp(protocol, "tcp") == 0) {
        return tun_tcp;
    } else if (strcasecmp(protocol, "udp") == 0) {
        return tun_udp;
    }
    return -1;
}

const char *get_protocol_str(tunneler_proto_type protocol_id) {
    switch (protocol_id) {
        case tun_tcp:
            return "tcp";
        case tun_udp:
            return "udp";
        default:
            return "NUL";
    }
}

/** determine server address for given service and client */
static bool get_dial_address(const host_ctx_t *h_ctx, const hosted_client_info_t *client,
                             tunneler_proto_type *proto, address_t *addr, u16_t *port) {
    if (h_ctx->forward_protocol) {
        if (client->dst_protocol == NULL || client->dst_protocol[0] == '\0') {
            TNL_LOG(ERR,
                    "hosted_service[%s] client[%s] config specifies 'forwardProtocol', but client did not send dst_protocol",
                    h_ctx->service_name, client->identity);
            return false;
        }
        if (!protocol_match(client->dst_protocol, &h_ctx->proto_u.allowed_protocols)) {
            TNL_LOG(ERR, "hosted_service[%s] client[%s] requested protocol '%s' is not allowed",
                    h_ctx->service_name, client->identity, client->dst_protocol);
            return false;
        }
        *proto = get_protocol_id(client->dst_protocol);
    } else {
        *proto = get_protocol_id(h_ctx->proto_u.protocol);
    }

    const char *dial_addr_str;
    if (h_ctx->forward_address) {
        if (client->dst_hostname != NULL && client->dst_hostname[0] != '\0') {
            dial_addr_str = client->dst_hostname;
        } else if (client->dst_ip != NULL && client->dst_ip[0] != '\0') {
            dial_addr_str = client->dst_ip;
        } else {
            TNL_LOG(ERR,
                    "hosted_service[%s] client[%s] config specifies 'forwardAddress' but client did not send dst_hostname or dst_ip",
                    h_ctx->service_name, client->identity);
        }
    } else {
        dial_addr_str = h_ctx->addr_u.address;
    }

    if (!parse_address_r(addr, dial_addr_str, h_ctx->tnlr_ctx->dns)) {
        TNL_LOG(ERR, "hosted_service[%s] client[%s] failed to parse server address '%s'", h_ctx->service_name,
                client->identity, dial_addr_str);
        return false;
    }

    // ensure dialed address is allowed
    if (h_ctx->forward_address) {
        // todo match hostnames; pass address_t to address_match?
        if (!address_match(&addr->ip, &h_ctx->addr_u.allowed_addresses)) {
            TNL_LOG(ERR, "hosted_service[%s] client[%s] requested address '%s' is not allowed",
                    h_ctx->service_name, client->identity, dial_addr_str);
            return false;
        }
    }

    if (h_ctx->forward_port) {
        if (client->dst_port != NULL || client->dst_port[0] != '\0') {
            errno = 0;
            *port = (u16_t) strtoul(client->dst_port, NULL, 10);
            if (errno != 0) {
                TNL_LOG(ERR, "hosted_service[%s] client[%s] failed to parse dst_port '%s'", h_ctx->service_name,
                        client->identity, client->dst_port);
                return false;
            }
        } else {
            TNL_LOG(ERR,
                    "hosted_service[%s] client[%s] config specifies 'forwardPort' but client did not send dst_port",
                    h_ctx->service_name, client->identity);
            return false;
        }

        if (!port_match(*port, &h_ctx->port_u.allowed_port_ranges)) {
            TNL_LOG(ERR, "hosted_service[%s] client[%s] requested port '%s' is not allowed",
                    h_ctx->service_name, client->identity, client->dst_port);
            return false;
        }
    } else {
        *port = h_ctx->port_u.port;
    }

    return true;
}

static bool get_source_address(const host_ctx_t *h_ctx, const hosted_client_info_t *client,
                               address_t *addr, u16_t *port) {
    const char *source_addr = client->source_addr;
    const char *port_sep = strchr(client->source_addr, ':');
    if (port_sep != NULL) {
        const char *port_str = port_sep + 1;
        errno = 0;
        *port = (u16_t) strtoul(port_str, NULL, 10);
        if (errno != 0) {
            TNL_LOG(ERR, "hosted_service[%s] client[%s] could not parse port in source_addr '%s'",
                    h_ctx->service_name, client->identity, client->source_addr);
            return false;
        }
        source_addr = strndup(client->source_addr, port_sep - client->source_addr);
    }

    bool r = parse_address_r(addr, source_addr, h_ctx->tnlr_ctx->dns);
    if (!r) {
        TNL_LOG(ERR, "hosted_service[%s] client[%s] failed to parse source_addr '%s'",
                h_ctx->service_name, client->identity, source_addr);
    }

    if (source_addr != client->source_addr) {
        free((char *) source_addr);
    }

    return r;
}

void hosted_client_info_init(hosted_client_info_t *client,
                             const char *identity,
                             const char *dst_protocol, const char *dst_ip, const char *dst_port,
                             const char *dst_hostname,
                             const char *src_protocol, const char *src_ip, const char *src_port,
                             const char *source_addr) {
    client->identity = identity;
    client->dst_protocol = dst_protocol;
    client->dst_ip = dst_ip;
    client->dst_port = dst_port;
    client->dst_hostname = dst_hostname;
    client->src_protocol = src_protocol;
    client->src_ip = src_ip;
    client->src_port = src_port;
    client->source_addr = source_addr;
}

hosted_client_info_t *hosted_client_info_new(const char *identity,
                                             const char *dst_protocol, const char *dst_ip, const char *dst_port,
                                             const char *dst_hostname,
                                             const char *src_protocol, const char *src_ip, const char *src_port,
                                             const char *source_addr) {
    hosted_client_info_t *client = malloc(sizeof(hosted_client_info_t));
    hosted_client_info_init(client, identity,
                            dst_protocol, dst_ip, dst_port, dst_hostname,
                            src_protocol, src_ip, src_port, source_addr);
    return client;
}

// todo packets to loopback addresses (with source IP set) are flagged as martian. can be overcome with:
// - linux: sysctl net.ipv4.conf.tun0.route_localnet=1 if dst is 127/8
// - macOS: ???
// - windows: ??
// allowing route_localnet is safe-ish, I think, because all packets that come out
// of the tun were put there by the tsdk - e.g. not routed in from the LAN.

tunneler_io_context ziti_tunneler_dial_host(host_ctx_t *h_ctx, hosted_client_info_t *client, io_ctx_t *io) {

    tunneler_proto_type dst_proto;
    address_t dst_addr;
    u16_t dst_port;

    if (!get_dial_address(h_ctx, client, &dst_proto, &dst_addr, &dst_port)) {
        TNL_LOG(ERR, "hosted_service[%s] client[%s] failed to determine server address",
                h_ctx->service_name, client->identity);
        return NULL;
    }

    address_t src_addr;
    ip_addr_t *src_ip_p = NULL;
    u16_t src_port = 0;

    if (client->source_addr != NULL) {
        src_ip_p = &src_addr.ip;
        if (!get_source_address(h_ctx, client, &src_addr, &src_port)) {
            TNL_LOG(ERR, "hosted_service[%s] client[%s] failed to get source_addr from '%s'",
                    h_ctx->service_name, client->identity, client->source_addr);
            return NULL;
        }
    }

    io->tnlr_io = tunneler_io_new(h_ctx->tnlr_ctx, dst_proto, NULL);
    switch (dst_proto) {
        case tun_tcp:
            io->tnlr_io->tcp = tunneler_tcp_dial_host(h_ctx, io, &dst_addr.ip, dst_port, src_ip_p, src_port);
            break;
        case tun_udp:
            // todo
            TNL_LOG(ERR, "hosted_service[%s] client[%s] hosted udp connections are not yet supported",
                    io->tnlr_io->service_name, io->tnlr_io->client);
            break;
        default:
            TNL_LOG(ERR, "hosted_service[%s] client[%s] invalid destination protocol %d",
                    h_ctx->service_name, client->identity, dst_proto);
            break;
    }

    return io->tnlr_io;
}

void ziti_tunneler_ziti_accept_completed(io_ctx_t *io, bool ok) {
    switch (io->tnlr_io->proto) {
        case tun_tcp:
            tunneler_tcp_hosted_client_ready(io, ok);
            break;
        case tun_udp:
            // todo
            TNL_LOG(ERR, "hosted_service[%s] client[%s] hosted udp connections are not yet supported",
                    io->tnlr_io->service_name, io->tnlr_io->client);
            break;
        default:
            TNL_LOG(ERR, "hosted_service[%s] client[%s] invalid destination protocol %d",
                    io->tnlr_io->service_name, io->tnlr_io->client, io->tnlr_io->proto);
            break;
    }
}

static void send_dns_resp(uint8_t *resp, size_t resp_len, void *ctx) {
    struct resolve_req *rreq = ctx;

    TNL_LOG(TRACE, "sending DNS resp[%zd] -> %s:%d", resp_len, ipaddr_ntoa(&rreq->addr), rreq->port);
    struct pbuf *rp = pbuf_alloc(PBUF_TRANSPORT, resp_len, PBUF_RAM);
    memcpy(rp->payload, resp, resp_len);

    err_t err = udp_sendto_if_src(rreq->tnlr_ctx->dns_pcb, rp, &rreq->addr, rreq->port,
                                  netif_default, &rreq->tnlr_ctx->dns_pcb->local_ip);
    if (err != ERR_OK) {
        TNL_LOG(WARN, "udp_send() DNS response: %d", err);
    }

    pbuf_free(rp);
    free(rreq);
}

static void on_dns_packet(void *arg, struct udp_pcb *pcb, struct pbuf *p,
    const ip_addr_t *addr, u16_t port) {
    tunneler_context tnlr_ctx = arg;

    struct resolve_req *rr = calloc(1,sizeof(struct resolve_req));
    rr->addr = *addr;
    rr->port = port;
    rr->tnlr_ctx = tnlr_ctx;

    int rc = tnlr_ctx->dns->query(tnlr_ctx->dns, p->payload, p->len, send_dns_resp, rr);
    if (rc != 0) {
        TNL_LOG(WARN, "DNS resolve error: %d", rc);
        free(rr);
    }
    pbuf_free(p);
}

void ziti_tunneler_set_dns(tunneler_context tnlr_ctx, dns_manager *dns) {
    tnlr_ctx->dns = dns;
    if (dns->internal_dns) {
        tnlr_ctx->dns_pcb = udp_new();
        ip_addr_t dns_addr = {
                .type = IPADDR_TYPE_V4,
                .u_addr.ip4.addr = dns->dns_ip,
        };
        udp_bind(tnlr_ctx->dns_pcb, &dns_addr, dns->dns_port);
        udp_recv(tnlr_ctx->dns_pcb, on_dns_packet, tnlr_ctx);
    }
}

intercept_ctx_t* intercept_ctx_new(tunneler_context tnlr_ctx, const char *app_id, void *app_intercept_ctx) {
    intercept_ctx_t *ictx = calloc(1, sizeof(intercept_ctx_t));
    ictx->tnlr_ctx = tnlr_ctx;
    ictx->service_name = app_id;
    ictx->app_intercept_ctx = app_intercept_ctx;
    STAILQ_INIT(&ictx->protocols);
    STAILQ_INIT(&ictx->addresses);
    STAILQ_INIT(&ictx->port_ranges);

    return ictx;
}

void intercept_ctx_add_protocol(intercept_ctx_t *ctx, const char *protocol) {
    protocol_t *proto = calloc(1, sizeof(protocol_t));
    proto->protocol = strdup(protocol);
    STAILQ_INSERT_TAIL(&ctx->protocols, proto, entries);
}

bool parse_address_r(address_t *addr, const char *hn_or_ip_or_cidr, dns_manager *dns) {
    if (!addr) {
        TNL_LOG(DEBUG, "null addr");
        return false;
    }
    memset(addr, 0, sizeof(address_t));

    if (!hn_or_ip_or_cidr || hn_or_ip_or_cidr[0] == '\0') {
        TNL_LOG(DEBUG, "null hn_or_ip_or_cidr");
        return false;
    }

    strncpy(addr->str, hn_or_ip_or_cidr, sizeof(addr->str));
    addr->is_hostname = false;
    char *prefix_sep = strchr(addr->str, '/');

    if (prefix_sep != NULL) {
        *prefix_sep = '\0';
        addr->prefix_len = (int)strtol(prefix_sep + 1, NULL, 10);
    }

    if (ipaddr_aton(addr->str, &addr->ip) == 0) {
        // does not parse as IP address; assume hostname and try to get IP from the dns manager
        if (dns) {
            const char *resolved_ip_str = assign_ip(addr->str);
            if (dns->apply(dns, addr->str, resolved_ip_str) != 0) {
                TNL_LOG(ERR, "failed to apply DNS mapping %s => %s", addr->str, resolved_ip_str);
                return false;
            } else {
                TNL_LOG(DEBUG, "intercept hostname %s is not an ip", addr->str);
                if (ipaddr_aton(resolved_ip_str, &addr->ip) == 0) {
                    TNL_LOG(ERR, "dns manager provided unparsable ip address '%s'", resolved_ip_str);
                    return false;
                } else {
                    addr->is_hostname = true;
                }
            }
        }
    }

    uint8_t addr_bits = IP_IS_V4(&addr->ip) ? 32 : 128;
    uint8_t net_bits = addr_bits - addr->prefix_len;

    if (prefix_sep != NULL) {
        // update ip (and str) with masked address - host bits zeroed
        if (addr->ip.type == IPADDR_TYPE_V4) {
            ip_addr_set_ip4_u32(&addr->_netmask, PP_HTONL(IPADDR_BROADCAST >> net_bits << net_bits));
            ip_addr_set_ip4_u32(&addr->ip, ip_2_ip4(&addr->ip)->addr & ip_2_ip4(&addr->_netmask)->addr);
        } else if (addr->ip.type == IPADDR_TYPE_V6) {
            TNL_LOG(ERR, "IPv6 CIDR intercept is not currently supported");
        }
        snprintf(addr->str, sizeof(addr->str), "%s/%d", ipaddr_ntoa(&addr->ip), addr->prefix_len);
    } else {
        // use full ip
        addr->prefix_len = addr_bits;
    }

    return true;
}

address_t *parse_address(const char *hn_or_ip_or_cidr, dns_manager *dns) {
    address_t *addr = calloc(1, sizeof(address_t));
    if (!parse_address_r(addr, hn_or_ip_or_cidr, dns)) {
        free(addr);
        return NULL;
    }
    return addr;
}

address_t *intercept_ctx_add_address(intercept_ctx_t *i_ctx, const char *address) {
    address_t *addr = parse_address(address, i_ctx->tnlr_ctx->dns);

    if (addr == NULL) {
        TNL_LOG(ERR, "failed to parse address '%s' service[%s]", address, i_ctx->service_name);
        return NULL;
    }

    STAILQ_INSERT_TAIL(&i_ctx->addresses, addr, entries);
    return addr;
}

port_range_t *parse_port_range(uint16_t low, uint16_t high) {
    port_range_t *pr = calloc(1, sizeof(port_range_t));
    if (low <= high) {
        pr->low = low;
        pr->high = high;
    } else {
        pr->low = high;
        pr->high = low;
    }

    if (low == high) {
        snprintf(pr->str, sizeof(pr->str), "%d", low);
    } else {
        snprintf(pr->str, sizeof(pr->str), "[%d-%d]", low, high);
    }
    return pr;
}

port_range_t *intercept_ctx_add_port_range(intercept_ctx_t *i_ctx, uint16_t low, uint16_t high) {
    port_range_t *pr = parse_port_range(low, high);
    STAILQ_INSERT_TAIL(&i_ctx->port_ranges, pr, entries);
    return pr;
}

/** intercept a service as described by the intercept_ctx */
int ziti_tunneler_intercept(tunneler_context tnlr_ctx, intercept_ctx_t *i_ctx) {
    if (tnlr_ctx == NULL) {
        TNL_LOG(ERR, "null tnlr_ctx");
        return -1;
    }

    address_t *address;
    STAILQ_FOREACH(address, &i_ctx->addresses, entries) {
        protocol_t *proto;
        STAILQ_FOREACH(proto, &i_ctx->protocols, entries) {
            port_range_t *pr;
            STAILQ_FOREACH(pr, &i_ctx->port_ranges, entries) {
                // todo find conflicts with services
                // intercept_ctx_t *match;
                // match = lookup_intercept_by_address(tnlr_ctx, proto->protocol, &address->ip, pr->low, pr->high);
                TNL_LOG(DEBUG, "intercepting address[%s:%s:%s] service[%s]",
                        proto->protocol, address->str, pr->str, i_ctx->service_name);
            }
        }
    }

    STAILQ_FOREACH(address, &i_ctx->addresses, entries) {
         add_route(tnlr_ctx->opts.netif_driver, address);
    }

    STAILQ_INSERT_TAIL(&tnlr_ctx->intercepts, (struct intercept_ctx_s *)i_ctx, entries);

    return 0;
}

static void tunneler_kill_active(const void *zi_ctx) {
    struct io_ctx_list_s *l;
    ziti_sdk_close_cb zclose;

    l = tunneler_tcp_active(zi_ctx);
    while (!SLIST_EMPTY(l)) {
        struct io_ctx_list_entry_s *n = SLIST_FIRST(l);
        TNL_LOG(DEBUG, "service_ctx[%p] client[%s] killing active connection", zi_ctx, n->io->tnlr_io->client);
        // close the ziti connection, which also closes the underlay
        zclose = n->io->tnlr_io->tnlr_ctx->opts.ziti_close;
        if (zclose) zclose(n->io->ziti_io);
        SLIST_REMOVE_HEAD(l, entries);
        free(n);
    }
    free(l);

    // todo be selective about protocols when merging newer config types
    l = tunneler_udp_active(zi_ctx);
    while (!SLIST_EMPTY(l)) {
        struct io_ctx_list_entry_s *n = SLIST_FIRST(l);
        TNL_LOG(DEBUG, "service[%p] client[%s] killing active connection", zi_ctx, n->io->tnlr_io->client);
        // close the ziti connection, which also closes the underlay
        zclose = n->io->tnlr_io->tnlr_ctx->opts.ziti_close;
        if (zclose) zclose(n->io->ziti_io);
        SLIST_REMOVE_HEAD(l, entries);
        free(n);
    }
    free(l);
}

// when called due to service unavailable we want to remove from tnlr_ctx.
// when called due to conflict we want to mark as disabled
void ziti_tunneler_stop_intercepting(tunneler_context tnlr_ctx, void *zi_ctx) {
    if (tnlr_ctx == NULL) {
        TNL_LOG(DEBUG, "null tnlr_ctx");
        return;
    }

    TNL_LOG(DEBUG, "removing intercept for service_ctx[%p]", zi_ctx);
    struct intercept_ctx_s *intercept;
    STAILQ_FOREACH(intercept, &tnlr_ctx->intercepts, entries) {
        if (intercept->app_intercept_ctx == zi_ctx) {
            STAILQ_REMOVE(&tnlr_ctx->intercepts, intercept, intercept_ctx_s, entries);
            break;
        }
    }

    if (intercept) {
        TNL_LOG(DEBUG, "removing intercept for service[%s] service_ctx[%p]", intercept->service_name, zi_ctx);

        while(!STAILQ_EMPTY(&intercept->protocols)) {
            protocol_t *p = STAILQ_FIRST(&intercept->protocols);
            STAILQ_REMOVE(&intercept->protocols, p, protocol_s, entries);
            free(p->protocol);
            free(p);
        }
        while(!STAILQ_EMPTY(&intercept->addresses)) {
            address_t *a = STAILQ_FIRST(&intercept->addresses);
            STAILQ_REMOVE(&intercept->addresses, a, address_s, entries);
            free(a);
        }

        while(!STAILQ_EMPTY(&intercept->port_ranges)) {
            port_range_t *p = STAILQ_FIRST(&intercept->port_ranges);
            STAILQ_REMOVE(&intercept->port_ranges, p, port_range_s , entries);
            free(p);
        }

        free(intercept);
    }


    tunneler_kill_active(zi_ctx);

}

void ziti_tunneler_stop_hosting(tunneler_context tnlr_ctx, void *zh_ctx) {
    // todo
}

/** called by tunneler application when data is read from a ziti connection */
ssize_t ziti_tunneler_write(tunneler_io_context tnlr_io_ctx, const void *data, size_t len) {
    if (tnlr_io_ctx == NULL) {
        TNL_LOG(WARN, "null tunneler io context");
        return -1;
    }

    ssize_t r;
    switch (tnlr_io_ctx->proto) {
        case tun_tcp:
            r = tunneler_tcp_write(tnlr_io_ctx->tcp, data, len);
            break;
        case tun_udp:
            r = tunneler_udp_write(tnlr_io_ctx->udp.pcb, data, len);
            break;
    }

    return r;
}

/** called by tunneler application when a ziti connection closes */
int ziti_tunneler_close(tunneler_io_context tnlr_io_ctx) {
    if (tnlr_io_ctx == NULL) {
        TNL_LOG(INFO, "null tnlr_io_ctx");
        return 0;
    }
    TNL_LOG(INFO, "closing connection: service=%s, client=%s",
            tnlr_io_ctx->service_name, tnlr_io_ctx->client);
    switch (tnlr_io_ctx->proto) {
        case tun_tcp:
            tunneler_tcp_close(tnlr_io_ctx->tcp);
            tnlr_io_ctx->tcp = NULL;
            break;
        case tun_udp:
            tunneler_udp_close(tnlr_io_ctx->udp.pcb);
            tnlr_io_ctx->udp.pcb = NULL;
            break;
        default:
            TNL_LOG(ERR, "unknown proto %d", tnlr_io_ctx->proto);
            break;
    }

    free(tnlr_io_ctx);
    return 0;
}

/** called by tunneler application when an EOF is received from ziti */
int ziti_tunneler_close_write(tunneler_io_context tnlr_io_ctx) {
    if (tnlr_io_ctx == NULL) {
        TNL_LOG(INFO, "null tnlr_io_ctx");
        return 0;
    }
    TNL_LOG(INFO, "closing write connection: service=%s, client=%s",
            tnlr_io_ctx->service_name, tnlr_io_ctx->client);
    switch (tnlr_io_ctx->proto) {
        case tun_tcp:
            tunneler_tcp_close_write(tnlr_io_ctx->tcp);
            break;
        default:
            TNL_LOG(DEBUG, "not sending FIN on %d connection", tnlr_io_ctx->proto);
            break;
    }
    return 0;
}

static void on_tun_data(uv_poll_t * req, int status, int events) {
    if (status != 0) {
        TNL_LOG(WARN, "not sure why status is %d", status);
        return;
    }

    if (events & UV_READABLE) {
        netif_shim_input(netif_default);
    }
}

static void check_lwip_timeouts(uv_timer_t * handle) {
    sys_check_timeouts();
}

/**
 * set up a protocol handler. lwip will call recv_fn with arg for each
 * packet that matches the protocol.
 */
static struct raw_pcb * init_protocol_handler(u8_t proto, raw_recv_fn recv_fn, void *arg) {
    struct raw_pcb *pcb;
    err_t err;

    if ((pcb = raw_new_ip_type(IPADDR_TYPE_ANY, proto)) == NULL) {
        TNL_LOG(ERR, "failed to allocate raw pcb for protocol %d", proto);
        return NULL;
    }

    if ((err = raw_bind(pcb, IP_ANY_TYPE)) != ERR_OK) {
        TNL_LOG(ERR, "failed to bind for protocol %d: error %d", proto, err);
        raw_remove(pcb);
        return NULL;
    }

    raw_bind_netif(pcb, netif_default);
    raw_recv(pcb, recv_fn, arg);

    return pcb;
}

static void run_packet_loop(uv_loop_t *loop, tunneler_context tnlr_ctx) {
    tunneler_sdk_options opts = tnlr_ctx->opts;
    if (opts.ziti_close == NULL || opts.ziti_close_write == NULL ||  opts.ziti_write == NULL ||
        opts.ziti_dial == NULL || opts.ziti_accept == NULL) {
        TNL_LOG(ERR, "ziti_sdk_* callback options cannot be null");
        exit(1);
    }

    lwip_init();

    netif_driver netif_driver = opts.netif_driver;
    if (netif_add_noaddr(&tnlr_ctx->netif, netif_driver, netif_shim_init, ip_input) == NULL) {
        TNL_LOG(ERR, "netif_add failed");
        exit(1);
    }

    netif_set_default(&tnlr_ctx->netif);
    netif_set_link_up(&tnlr_ctx->netif);
    netif_set_up(&tnlr_ctx->netif);

    if (netif_driver->setup) {
        netif_driver->setup(netif_driver->handle, loop, on_packet, netif_default);
    } else if (netif_driver->uv_poll_init) {
        netif_driver->uv_poll_init(netif_driver->handle, loop, &tnlr_ctx->netif_poll_req);
        if (uv_poll_start(&tnlr_ctx->netif_poll_req, UV_READABLE, on_tun_data) != 0) {
            TNL_LOG(ERR, "failed to start tun poll handle");
            exit(1);
        }
    } else {
        TNL_LOG(WARN, "no method to initiate tunnel reader, maybe it's ok");
    }

    if ((tnlr_ctx->tcp = init_protocol_handler(IP_PROTO_TCP, recv_tcp, tnlr_ctx)) == NULL) {
        TNL_LOG(ERR, "tcp setup failed");
        exit(1);
    }
    if ((tnlr_ctx->udp = init_protocol_handler(IP_PROTO_UDP, recv_udp, tnlr_ctx)) == NULL) {
        TNL_LOG(ERR, "udp setup failed");
        exit(1);
    }

    uv_timer_init(loop, &tnlr_ctx->lwip_timer_req);
    uv_timer_start(&tnlr_ctx->lwip_timer_req, check_lwip_timeouts, 0, 10);
}

#define _str(x) #x
#define str(x) _str(x)
const char* ziti_tunneler_version() {
    return str(GIT_VERSION);
}