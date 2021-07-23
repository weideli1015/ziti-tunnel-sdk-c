/*
Copyright 2021 NetFoundry, Inc.

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

#if _WIN32
// _WIN32_WINNT needs to be declared and needs to be > 0x600 in order for
// some constants used below to be declared
#define _WIN32_WINNT  _WIN32_WINNT_WIN6
 // Windows Server 2008
#include <ws2tcpip.h>
#endif


#include <stdio.h>
#include <ziti/ziti_log.h>
#include <memory.h>
#include <ziti/ziti_tunnel_cbs.h>

#define safe_free(p) if ((p) != NULL) free((p))

void free_ziti_host(ziti_host_t *zh_ctx) {
    if (zh_ctx == NULL) {
        return;
    }
    safe_free((char *)zh_ctx->service_name);
    switch (zh_ctx->cfg_type) {
        case HOST_CFG_V1:
            free_ziti_host_cfg_v1(&zh_ctx->cfg.host_v1);
            break;
        case SERVER_CFG_V1:
            free_ziti_server_cfg_v1(&zh_ctx->cfg.server_v1);
            break;
        default:
            ZITI_LOG(DEBUG, "unexpected cfg_type %d", zh_ctx->cfg_type);
            break;
    }

}

/** called by ziti sdk when a client connection is established (or fails) */
static void on_hosted_client_connect_complete(ziti_connection clt, int err) {
    io_ctx_t *io = ziti_conn_data(clt);
    ziti_host_t *zh = get_app_host_ctx(io->service.host_ctx);
    if (err == ZITI_OK) {
        ZITI_LOG(DEBUG, "hosted_service[%s] client[%s] connected", zh->service_name, ziti_conn_source_identity(clt));
    } else {
        ZITI_LOG(ERROR, "hosted_service[%s] client[%s] failed to connect: %s", zh->service_name,
                 ziti_conn_source_identity(clt), ziti_errorstr(err));
    }
    ziti_tunneler_ziti_accept_completed(io, err == ZITI_OK);
}

/** called by ziti sdk when a ziti endpoint (client) initiates connection to a hosted service
 * - create hosted_client_info from client's app_data, if any
 * - create io_ctx_t, populated with ziti connection
 * - initiate connection with hosted service
 */
static void on_hosted_client_connect(ziti_connection serv, ziti_connection clt, int status, ziti_client_ctx *clt_ctx) {
    host_ctx_t *h_ctx = ziti_conn_data(serv);
    if (h_ctx == NULL) {
        ZITI_LOG(ERROR, "null host_ctx");
        ziti_close(clt, ziti_conn_close_cb);
        return;
    }
    ziti_host_t *zh = get_app_host_ctx(h_ctx);

    if (status != ZITI_OK) {
        ZITI_LOG(ERROR, "incoming connection to service[%s] failed: %s", zh->service_name, ziti_errorstr(status));
        ziti_close(clt, ziti_conn_close_cb);
        return;
    }

    const char *client_identity = clt_ctx->caller_id;
    if (client_identity == NULL) client_identity = "<unidentified>";

    hosted_client_info_t *client_p = NULL, client = {0};
    tunneler_app_data app_data = {0};
    if (clt_ctx->app_data != NULL) {
        ZITI_LOG(DEBUG, "hosted_service[%s], client[%s]: received app_data_json='%.*s'", zh->service_name,
                 client_identity, (int) clt_ctx->app_data_sz, clt_ctx->app_data);
        if (parse_tunneler_app_data(&app_data, (char *) clt_ctx->app_data, clt_ctx->app_data_sz) != 0) {
            ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: failed to parse app_data_json '%.*s'",
                     zh->service_name,
                     client_identity, (int) clt_ctx->app_data_sz, clt_ctx->app_data);
            ziti_close(clt, ziti_conn_close_cb);
        }
        client_p = &client;
        hosted_client_info_init(client_p, client_identity,
                                app_data.dst_protocol, app_data.dst_ip, app_data.dst_port,
                                app_data.dst_hostname,
                                app_data.src_protocol, app_data.src_ip, app_data.src_port,
                                app_data.source_addr);
    }


    struct io_ctx_s *io = calloc(1, sizeof(struct io_ctx_s));
    ziti_io_context *ziti_io = calloc(1, sizeof(ziti_io_context));
    io->ziti_ctx = zh;
    io->ziti_io = ziti_io;
    io->service.host_ctx = h_ctx;
    ziti_io->ziti_conn = clt;
    ziti_conn_set_data(clt, io);

    ziti_tunneler_dial_host(h_ctx, client_p, io);
}

/** called by ziti SDK when a hosted service listener is ready */
static void hosted_listen_cb(ziti_connection serv, int status) {
    host_ctx_t *h_ctx = ziti_conn_data(serv);
    if (h_ctx == NULL) {
        ZITI_LOG(DEBUG, "null host_ctx");
        return;
    }

    if (status != ZITI_OK) {
        ziti_host_t *zh_ctx = get_app_host_ctx(h_ctx);
        ZITI_LOG(ERROR, "unable to host service %s: %s", zh_ctx->service_name, ziti_errorstr(status));
        ziti_conn_set_data(serv, NULL);
        ziti_close(serv, ziti_conn_close_cb);
        host_ctx_free(h_ctx);
    }
}

static void listen_opts_from_host_cfg_v1(ziti_listen_opts *opts, const ziti_host_cfg_v1 *config) {
    tag *t;

    opts->bind_using_edge_identity = false;
    t = model_map_get(&config->listen_options, "bindUsingEdgeIdentity");
    if (t != NULL) {
        opts->bind_using_edge_identity = t->bool_value;
    }

    opts->identity = NULL;
    t = model_map_get(&config->listen_options, "identity");
    if (t != NULL) {
        if (opts->bind_using_edge_identity) {
            ZITI_LOG(WARN, "listen options specifies both 'identity=%s' and 'bindUsingEdgeIdentity=true'",
                     t->string_value);
        } else {
            opts->identity = t->string_value;
        }
    }

    opts->connect_timeout_seconds = 5;
    t = model_map_get(&config->listen_options, "connectTimeoutSeconds");
    if (t != NULL) {
        opts->connect_timeout_seconds = t->num_value;
    }

    opts->terminator_precedence = PRECEDENCE_DEFAULT;
    t = model_map_get(&config->listen_options, "precedence");
    if (t != NULL) {
        if (strcmp(t->string_value, "default") == 0) {
            opts->terminator_precedence = PRECEDENCE_DEFAULT;
        } else if (strcmp(t->string_value, "required") == 0) {
            opts->terminator_precedence = PRECEDENCE_REQUIRED;
        } else if (strcmp(t->string_value, "failed") == 0) {
            opts->terminator_precedence = PRECEDENCE_FAILED;
        } else {
            ZITI_LOG(WARN, "unsupported terminator precedence '%s'", t->string_value);
        }
    }

    opts->terminator_cost = 0;
    t = model_map_get(&config->listen_options, "cost");
    if (t != NULL) {
        opts->terminator_cost = t->num_value;
    }
}

ziti_host_t *new_ziti_host(ziti_context ztx, ziti_service *service) {
    ziti_host_t *zh_ctx = calloc(1, sizeof(ziti_host_t));
    zh_ctx->ztx = ztx;
    zh_ctx->service_name = service->name;
    bool have_host = false;

    for (int i = 0; i < sizeof(host_cfgtypes) / sizeof(cfgtype_desc_t); i++) {
        cfgtype_desc_t *cfgtype = &host_cfgtypes[i];
        const char *cfg_json = ziti_service_get_raw_config(service, cfgtype->name);
        if (cfg_json != 0 && cfgtype->parse(&zh_ctx->cfg, cfg_json, strlen(cfg_json)) == 0) {
            ZITI_LOG(INFO, "creating host context for service[%s] with %s = %s", service->name, cfgtype->name, cfg_json);
            have_host = true;
            zh_ctx->cfg_type = cfgtype->cfgtype;
            break;
        }
    }

    if (!have_host) {
        free(zh_ctx);
        return NULL;
    }
    return zh_ctx;
}

host_ctx_t *new_host_ctx(tunneler_context tnlr_ctx, ziti_host_t *zh_ctx) {
    host_ctx_t *h_ctx = host_ctx_new(tnlr_ctx, zh_ctx->service_name, zh_ctx);

    if (zh_ctx->service_name == NULL) {
        ZITI_LOG(ERROR, "null service_name");
        return NULL;
    }

    ziti_listen_opts listen_opts;
    ziti_listen_opts *listen_opts_p = NULL;
    switch (zh_ctx->cfg_type) {
        case HOST_CFG_V1: {
            const ziti_host_cfg_v1 *host_v1_cfg = &zh_ctx->cfg.host_v1;
            listen_opts_from_host_cfg_v1(&listen_opts, host_v1_cfg);
            listen_opts_p = &listen_opts;
            int i;

            if (host_v1_cfg->forward_protocol) {
                string_array allowed_protos = host_v1_cfg->allowed_protocols;
                for (i = 0; allowed_protos != NULL && allowed_protos[i] != NULL; i++) {
                    host_ctx_add_allowed_protocol(h_ctx, allowed_protos[i]);
                }
                if (i == 0) {
                    ZITI_LOG(ERROR,
                             "hosted_service[%s] specifies 'forwardProtocol' with zero-length 'allowedProtocols'",
                             zh_ctx->service_name);
                    host_ctx_free(h_ctx);
                    return NULL;
                }
            } else {
                host_ctx_set_protocol(h_ctx, host_v1_cfg->protocol);
            }


            if (host_v1_cfg->forward_address) {
                string_array allowed_addrs = host_v1_cfg->allowed_addresses;
                for (i = 0; allowed_addrs != NULL && allowed_addrs[i] != NULL; i++) {
                    if (host_ctx_add_allowed_address(h_ctx, allowed_addrs[i]) == NULL) {
                        ZITI_LOG(ERROR, "hosted_service[%s] failed to parse allowed_address '%s'",
                                 zh_ctx->service_name, allowed_addrs[i]);
                        host_ctx_free(h_ctx);
                        return NULL;
                    }
                }
                if (i == 0) {
                    ZITI_LOG(ERROR, "hosted_service[%s] specifies 'forwardAddress' with zero-length 'allowedAddresses'",
                             zh_ctx->service_name);
                    host_ctx_free(h_ctx);
                    return NULL;
                }
            } else {
                host_ctx_set_address(h_ctx, host_v1_cfg->address);
            }

            if (host_v1_cfg->forward_port) {
                ziti_port_range_array port_ranges = host_v1_cfg->allowed_port_ranges;
                for (i = 0; port_ranges != NULL && port_ranges[i] != NULL; i++) {
                    host_ctx_add_allowed_port_range(h_ctx, port_ranges[i]->low, port_ranges[i]->high);
                }
                if (i == 0) {
                    ZITI_LOG(ERROR, "hosted_service[%s] specifies 'forwardPort' with zero-length 'allowedPortRanges'",
                             zh_ctx->service_name);
                    host_ctx_free(h_ctx);
                    return NULL;
                }
            } else {
                host_ctx_set_port(h_ctx, host_v1_cfg->port);
            }

            string_array allowed_src_addrs = host_v1_cfg->allowed_source_addresses;
            for (i = 0; allowed_src_addrs != NULL && allowed_src_addrs[i] != NULL; i++) {
                if (host_ctx_add_allowed_source_address(h_ctx, allowed_src_addrs[i]) == NULL) {
                    ZITI_LOG(ERROR, "hosted_service[%s] failed to parse allowed_source_address '%s'",
                             zh_ctx->service_name, allowed_src_addrs);
                    host_ctx_free(h_ctx);
                    return NULL;
                }
            }
        }
            break;
        case SERVER_CFG_V1: {
            const ziti_server_cfg_v1 *server_v1_cfg = &zh_ctx->cfg.server_v1;
            host_ctx_set_protocol(h_ctx, server_v1_cfg->protocol);
            host_ctx_set_address(h_ctx, server_v1_cfg->hostname);
            host_ctx_set_port(h_ctx, server_v1_cfg->port);
        }
            break;
        default:
            ZITI_LOG(WARN, "unexpected cfg_type %d", zh_ctx->cfg_type);
            break;
    }

    host_ctx_set_display_address(h_ctx);
    ziti_connection serv;
    ziti_conn_init(zh_ctx->ztx, &serv, h_ctx);

    char listen_identity[128];
    if (listen_opts_p != NULL) {
        if (listen_opts_p->identity != NULL && listen_opts_p->identity[0] != '\0') {
            const ziti_identity *zid = ziti_get_identity(zh_ctx->ztx);
            strncpy(listen_identity, listen_opts_p->identity, sizeof(listen_identity));
            if (string_replace(listen_identity, sizeof(listen_identity), "$tunneler_id.name", zid->name) != NULL) {
                listen_opts_p->identity = listen_identity;
            }
        }
    }
    ziti_listen_with_options(serv, zh_ctx->service_name, listen_opts_p, hosted_listen_cb, on_hosted_client_connect);

    return h_ctx;
}

// todo: pass connect status here (and ziti_close here)? alternative is to close ziti in close cb
// todo: return accept status here? tsdk might close if this fails. alternative is to do this in close cb.

/** called by tsdk when a connection to a hosted server is established (or fails) */
bool ziti_sdk_c_accept(const void *zh_ctx, io_ctx_t *io) {
    ziti_host_t *zh = zh_ctx;
    ziti_io_context *ziti_io = io->ziti_io;

    int r = ziti_accept(ziti_io->ziti_conn, on_hosted_client_connect_complete, on_ziti_data);
    return r == ZITI_OK;
}