#ifndef ZITI_TUNNELER_SDK_ZITI_TUNNEL_CBS_H
#define ZITI_TUNNELER_SDK_ZITI_TUNNEL_CBS_H

#include "ziti/ziti_tunnel.h"
#include "ziti/ziti.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TUNNELER_APP_DATA_MODEL(XX, ...) \
XX(dst_protocol, string, none, dst_protocol, __VA_ARGS__)\
XX(dst_hostname, string, none, dst_hostname, __VA_ARGS__)\
XX(dst_ip, string, none, dst_ip, __VA_ARGS__)\
XX(dst_port, string, none, dst_port, __VA_ARGS__)\
XX(src_protocol, string, none, src_protocol, __VA_ARGS__)\
XX(src_ip, string, none, src_ip, __VA_ARGS__)\
XX(src_port, string, none, src_port, __VA_ARGS__)\
XX(source_addr, string, none, source_addr, __VA_ARGS__)

DECLARE_MODEL(tunneler_app_data, TUNNELER_APP_DATA_MODEL)

#define TUNNEL_COMMANDS(XX,...) \
XX(ZitiDump, __VA_ARGS__)    \
XX(LoadIdentity, __VA_ARGS__)   \
XX(ListIdentities, __VA_ARGS__)

DECLARE_ENUM(TunnelCommand, TUNNEL_COMMANDS)

#define TUNNEL_CMD(XX, ...) \
XX(command, TunnelCommand, none, command, __VA_ARGS__) \
XX(data, json, none, data, __VA_ARGS__)

#define TUNNEL_CMD_RES(XX, ...) \
XX(success, bool, none, success, __VA_ARGS__) \
XX(error, string, none, error, __VA_ARGS__)\
XX(data, json, none, data, __VA_ARGS__)

#define TNL_LOAD_IDENTITY(XX, ...) \
XX(path, string, none, path, __VA_ARGS__)

#define TNL_IDENTITY_INFO(XX, ...) \
XX(name, string, none, name, __VA_ARGS__) \
XX(config, string, none, config, __VA_ARGS__) \
XX(network, string, none, network, __VA_ARGS__) \
XX(id, string, none, id, __VA_ARGS__)

#define TNL_IDENTITY_LIST(XX, ...) \
XX(identities, tunnel_identity_info, array, identities, __VA_ARGS__)

DECLARE_MODEL(tunnel_comand, TUNNEL_CMD)
DECLARE_MODEL(tunnel_result, TUNNEL_CMD_RES)
DECLARE_MODEL(tunnel_load_identity, TNL_LOAD_IDENTITY)
DECLARE_MODEL(tunnel_identity_info, TNL_IDENTITY_INFO)
DECLARE_MODEL(tunnel_identity_list, TNL_IDENTITY_LIST)

/** context passed through the tunneler SDK for network i/o */
typedef struct ziti_io_ctx_s {
    ziti_connection      ziti_conn;
    bool ziti_eof;
    bool tnlr_eof;
} ziti_io_context;

typedef int (*cfg_parse_fn)(void *, const char *, size_t);
typedef void* (*cfg_alloc_fn)();
typedef void (*cfg_free_fn)(void *);

typedef struct cfgtype_desc_s {
    const char *name;
    cfg_type_e cfgtype;
    cfg_alloc_fn alloc;
    cfg_free_fn free;
    cfg_parse_fn parse;
} cfgtype_desc_t;

#define CFGTYPE_DESC(name, cfgtype, type) { (name), (cfgtype), (cfg_alloc_fn)alloc_##type, (cfg_free_fn)free_##type, (cfg_parse_fn)parse_##type }

static struct cfgtype_desc_s intercept_cfgtypes[] = {
        CFGTYPE_DESC("intercept.v1", INTERCEPT_CFG_V1, ziti_intercept_cfg_v1),
        CFGTYPE_DESC("ziti-tunneler-client.v1", CLIENT_CFG_V1, ziti_client_cfg_v1)
};

static struct cfgtype_desc_s host_cfgtypes[] = {
        CFGTYPE_DESC("host.v1", HOST_CFG_V1, ziti_host_cfg_v1),
        CFGTYPE_DESC("ziti-tunneler-server.v1", SERVER_CFG_V1, ziti_server_cfg_v1)
};

typedef struct ziti_host_s {
    const char *service_name;
    ziti_context ztx;
    cfg_type_e cfg_type;
    union {
        ziti_host_cfg_v1 host_v1;
        ziti_server_cfg_v1 server_v1;
    } cfg;
} ziti_host_t;

ziti_host_t *new_ziti_host(ziti_context ztx, ziti_service *service);
void free_ziti_host(ziti_host_t *zh_ctx);
host_ctx_t *new_host_ctx(tunneler_context tnlr_ctx, ziti_host_t *zh_ctx);

typedef void (*command_cb)(const tunnel_result *, void *ctx);
typedef struct {
    int (*process)(const tunnel_comand *cmd, command_cb cb, void *ctx);
    int (*load_identity)(const char *path, command_cb, void *ctx);
} ziti_tunnel_ctrl;

/**
  * replaces first occurrence of _substring_ in _source_ with _with_.
  * returns pointer to last replaced char in _source_, or NULL if no replacement was made.
  */
char *string_replace(char *source, size_t sourceSize, const char *substring, const char *with);

ssize_t on_ziti_data(ziti_connection conn, uint8_t *data, ssize_t len);

/** called by tunneler SDK after a client connection is intercepted */
void *ziti_sdk_c_dial(const void *app_intercept_ctx, struct io_ctx_s *io);

/** called from tunneler SDK when intercepted client sends data */
ssize_t ziti_sdk_c_write(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len);

/** called by tunneler SDK after a client connection's RX is closed
 * return 0 if TX should still be open, 1 if both sides are closed */
int ziti_sdk_c_close(void *io_ctx);
int ziti_sdk_c_close_write(void *io_ctx);

bool ziti_sdk_c_accept(const void *app_host_ctx, struct io_ctx_s *io);

/** passed to ziti-sdk via ziti_options.service_cb */
tunneled_service_t *ziti_sdk_c_on_service(ziti_context ziti_ctx, ziti_service *service, int status, void *tnlr_ctx);

void ziti_conn_close_cb(ziti_connection zc);

const ziti_tunnel_ctrl* ziti_tunnel_init_cmd(uv_loop_t *loop, tunneler_context, command_cb);


#ifdef __cplusplus
}
#endif

#endif //ZITI_TUNNELER_SDK_ZITI_TUNNEL_CBS_H