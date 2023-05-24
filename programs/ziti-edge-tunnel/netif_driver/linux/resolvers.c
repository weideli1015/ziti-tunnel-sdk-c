/*
 Copyright 2021 NetFoundry Inc.

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

#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
#include <net/if.h>
#include <stdarg.h>
#include "linux/libsystemd.h"
#endif

#include <ziti/ziti_log.h>
#include <uv.h>

#include "resolvers.h"
#include "utils.h"

#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
#define RET_ON_FAIL(bool_func) do{if (!(bool_func)) return;} while(0)

static int detect_systemd_resolved_routing_domain_wildcard(sd_bus *bus, int32_t ifindex) {
    _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *reply = NULL;
    _cleanup_(sd_bus_error_free_wrapper) sd_bus_error error = SD_BUS_ERROR_NULL;

    int r;

    r = sd_bus_get_property_f(
            bus,
            RESOLVED_DBUS_NAME,
            RESOLVED_DBUS_PATH,
            RESOLVED_DBUS_MANAGER_INTERFACE,
            "Domains",
            &error,
            &reply,
            "a(isb)"
            );
    if (r < 0) {
        ZITI_LOG(ERROR, "Could not retrieve systemd-resolved domains: (%s, %s)", error.name, error.message);
        return r;
    }

    r = sd_bus_message_enter_container_f(reply, SD_BUS_TYPE_ARRAY, "(isb)");
    if (r < 0) {
        ZITI_LOG(ERROR, "Failure composing DBus message: (%s, %s)", error.name, error.message);
        return r;
    }

    struct s_domain {
        int32_t ifindex;
        char * name;
        int is_routing_only;
    };

    struct s_domain domain;

    int routing_only_wildcard_set = 1;

    while ((r = sd_bus_message_read_f(reply, "(isb)", &domain.ifindex, &domain.name, &domain.is_routing_only)) > 0) {
        // Don't break out of loop when we find the route-only wildcard is set on a separate interface.
        // We must exhaust all container members before exiting the container.
        if ((domain.ifindex != ifindex) && (strcmp(domain.name, ".") == 0) && (domain.is_routing_only == 1)) {
            routing_only_wildcard_set = 0;
        }
    }

    if (routing_only_wildcard_set == 0) {
        ZITI_LOG(DEBUG, "systemd-resolved routing only domain wildcard found");
    }

    if (r < 0) {
        ZITI_LOG(ERROR, "Failure reading DBus message: %s", strerror(-r));
        return r;
    }

    r = sd_bus_message_exit_container_f(reply);
    if (r < 0) {
        ZITI_LOG(ERROR, "Failure exiting DBus message container: %s", strerror(-r));
        return r;
    }

    return routing_only_wildcard_set;
}

static bool set_systemd_resolved_link_setting(sd_bus *bus, const char* tun, const char* method, const char* method_type, ...) {
    _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *reply = NULL;
    _cleanup_(sd_bus_error_free_wrapper) sd_bus_error error = SD_BUS_ERROR_NULL;

    int r;
    va_list ap;

    va_start(ap, method_type);

    r = sd_bus_call_method_va(
            bus,
            RESOLVED_DBUS_NAME,
            RESOLVED_DBUS_PATH,
            RESOLVED_DBUS_MANAGER_INTERFACE,
            method,
            &error,
            &reply,
            method_type,
            ap);

    va_end(ap);

    if (r < 0) {
        if (sd_bus_error_has_name_f(&error, SD_BUS_ERROR_UNKNOWN_METHOD)) {
            ZITI_LOG(WARN, "Attempted to call unknown method: %s for link: (%s)",
                    method, tun);
            return true;
        }

        ZITI_LOG(ERROR, "Failure calling method: %s for link: (%s): (%s, %s)",
                 method, tun, error.name, error.message);
        return false;
    }

    ZITI_LOG(DEBUG, "Success calling method: %s for link: (%s)", method, tun);

    return true;
}

bool try_libsystemd_resolver(void) {
    if (!libsystemd_dl_success) {
        return false;
    }

    _cleanup_(sd_bus_flush_close_unrefp_f) sd_bus *bus = NULL;

    int r;

    if (sd_booted_f() > 0) {
        ZITI_LOG(DEBUG, "Detected systemd is init system");
    } else {
        ZITI_LOG(DEBUG, "Could not detect systemd init system");
    }

    r = sd_bus_open_system_f(&bus);
    if ((r >= 0) && (sd_bus_is_bus_client_f(bus) > 0)) {
        ZITI_LOG(DEBUG, "Connected to system DBus");
        r = sd_bus_is_acquired_name(bus, RESOLVED_DBUS_NAME);
        if (r != 0) {
            ZITI_LOG(WARN, "libsystemd resolver unsuccessful. Falling back to legacy resolvers");
            return false;
        }
        if (r == 0) {
            ZITI_LOG(INFO, "systemd-resolved selected as dns resolver manager");
            return true;
        }
    } else {
        ZITI_LOG(DEBUG, "Could not create system DBus client");
    }

    return false;
}

void dns_update_systemd_resolved(const char* tun, unsigned int ifindex, const char* addr) {
    int r;
    struct in_addr inaddr;

    _cleanup_(sd_bus_flush_close_unrefp_f) sd_bus *bus = NULL;

    // dbus 'ay' encodes 'array of bytes'
    unsigned char ay[4];

    r = inet_pton(AF_INET, addr, &inaddr);

    if (r != 1) {
        ZITI_LOG(ERROR, "Failed to translate dns address. Received: %s", addr);
        return;
    } else {
        sscanf(addr, "%hhu.%hhu.%hhu.%hhu", &ay[0], &ay[1], &ay[2], &ay[3]);
    }

    r = sd_bus_open_system_f(&bus);
    if (r < 0) {
        ZITI_LOG(ERROR, "Could not connect to system DBus: %s", strerror(-r));
        return;
    }

    RET_ON_FAIL(set_systemd_resolved_link_setting(bus, tun, "SetLinkLLMNR", "is", ifindex, "no"));
    RET_ON_FAIL(set_systemd_resolved_link_setting(bus, tun, "SetLinkMulticastDNS", "is", ifindex, "no"));
    RET_ON_FAIL(set_systemd_resolved_link_setting(bus, tun, "SetLinkDNSOverTLS", "is", ifindex, "no"));
    RET_ON_FAIL(set_systemd_resolved_link_setting(bus, tun, "SetLinkDNSSEC", "is", ifindex, "no"));
    RET_ON_FAIL(set_systemd_resolved_link_setting(bus, tun, "SetLinkDNS", "ia(iay)", ifindex, 1, AF_INET, 4, ay[0], ay[1], ay[2], ay[3]));

    r = detect_systemd_resolved_routing_domain_wildcard(bus, ifindex);

    switch(r) {
        case 0:
            ZITI_LOG(INFO, "Setting wildcard routing only domain on interface: %s", tun);
            RET_ON_FAIL(set_systemd_resolved_link_setting(bus, tun, "SetLinkDomains", "ia(sb)", ifindex, 1, ".", true));
            break;
        case 1:
            ZITI_LOG(DEBUG, "Setting empty domain on interface: %s", tun);
            RET_ON_FAIL(set_systemd_resolved_link_setting(bus, tun, "SetLinkDomains", "ia(sb)", ifindex, 0));
            break;
        default:
            ZITI_LOG(ERROR, "Error detecting systemd-resolved domain configuration: %s", strerror(-r));
            return;
    }

    sd_bus_run_command(bus, RESOLVED_DBUS_NAME, RESOLVED_DBUS_PATH, RESOLVED_DBUS_MANAGER_INTERFACE, "FlushCaches");
    sd_bus_run_command(bus, RESOLVED_DBUS_NAME, RESOLVED_DBUS_PATH, RESOLVED_DBUS_MANAGER_INTERFACE, "ResetServerFeatures");
}
#endif

void dns_update_resolvconf(const char* tun, unsigned int ifindex, const char* addr) {
    run_command("echo 'nameserver %s' | %s -a %s", addr, RESOLVCONF, tun);
}

void dns_update_etc_resolv(const char* tun, unsigned int ifindex, const char* addr) {
    if (run_command_ex(false, "grep -q '^nameserver %s' /etc/resolv.conf", addr) != 0) {
        run_command("sed -z -i 's/nameserver/nameserver %s\\nnameserver/' /etc/resolv.conf", addr);
    }
}

bool is_systemd_resolved_primary_resolver(void){
    if (is_symlink("/etc/resolv.conf")){

        const char *valid_links[] = {
            "/run/systemd/resolve/stub-resolv.conf",
            "/run/systemd/resolve/resolv.conf",
            "/usr/lib/systemd/resolv.conf",
            "/lib/systemd/resolv.conf"
        };

        char buf[PATH_MAX];
        char *actualpath = realpath("/etc/resolv.conf", buf);

        if (actualpath != NULL) {
            for (int idx = 0; idx < (sizeof(valid_links) / sizeof(valid_links[0])); idx++) {
                if (strcmp(actualpath, valid_links[idx]) == 0) {
                    ZITI_LOG(INFO, "Detected systemd-resolved is primary system resolver");
                    return true;
                }
            }
        }
    }

    return false;
}

bool is_resolvconf_systemd_resolved(void) {
    if (is_symlink(RESOLVCONF)) {
        char buf[PATH_MAX];
        char *actualpath = realpath(RESOLVCONF, buf);

        if (actualpath != NULL) {
            char *file_base = basename(actualpath);
            if (strcmp(file_base, basename(RESOLVECTL)) == 0
                || strcmp(file_base, basename(SYSTEMD_RESOLVE)) == 0) {
                ZITI_LOG(DEBUG, "Detected %s is a symlink to systemd-resolved", actualpath);
                return true;
            }
        }
    }
    return false;
}
