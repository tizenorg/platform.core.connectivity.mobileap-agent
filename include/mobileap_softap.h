/*
 * mobileap-agent
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __MOBILEAP_SOFTAP_H__
#define __MOBILEAP_SOFTAP_H__

#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus.h>
#include <dlog.h>
#include <vconf.h>
#include <netinet/in.h>
#include <tzplatform_config.h>

#include "mobileap.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG		"MOBILEAP_AGENT"

#define DBG(fmt, args...)	LOGD(fmt, ##args)
#define ERR(fmt, args...)	LOGE(fmt, ##args)
#define SDBG(fmt, args...)	SECURE_LOGD(fmt, ##args)
#define SERR(fmt, args...)	SECURE_LOGE(fmt, ##args)

#define DRIVER_DELAY		250000	/* micro seconds */

#define IF_BUF_LEN		32
#define NET_BUF_LEN		12
#define INTERFACE_NAME_LEN	12
#define SECURITY_TYPE_LEN	32
#define DNSMASQ_RANGE_LEN	32

/* MAC information */
#define MOBILE_AP_INTF_HWADDR_FILE      "/csa/.mac.info"

/* Network Interface */
#define IP_SUBNET_MASK		"255.255.255.0"

#define WIFI_IF			"wlan0"
#define IP_ADDRESS_WIFI		0xC0A82B02	/* 192.168.43.2 */

#define SOFTAP_IF		"wl0.1"
#define IP_ADDRESS_SOFTAP	0xC0A82B01	/* 192.168.43.1 */

#define USB_IF			"usb0"
#define IP_ADDRESS_USB		0xC0A88103	/* 192.168.129.3 */

#define BT_IF_PREFIX		"bnep"
#define BT_IF_ALL		BT_IF_PREFIX"+"
#define IP_ADDRESS_BT_1		0xC0A88201	/* 192.168.130.1 */
#define IP_ADDRESS_BT_2		0xC0A88301	/* 192.168.131.1 */
#define IP_ADDRESS_BT_3		0xC0A88401	/* 192.168.132.1 */
#define IP_ADDRESS_BT_4		0xC0A88501	/* 192.168.133.1 */
#define IP_ADDRESS_BT_5		0xC0A88601	/* 192.168.134.1 */
#define IP_ADDRESS_BT_6		0xC0A88701	/* 192.168.135.1 */
#define IP_ADDRESS_BT_7		0xC0A88801	/* 192.168.136.1 */

#define RET_FAILURE		(-1)
#define RET_SUCCESS		(0)
#define MAX_BUF_SIZE		(256u)

#define DNSMASQ_CONF_LEN	1024
#define DNSMASQ_CONF	\
			"dhcp-range=192.168.43.3,192.168.43.254,255.255.255.0\n" \
			"dhcp-range=192.168.130.2,192.168.130.150,255.255.255.0\n" \
			"dhcp-range=192.168.131.2,192.168.131.150,255.255.255.0\n" \
			"dhcp-range=192.168.132.2,192.168.132.150,255.255.255.0\n" \
			"dhcp-range=192.168.133.2,192.168.133.150,255.255.255.0\n" \
			"dhcp-range=192.168.134.2,192.168.134.150,255.255.255.0\n" \
			"dhcp-range=192.168.135.2,192.168.135.150,255.255.255.0\n" \
			"dhcp-range=192.168.136.2,192.168.136.150,255.255.255.0\n" \
			"dhcp-range=192.168.137.2,192.168.137.150,255.255.255.0\n" \
			"dhcp-range=set:blue,192.168.129.4,192.168.129.150,255.255.255.0\n"\
			"enable-dbus\n" \
			"group=system\n" \
			"user=system\n" \
			"dhcp-option=tag:blue,option:router,192.168.129.3\n" \
			"dhcp-option=6,%s\n"

#define DNSMASQ_CONF_FILE	"/tmp/dnsmasq.conf"

/* Start of hostapd configuration */
#define MH_CTRL_INTF		"/tmp/mh_wpa_ctrl"
#define MH_MONITOR_INTF		"/tmp/mh_wpa_monitor"

#define HOSTAPD_BIN		"/usr/sbin/hostapd"
#define HOSTAPD_ENTROPY_FILE	tzplatform_mkpath(TZ_SYS_VAR, "/lib/misc/hostapd.bin")
#define HOSTAPD_CONF_FILE		tzplatform_mkpath(TZ_SYS_RUN, "/hostapd.conf")
#define HOSTAPD_CTRL_INTF_DIR	tzplatform_mkpath(TZ_SYS_RUN, "/hostapd")
#define HOSTAPD_ALLOWED_LIST	tzplatform_mkpath(TZ_SYS_VAR, "/lib/hostapd/hostapd.accept")
#define HOSTAPD_BLOCKED_LIST	tzplatform_mkpath(TZ_SYS_VAR, "/lib/hostapd/hostapd.deny")

#define HOSTAPD_CTRL_INTF_DIR_FOR_WPS	"/var/run/hostapd"

#define HOSTAPD_CONF_LEN	1024
#define HOSTAPD_DEFAULT_HW_MODE	"g"

/* WPS (Wi-FI Protected Setup)*/
#define HOSTAPD_WPS_DEVICE_NAME     "Tizen AP"
#define HOSTAPD_WPS_DEVICE_TYPE     "6-0050F204-1"
#define HOSTPAD_WPS_CONFIG_METHODS	"label virtual_display virtual_push_button keypad"

#ifndef TIZEN_WLAN_BOARD_SPRD
#define HOSTAPD_CONF		"interface=%s\n" \
				"driver=nl80211\n" \
				"ctrl_interface=%s\n" \
				"ssid=%s\n" \
				"channel=%d\n" \
				"ignore_broadcast_ssid=%d\n" \
				"hw_mode=%s\n" \
				"max_num_sta=%d\n" \
				"macaddr_acl=%d\n" \
				"accept_mac_file=%s\n" \
				"deny_mac_file=%s\n" \
				"ieee80211n=1\n"
#else
#define HOSTAPD_CONF		"interface=%s\n" \
				"driver=nl80211\n" \
				"ctrl_interface=%s\n" \
				"ssid=%s\n" \
				"channel=%d\n" \
				"ignore_broadcast_ssid=%d\n" \
				"hw_mode=%s\n" \
				"max_num_sta=%d\n" \
				"macaddr_acl=%d\n" \
				"accept_mac_file=%s\n" \
				"deny_mac_file=%s\n" \
				"ieee80211n=1\n" \
				"wowlan_triggers=any\n"

#define HOSTAPD_WPS_CONF	"interface=%s\n" \
				"driver=nl80211\n" \
				"ctrl_interface=%s\n" \
				"ssid=%s\n" \
				"channel=%d\n" \
				"ignore_broadcast_ssid=%d\n" \
				"hw_mode=%s\n" \
				"max_num_sta=%d\n" \
				"macaddr_acl=%d\n" \
				"accept_mac_file=%s\n" \
				"deny_mac_file=%s\n" \
				"ieee80211n=1\n" \
				"wowlan_triggers=any\n" \
				"eap_server=1\n" \
				"wps_state=2\n" \
				"ap_setup_locked=1\n" \
				"config_methods=%s\n" \
				"device_type=%s\n" \
				"wpa=2\n" \
				"rsn_pairwise=CCMP\n" \
				"wpa_psk=%s\n"
#endif

#define HOSTAPD_DEBUG_FILE	"/var/log/hostapd.log"
#define HOSTAPD_REQ_MAX_LEN	128
#define HOSTAPD_RETRY_MAX	5
#define HOSTAPD_RETRY_DELAY	500000	/* us */
#define HOSTAPD_STA_DISCONN	"AP-STA-DISCONNECTED "	/* from wpa_ctrl.h */
#define HOSTAPD_STA_CONN	"AP-STA-CONNECTED "
#define HOSTAPD_STA_DISCONN_LEN 20
#define HOSTAPD_STA_CONN_LEN	17
#define HOSTAPD_MONITOR_ATTACH	"ATTACH"
#define HOSTAPD_MONITOR_DETACH	"DETACH"
#define HOSTAPD_DHCP_MAX_INTERVAL 30000 /* 30 seconds */

/* Samsung VSIE value in beacon / probe response.
 * Wi-Fi station can identify AP whether it is tethering or AP only using this value.
 */
#define HOSTAPD_VENDOR_ELEMENTS_TETH	"DD050016328000"	/* Samsung tethering device */
#define HOSTAPD_VENDOR_ELEMENTS_WIFI_AP	"DD050016321000"	/* Specific application mode AP (e.g. GroupPlay) */
/* End of hostapd configuration */

#define IP_FORWARD	"/proc/sys/net/ipv4/ip_forward"
#define IP_CMD		"/usr/sbin/ip"
#define GREP		"/bin/grep"
#define AWK		"/usr/bin/awk"
#define DATA_USAGE_FILE	"/tmp/tethering_data_usage.txt"

#define TETHERING_ROUTING_TABLE	252
#define SRC_ROUTING_RULE	"iif %s lookup %d"
#define DEFAULT_ROUTER		"default via %s dev %s scope global table %d"
#define INTERFACE_ROUTING	"%s/24 table %d dev %s"
#define DNS_ORDER		1
#define TCP_DNS_FORWARD_RULE	"-i %s -p tcp --dport 53 -j DNAT --to %s:53"
#define UDP_DNS_FORWARD_RULE	"-i %s -p udp --dport 53 -j DNAT --to %s:53"

#define MOBILE_AP_STATE_NONE	0
#define MOBILE_AP_STATE_WIFI	1
#define MOBILE_AP_STATE_USB	2
#define MOBILE_AP_STATE_BT	4
#define MOBILE_AP_STATE_WIFI_AP	8
#define MOBILE_AP_STATE_ALL	15

#define DNSMASQ_DBUS_INTERFACE "uk.org.thekelleys.dnsmasq"

#define PROC_NET_DEV			"/proc/net/dev"
#define TETHERING_CONN_TIMEOUT		(1200)	/* 20 Mins */
#define WIFI_AP_CONN_TIMEOUT		(300)	/* 5 Mins */
#define CHECK_NET_STATE_RETRY_COUNT	5
#define PSK_ITERATION_COUNT		4096

typedef struct {
	int hide_mode;

	char ssid[MOBILE_AP_WIFI_SSID_MAX_LEN + 1];
	/* in AP case, hex key will be passed from library, so one extra byte is needed */
	char key[MOBILE_AP_WIFI_KEY_MAX_LEN + 1];
	char security_type[SECURITY_TYPE_LEN];
	char mode[MOBILE_AP_WIFI_MODE_MAX_LEN + 1];
	int channel;
	int mac_filter;
	int max_sta;
} softap_settings_t;

typedef struct {
	unsigned int number;	/* Number of connected device */
				/* BSSID list of connected device */
	char bssid[MOBILE_AP_MAX_WIFI_STA][MOBILE_AP_STR_INFO_LEN];
} softap_device_info_t;

typedef struct {
	const char *key;
	vconf_callback_fn cb;
	int *value;
} vconf_reg_t;

typedef enum {
	MOBILE_AP_DRV_INTERFACE_NONE,
	MOBILE_AP_WEXT,
	MOBILE_AP_NL80211,
} mobile_ap_drv_interface_e;

typedef struct {
	guint tid;
	char *mac_addr;
} sta_timer_t;

/* ssid : 32  key : 64 */
int _mh_core_enable_softap(const mobile_ap_type_e type, const char *ssid,
		const char *security, const char *key, const char *mode, int channel, int hide_mode, int mac_filter, int max_sta);
int _mh_core_disable_softap(void);
int _mh_core_get_device_info(softap_device_info_t *di);
int _mh_core_execute_dhcp_server(void);
int _mh_core_terminate_dhcp_server(void);
int _mh_core_execute_dhcp_server_range(gchar *rangestart, gchar *rangestop);
int _mh_core_enable_masquerade(const char *ext_if);
int _mh_core_disable_masquerade(const char *ext_if);
void _mh_core_add_data_to_array(GPtrArray *array, guint type, gchar *dev_name);
int _mh_core_set_ip_address(const char *if_name, const in_addr_t ip);

int _mh_core_set_mtu(int mtu);
int _mh_core_change_mac(const char *mac);
int _mh_core_enable_port_forwarding(int enable);
int _mh_core_add_port_forwarding_rule(const char* ifname, const char* proto,
		const char* org_ip, int org_port, const char* final_ip, int final_port);
int _mh_core_reset_port_forwarding_rule();
int _mh_core_enable_port_filtering(int enable);
int _mh_core_add_port_filtering_rule(int port, const char *protocol, int allow);
int _mh_core_add_custom_port_filtering_rule(int port1, int port2, const char *protocol, int allow);
int _mh_core_set_vpn_passthrough_rule(int vpn_type, int enable);
int _mh_core_push_wps_button(void);
int _mh_core_set_wps_pin(const char *wps_pin);

void _register_wifi_station_handler(void);
void _unregister_wifi_station_handler(void);

void _block_device_sleep(void);
void _unblock_device_sleep(void);
int _init_tethering(void);
gboolean _deinit_tethering(void);
gboolean _mobileap_clear_state(int state);
gboolean _terminate_mobileap_agent(gpointer user_data);


gboolean _mobileap_is_disabled(void);
gboolean _mobileap_is_enabled(int state);
gboolean _mobileap_is_enabled_by_type(mobile_ap_type_e type);
gboolean _mobileap_set_state(int state);
void _flush_dhcp_ack_timer(void);
void _destroy_dhcp_ack_timer(char *mac_addr);

int _set_hostapd_tx_power(unsigned int txpower);
unsigned int _get_hostapd_tx_power(void);

void _set_dns_address(char *_dns_addr);
#endif
