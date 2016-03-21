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

#ifndef __MOBILEAP_WIFI_H__
#define __MOBILEAP_WIFI_H__

#include "mobileap_softap.h"

#define VCONFKEY_MOBILE_HOTSPOT_SSID		"memory/private/mobileap-agent/ssid"
#define VCONFKEY_SOFTAP_SSID				"memory/private/softap/ssid"
#define SOFTAP_SECURITY_TYPE_OPEN_STR		"open"
#define SOFTAP_SECURITY_TYPE_WPA2_PSK_STR	"wpa2-psk"
#define SOFTAP_PASSPHRASE_PATH			"wifi_tethering.txt"
#define SOFTAP_PASSPHRASE_GROUP_ID		"secure-storage::tethering"

typedef enum {
	SOFTAP_SECURITY_TYPE_OPEN,
	SOFTAP_SECURITY_TYPE_WPA2_PSK,
} softap_security_type_e;

typedef struct {
	int hide_mode;
	int mac_filter;
	char *ssid;
	char *key;
	char *mode;
	int channel;
	softap_security_type_e security_type;
} wifi_saved_settings;

int _get_wifi_name_from_lease_info(const char *mac, char **name_buf);
mobile_ap_error_code_e _enable_wifi_tethering(Tethering *obj, gchar *ssid,
	gchar *passphrase, gchar* mode, gint channel, int hide_mode, int mac_filter, softap_security_type_e security_type);
mobile_ap_error_code_e _disable_wifi_tethering(Tethering *obj);
gboolean _is_trying_wifi_operation(void);
mobile_ap_error_code_e _reload_softap_settings(Tethering *obj,
		gchar *ssid, gchar *key, gchar* mode, gint channel, gint hide_mode, gint mac_filter, gint security_type);
mobile_ap_error_code_e _reload_softap_settings_for_ap(Tethering *obj,
	gchar *ssid, gchar *key, gint hide_mode, gint security_type);

/* Dbus method */
mobile_ap_error_code_e _enable_wifi_ap(Tethering *obj, gchar *ssid,
		gchar *passphrase, int hide_mode,
                softap_security_type_e security_type);
mobile_ap_error_code_e _disable_wifi_ap(Tethering *obj);
gboolean tethering_enable_wifi_tethering(Tethering *obj,
		GDBusMethodInvocation *context, gchar *ssid,
		gchar *key, gchar* mode, gint channel, gint visibility, gint mac_filter, gint security_type);

softap_settings_t  *_get_softap_settings();

gboolean tethering_disable_wifi_tethering(Tethering *obj,
		GDBusMethodInvocation *context);

gboolean tethering_reload_wifi_settings(Tethering *obj,
		GDBusMethodInvocation *context,
		gchar *ssid, gchar *key, gchar* mode, gint channel, gint visibility, gint mac_filter, gint security_type);

gboolean tethering_reload_wifi_ap_settings(Tethering *obj,
				GDBusMethodInvocation *context, gchar *ssid, gchar *key,
				gint hide_mode, gint security);

gboolean tethering_enable_wifi_ap(Tethering *obj, GDBusMethodInvocation *context,
		gchar *ssid, gchar *key, gint hide_mode, gint security_type);

gboolean tethering_disable_wifi_ap(Tethering *obj,
		GDBusMethodInvocation *context);

gboolean tethering_get_wifi_tethering_passphrase(Tethering *obj,
		GDBusMethodInvocation *context);

gboolean tethering_set_wifi_tethering_passphrase(Tethering *obj,
		GDBusMethodInvocation *context, gchar *passphrase);

gboolean tethering_enable_dhcp(Tethering *obj,
		GDBusMethodInvocation *context, gboolean enable);

gboolean tethering_dhcp_range(Tethering *obj,
		GDBusMethodInvocation *context, gchar *rangestart, gchar *rangestop);

/* Dbus method for softap APIs */
gboolean softap_enable(Softap *obj, GDBusMethodInvocation *context,
		gchar *ssid, gchar *key, gint hide_mode, gint security_type);

gboolean softap_disable(Softap *obj,
		GDBusMethodInvocation *context);

gboolean softap_reload_settings(Softap *obj, GDBusMethodInvocation *context,
		gchar *ssid, char *key, gint visibility, gint security_type);

#endif /* __MOBILEAP_WIFI_H__ */
