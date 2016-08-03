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

#include <glib.h>
#include <dbus/dbus.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wifi.h>
#include <wifi-direct.h>
#include <ckmc/ckmc-manager.h>

#include "mobileap_softap.h"
#include "mobileap_common.h"
#include "mobileap_wifi.h"
#include "mobileap_handler.h"
#include "mobileap_notification.h"

#define WIFI_RECOVERY_GUARD_TIME	1000	/* ms */
#define MOBILE_AP_WIFI_KEY_MIN_LEN	8	/**< Minimum length of wifi key */
#define MOBILE_AP_WIFI_KEY_MAX_LEN	64	/**< Maximum length of wifi key */

#define MOBILE_AP_WIFI_PASSPHRASE_STORE_KEY "tethering_wifi_passphrase"

static mobile_ap_error_code_e __update_softap_settings(softap_settings_t *st,
	gchar *ssid, gchar *passphrase, gchar* mode, gint channel, int hide_mode, int mac_filter, int max_sta, softap_security_type_e security_type);
static mobile_ap_error_code_e __get_passphrase(char *passphrase,
	unsigned int passphrase_size, unsigned int *passphrase_len);
static mobile_ap_error_code_e __set_passphrase(const char *passphrase, const unsigned int size);
static char *__get_key_manager_alias(const char* name);
static int __turn_off_wifi(Tethering *obj);
static unsigned int __generate_initial_passphrase(char *passphrase, unsigned int size);

static GDBusMethodInvocation *g_context = NULL;
static guint wifi_recovery_timeout_id = 0;
static gboolean prev_wifi_on = FALSE;
static wifi_saved_settings wifi_settings = {0, 0, 0,  NULL, NULL, NULL, 0};
static softap_settings_t obj_softap_settings = {0, "", "", "", "", 0, 0, 0};

softap_settings_t *_get_softap_settings()
{
	return &obj_softap_settings;
}
static void _wifi_direct_state_cb(int error_code, wifi_direct_device_state_e state, void *user_data)
{
	bool wifi_state = false;

	DBG("+\n");

	if (user_data == NULL) {
		ERR("The param is NULL\n");
		return;
	}

	Tethering *obj = (Tethering *)user_data;
	int ret = 0;

	if (state != WIFI_DIRECT_DEVICE_STATE_DEACTIVATED) {
		ERR("Unknown state : %d\n", state);
		return;
	}

	wifi_direct_unset_device_state_changed_cb();
	wifi_direct_deinitialize();

	if (error_code != 0) {
		ERR("wifi_direct_deactivate fail in cb : %d\n", error_code);
		ret = MOBILE_AP_ERROR_INTERNAL;
		goto DONE;
	}
	DBG("Wi-Fi direct is turned off\n");

	wifi_is_activated(&wifi_state);
	if (wifi_state) {
		DBG("Wi-Fi is turned on. Turn off Wi-Fi");
		if (__turn_off_wifi(obj) != MOBILE_AP_ERROR_NONE) {
			ERR("_turn_off_wifi is failed\n");
			ret = MOBILE_AP_ERROR_INTERNAL;
			goto DONE;
		}
		return;
	}

	ret = _enable_wifi_tethering(obj, wifi_settings.ssid, wifi_settings.key,
			wifi_settings.mode, wifi_settings.channel, wifi_settings.hide_mode, wifi_settings.mac_filter, wifi_settings.max_sta, wifi_settings.security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_wifi_tethering is failed\n");
	} else {
		tethering_emit_wifi_on(obj);
		_create_tethering_active_noti();
	}

DONE:
	tethering_complete_enable_wifi_tethering(obj, g_context, ret);
	g_context = NULL;

	g_free(wifi_settings.ssid);
	g_free(wifi_settings.key);
	g_free(wifi_settings.mode);
	memset(&wifi_settings, 0, sizeof(wifi_settings));

	DBG("-\n");
	return;
}

static void __wifi_activated_cb(wifi_error_e result, void *user_data)
{
	DBG("Wi-Fi on is done\n");

	return;
}

static void __wifi_deactivated_cb(wifi_error_e result, void *user_data)
{
	DBG("+\n");

	if (user_data == NULL) {
		ERR("The param is NULL\n");
		return;
	}

	Tethering *obj = (Tethering *)user_data;
	int ret;

	if (result != WIFI_ERROR_NONE) {
		ERR("__wifi_deactivated_cb error : %d\n", result);
		ret = MOBILE_AP_ERROR_INTERNAL;
		goto DONE;
	}

	DBG("Wi-Fi is turned off\n");

	ret = _enable_wifi_tethering(obj, wifi_settings.ssid, wifi_settings.key,
			wifi_settings.mode, wifi_settings.channel, wifi_settings.hide_mode, wifi_settings.mac_filter, wifi_settings.max_sta, wifi_settings.security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_wifi_tethering is failed\n");
	} else {
		prev_wifi_on = TRUE;
		tethering_emit_wifi_on(obj);
		_create_tethering_active_noti();
	}

DONE:
	tethering_complete_enable_wifi_tethering(obj, g_context, ret);

	g_context = NULL;

	g_free(wifi_settings.ssid);
	g_free(wifi_settings.key);
	g_free(wifi_settings.mode);
	memset(&wifi_settings, 0, sizeof(wifi_settings));

	DBG("-\n");
	return;
}

static int __turn_off_wifi(Tethering *obj)
{
	int ret;

	ret = wifi_deactivate(__wifi_deactivated_cb, (void *)obj);
	if (ret != WIFI_ERROR_NONE) {
		ERR("wifi_deactivate() is failed : %d\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

static gboolean __turn_on_wifi_timeout_cb(gpointer user_data)
{
	int ret;
	guint idle_id;

	wifi_recovery_timeout_id = 0;

	ret = wifi_activate(__wifi_activated_cb, NULL);
	if (ret != WIFI_ERROR_NONE)
		ERR("wifi_activate() is failed : %d\n", ret);

	idle_id = g_idle_add(_terminate_mobileap_agent, NULL);
	if (idle_id == 0)
		ERR("g_idle_add is failed\n");

	return FALSE;
}

static int __turn_on_wifi(void)
{
	if (wifi_recovery_timeout_id > 0) {
		g_source_remove(wifi_recovery_timeout_id);
		wifi_recovery_timeout_id = 0;
	}

	wifi_recovery_timeout_id = g_timeout_add(WIFI_RECOVERY_GUARD_TIME,
			__turn_on_wifi_timeout_cb, NULL);
	if (wifi_recovery_timeout_id == 0) {
		ERR("g_timeout_add is failed\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

static gboolean __is_wifi_direct_on(void)
{
	int wifi_direct_state = 0;
	int ret;

	ret = vconf_get_int(VCONFKEY_WIFI_DIRECT_STATE, &wifi_direct_state);
	if (ret < 0) {
		ERR("vconf_get_int() is failed : %d\n", ret);
		return FALSE;
	}

	return wifi_direct_state != 0 ? TRUE : FALSE;
}

static int __turn_off_wifi_direct(Tethering *obj)
{
	int ret;

	ret = wifi_direct_initialize();
	if (ret < 0) {
		ERR("wifi_direct_initialize() is failed : %d\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = wifi_direct_set_device_state_changed_cb(_wifi_direct_state_cb, (void *)obj);
	if (ret < 0) {
		ERR("wifi_direct_set_device_state_changed_cb() is failed : %d\n", ret);
		ret = wifi_direct_deinitialize();
		DBG("wifi_direct_deinitialize() ret : %d\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = wifi_direct_deactivate();
	if (ret < 0) {
		ERR("wifi_direct_deactivate() is failed : %d\n", ret);
		ret = wifi_direct_unset_device_state_changed_cb();
		DBG("wifi_direct_unset_device_state_changed_cb() ret : %d\n", ret);
		ret = wifi_direct_deinitialize();
		DBG("wifi_direct_deinitialize() ret : %d\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

static mobile_ap_error_code_e __update_softap_settings(softap_settings_t *st,
	gchar *ssid, gchar *passphrase, gchar* mode, gint channel, int hide_mode, int mac_filter, int max_sta, softap_security_type_e security_type)
{
	if (st == NULL) {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	g_strlcpy(st->ssid, ssid, sizeof(st->ssid));

	if (security_type == SOFTAP_SECURITY_TYPE_WPA2_PSK) {
		g_strlcpy(st->security_type, SOFTAP_SECURITY_TYPE_WPA2_PSK_STR,
			sizeof(st->security_type));
		g_strlcpy(st->key, passphrase, sizeof(st->key));
	} else if (security_type == SOFTAP_SECURITY_TYPE_OPEN) {
		g_strlcpy(st->security_type, SOFTAP_SECURITY_TYPE_OPEN_STR,
			sizeof(st->security_type));
		g_strlcpy(st->key, "00000000", sizeof(st->key));
	} else if (security_type == SOFTAP_SECURITY_TYPE_WPS) {
		g_strlcpy(st->security_type, SOFTAP_SECURITY_TYPE_WPS_STR,
				sizeof(st->security_type));
		g_strlcpy(st->key, passphrase, sizeof(st->key));
	} else {
		ERR("Unknown security type\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	if (mode != NULL)
		g_strlcpy(st->mode, mode, sizeof(st->mode));

	st->channel = channel;
	st->hide_mode = hide_mode;
	st->mac_filter = mac_filter;
	st->max_sta = max_sta;

	SDBG("ssid : %s security type : %s hide mode : %d mac filter : %d max_sta: %d hw_mode: %s \n",
			st->ssid, st->security_type, st->hide_mode, st->mac_filter, st->max_sta, st->mode);

	return MOBILE_AP_ERROR_NONE;
}

static gboolean __is_equal_softap_settings(softap_settings_t *a, softap_settings_t *b)
{
	if (a->hide_mode != b->hide_mode)
		return FALSE;

	if (a->mac_filter != b->mac_filter)
		return FALSE;

	if (a->max_sta != b->max_sta)
		return FALSE;

	if (strcmp(a->ssid, b->ssid) != 0)
		return FALSE;

	if (strcmp(a->key, b->key) != 0)
		return FALSE;

	if (strcmp(a->mode, b->mode) != 0)
		return FALSE;

	if (a->channel != b->channel)
		return FALSE;

	if (strcmp(a->security_type, b->security_type) != 0)
		return FALSE;

	return TRUE;
}

mobile_ap_error_code_e _reload_softap_settings(Tethering *obj,
		gchar *ssid, gchar *key, gchar* mode, gint channel, gint hide_mode, gint mac_filter, gint max_sta, gint security_type)
{
	gboolean backup_prev_wifi_on = prev_wifi_on;
	mobile_ap_error_code_e ret;
	softap_settings_t *old_settings = _get_softap_settings();
	softap_settings_t new_settings;

	if (obj == NULL || ssid == NULL || !strlen(ssid)) {
		ERR("invalid parameters\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_WIFI))
		return MOBILE_AP_ERROR_NONE;

	ret = __update_softap_settings(&new_settings, ssid, key, mode, channel, hide_mode,
			mac_filter, max_sta, (softap_security_type_e)security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("__update_softap_settings is failed\n");
		return ret;
	}

	if (__is_equal_softap_settings(&new_settings, old_settings) == TRUE) {
		DBG("No need to reload settings\n");
		return MOBILE_AP_ERROR_NONE;
	}

	prev_wifi_on = FALSE;
	ret = _disable_wifi_tethering(obj);

	prev_wifi_on = backup_prev_wifi_on;
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_disable_wifi_tethering is failed : %d\n", ret);
		return ret;
	}

	ret = _enable_wifi_tethering(obj, ssid, key, mode, channel, hide_mode,
			mac_filter, max_sta, (softap_security_type_e)security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_wifi_tethering is failed : %d\n", ret);
		return ret;
	}
	tethering_emit_wifi_on(obj);
	_create_tethering_active_noti();

	return MOBILE_AP_ERROR_NONE;
}

mobile_ap_error_code_e _reload_softap_settings_for_ap(Tethering *obj,
	gchar *ssid, gchar *key, gint hide_mode, gint security_type)
{
	gboolean backup_prev_wifi_on = prev_wifi_on;
	mobile_ap_error_code_e ret;
	softap_settings_t *old_settings = _get_softap_settings();
	softap_settings_t new_settings;

	if (obj == NULL || ssid == NULL || !strlen(ssid)) {
		ERR("invalid parameters\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	ret = __update_softap_settings(&new_settings, ssid, key, NULL, MOBILE_AP_WIFI_CHANNEL, hide_mode,
			false, MOBILE_AP_MAX_WIFI_STA, (softap_security_type_e)security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("__update_softap_settings is failed\n");
		return ret;
	}

	if (__is_equal_softap_settings(&new_settings, old_settings) == TRUE) {
		DBG("No need to reload settings\n");
		return MOBILE_AP_ERROR_NONE;
	}

	prev_wifi_on = FALSE;

	ret = _disable_wifi_ap(obj);
	prev_wifi_on = backup_prev_wifi_on;
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_disable_wifi_ap is failed : %d\n", ret);
		return ret;
	}

	ret = _enable_wifi_ap(obj, ssid, key, hide_mode,
			(softap_security_type_e)security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_wifi_ap is failed : %d\n", ret);
		return ret;
	}

	return MOBILE_AP_ERROR_NONE;
}

int _register_app_for_wifi_passphrase(const char *pkg_id)
{
	if (pkg_id == NULL) {
		ERR("Invalid parameter");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	char *alias = NULL;

	alias = __get_key_manager_alias(MOBILE_AP_WIFI_PASSPHRASE_STORE_KEY);
	if (ckmc_set_permission(alias, pkg_id, CKMC_PERMISSION_REMOVE) != CKMC_ERROR_NONE) {
		ERR("Fail to set permission for Wi-Fi passphrase (%d)");

		if (alias)
			free(alias);

		return MOBILE_AP_ERROR_NOT_PERMITTED;
	}

	if (alias)
		free(alias);

	return MOBILE_AP_ERROR_NONE;

}

int _get_wifi_name_from_lease_info(const char *mac, char **name_buf)
{
	if (mac == NULL || name_buf == NULL)
		return MOBILE_AP_ERROR_INVALID_PARAM;

	GIOChannel *io = NULL;
	char *line = NULL;
	char *device_name = MOBILE_AP_NAME_UNKNOWN;
	char ip_addr[MOBILE_AP_STR_INFO_LEN] = {0, };
	char mac_addr[MOBILE_AP_STR_INFO_LEN] = {0, };
	char name[MOBILE_AP_STR_HOSTNAME_LEN] = {0, };
	char expire[MOBILE_AP_STR_INFO_LEN] = {0, };
	char extra[MOBILE_AP_STR_INFO_LEN] = {0, };

	io = g_io_channel_new_file(DNSMASQ_LEASES_FILE, "r", NULL);
	if (io == NULL)
		return MOBILE_AP_ERROR_RESOURCE;

	while (g_io_channel_read_line(io, &line, NULL, NULL, NULL) ==
			G_IO_STATUS_NORMAL) {
		sscanf(line, "%19s %19s %19s %19s %19s",
				expire, mac_addr, ip_addr, name, extra);
		g_free(line);

		if (g_ascii_strcasecmp(mac_addr, mac) == 0) {
			if (g_strcmp0(name, "*") != 0)
				device_name = name;
			break;
		}
	}
	g_io_channel_unref(io);

	*name_buf = g_strdup(device_name);

	return MOBILE_AP_ERROR_NONE;
}

mobile_ap_error_code_e _enable_wifi_tethering(Tethering *obj, gchar *ssid,
	gchar *passphrase, gchar* mode, gint channel, int hide_mode, int mac_filter, int max_sta, softap_security_type_e security_type)
{
	mobile_ap_error_code_e ret;

	if (obj == NULL || ssid == NULL || !strlen(ssid)) {
		ERR("invalid parameters\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (security_type == SOFTAP_SECURITY_TYPE_WPA2_PSK && passphrase == NULL) {
		ERR("passphrase is null\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP)) {
		ERR("Wi-Fi AP is already enabled\n");
		ret = MOBILE_AP_ERROR_RESOURCE;
		return ret;
	}

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI)) {
		ERR("Wi-Fi tethering is already enabled\n");
		ret = MOBILE_AP_ERROR_ALREADY_ENABLED;
		return ret;
	}

	/* Update global state */
	if (!_mobileap_set_state(MOBILE_AP_STATE_WIFI)) {
		ret = MOBILE_AP_ERROR_RESOURCE;
		return ret;
	}

	/* Update Wi-Fi hotspot data to global settings pointer */
	ret = __update_softap_settings(&obj_softap_settings, ssid, passphrase,
			mode, channel, hide_mode, mac_filter, max_sta, security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI);
		return ret;
	}

	if (vconf_set_str(VCONFKEY_MOBILE_HOTSPOT_SSID,
			obj_softap_settings.ssid) < 0) {
		ERR("vconf_set_str is failed\n");
	}

	/* Initialize tethering */
	_block_device_sleep();
	ret = _init_tethering();
	if (ret != MOBILE_AP_ERROR_NONE) {
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI);
		goto DONE;
	}

	/* Upload driver */
	ret = _mh_core_enable_softap(MOBILE_AP_TYPE_WIFI,
			obj_softap_settings.ssid,
			obj_softap_settings.security_type,
			obj_softap_settings.key,
			obj_softap_settings.mode,
			obj_softap_settings.channel,
			obj_softap_settings.hide_mode,
			obj_softap_settings.mac_filter,
			obj_softap_settings.max_sta);
	if (ret != MOBILE_AP_ERROR_NONE) {
		_deinit_tethering();
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI);
		goto DONE;
	}
	_delete_timeout_noti();

	_init_timeout_cb(MOBILE_AP_TYPE_WIFI, (void *)obj);
	_start_timeout_cb(MOBILE_AP_TYPE_WIFI, time(NULL) + TETHERING_CONN_TIMEOUT);

	_add_interface_routing(WIFI_IF, IP_ADDRESS_SOFTAP);
	_add_routing_rule(WIFI_IF);

DONE:
	_unblock_device_sleep();
	return ret;
}

mobile_ap_error_code_e _enable_wifi_ap(Tethering *obj,
					gchar *ssid, gchar *passphrase, int hide_mode,
					softap_security_type_e security_type)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	if (obj == NULL || ssid == NULL || !strlen(ssid)) {
		ERR("invalid parameters\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (security_type == SOFTAP_SECURITY_TYPE_WPA2_PSK &&
		(passphrase == NULL || strlen(passphrase) >= MOBILE_AP_WIFI_KEY_MAX_LEN)) {
		ERR("hex key length is not correct\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI | MOBILE_AP_STATE_BT
			| MOBILE_AP_STATE_USB)) {
		ERR("Tethering is already enabled\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP)) {
		ERR("Wi-Fi AP is already enabled\n");
		return MOBILE_AP_ERROR_ALREADY_ENABLED;
	}

	if (!_mobileap_set_state(MOBILE_AP_STATE_WIFI_AP))
		return MOBILE_AP_ERROR_RESOURCE;

	ret = __update_softap_settings(&obj_softap_settings, ssid, passphrase,
			NULL, MOBILE_AP_WIFI_CHANNEL, hide_mode, false, MOBILE_AP_MAX_WIFI_STA, security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI_AP);
		return ret;
	}

	_block_device_sleep();

	if (_init_tethering() != MOBILE_AP_ERROR_NONE) {
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI_AP);
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto DONE;
	}

	/* Upload driver */
	ret = _mh_core_enable_softap(MOBILE_AP_TYPE_WIFI_AP,
			obj_softap_settings.ssid,
			obj_softap_settings.security_type,
			obj_softap_settings.key,
			NULL,
			obj_softap_settings.channel,
			obj_softap_settings.hide_mode,
			obj_softap_settings.mac_filter,
			obj_softap_settings.max_sta);
	if (ret != MOBILE_AP_ERROR_NONE) {
		_deinit_tethering();
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI_AP);
		goto DONE;
	}

	_delete_timeout_noti();
	_init_timeout_cb(MOBILE_AP_TYPE_WIFI_AP, (void *)obj);
	_start_timeout_cb(MOBILE_AP_TYPE_WIFI_AP, time(NULL) + WIFI_AP_CONN_TIMEOUT);
	_add_interface_routing(WIFI_IF, IP_ADDRESS_SOFTAP);
	_add_routing_rule(WIFI_IF);

DONE:
	_unblock_device_sleep();
	return ret;
}

mobile_ap_error_code_e _disable_wifi_tethering(Tethering *obj)
{
	int ret;
	int state;
	mobile_ap_type_e type;

	type = MOBILE_AP_TYPE_WIFI;
	state = MOBILE_AP_STATE_WIFI;

	if (!_mobileap_is_enabled(state)) {
		ERR("Wi-Fi tethering ap has not been activated\n");
		ret = MOBILE_AP_ERROR_NOT_ENABLED;
		return ret;
	}

	_block_device_sleep();
	_del_routing_rule(WIFI_IF);
	_del_interface_routing(WIFI_IF, IP_ADDRESS_SOFTAP);
	_flush_ip_address(WIFI_IF);
	_deinit_timeout_cb(type);

	if (_remove_station_info_all(type) != MOBILE_AP_ERROR_NONE)
		ERR("_remove_station_info_all is failed. Ignore it.\n");

	ret = _mh_core_disable_softap();
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_mh_core_disable_softap is failed : %d\n", ret);
		goto DONE;
	}

	_deinit_tethering();
	_mobileap_clear_state(state);

	if (prev_wifi_on == TRUE) {
		DBG("Previous Wi-Fi was turned on. Recover it\n");
		if (__turn_on_wifi() != MOBILE_AP_ERROR_NONE)
			ERR("__turn_on_wifi() is failed\n");
		prev_wifi_on = FALSE;
	}
	DBG("_disable_wifi_tethering is done\n");

DONE:
	_unblock_device_sleep();
	return ret;
}

mobile_ap_error_code_e _disable_wifi_ap(Tethering *obj)
{
	int ret;
	int state;
	mobile_ap_type_e type;

	type = MOBILE_AP_TYPE_WIFI_AP;
	state = MOBILE_AP_STATE_WIFI_AP;

	if (!_mobileap_is_enabled(state)) {
		ERR("Wi-Fi ap tethering has not been activated\n");
		ret = MOBILE_AP_ERROR_NOT_ENABLED;
		return ret;
	}

	_block_device_sleep();
	_del_routing_rule(WIFI_IF);
	_del_interface_routing(WIFI_IF, IP_ADDRESS_SOFTAP);
	_flush_ip_address(WIFI_IF);
	_deinit_timeout_cb(type);

	if (_remove_station_info_all(type) != MOBILE_AP_ERROR_NONE)
		ERR("_remove_station_info_all is failed. Ignore it.\n");

	ret = _mh_core_disable_softap();
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_mh_core_disable_softap is failed : %d\n", ret);
		goto DONE;
	}

	_deinit_tethering();
	_mobileap_clear_state(state);

	DBG("_disable_wifi_ap is done\n");

DONE:
	_unblock_device_sleep();
	return ret;
}

mobile_ap_error_code_e _enable_soft_ap(Softap *obj,
					gchar *ssid, gchar *passphrase, int hide_mode,
					softap_security_type_e security_type)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	if (obj == NULL || ssid == NULL || !strlen(ssid)) {
		ERR("invalid parameters\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (security_type == SOFTAP_SECURITY_TYPE_WPA2_PSK &&
		(passphrase == NULL || strlen(passphrase) >= MOBILE_AP_WIFI_KEY_MAX_LEN)) {
		ERR("hex key length is not correct\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI | MOBILE_AP_STATE_BT
			| MOBILE_AP_STATE_USB)) {
		ERR("Tethering is already enabled\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP)) {
		ERR("Wi-Fi AP is already enabled\n");
		return MOBILE_AP_ERROR_ALREADY_ENABLED;
	}

	if (!_mobileap_set_state(MOBILE_AP_STATE_WIFI_AP))
		return MOBILE_AP_ERROR_RESOURCE;

	ret = __update_softap_settings(&obj_softap_settings, ssid, passphrase,
			NULL, MOBILE_AP_WIFI_CHANNEL, hide_mode, false, MOBILE_AP_MAX_WIFI_STA, security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI_AP);
		return ret;
	}

	if (vconf_set_str(VCONFKEY_SOFTAP_SSID, obj_softap_settings.ssid) < 0)
		ERR("vconf_set_str is failed");

	if (vconf_set_str(VCONFKEY_SOFTAP_KEY, obj_softap_settings.key) < 0)
		ERR("vconf_set_str is failed");

	_block_device_sleep();

	if (_init_tethering() != MOBILE_AP_ERROR_NONE) {
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI_AP);
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto DONE;
	}

	/* Upload driver */
	ret = _mh_core_enable_softap(MOBILE_AP_TYPE_WIFI_AP,
			obj_softap_settings.ssid,
			obj_softap_settings.security_type,
			obj_softap_settings.key,
			NULL,
			obj_softap_settings.channel,
			obj_softap_settings.hide_mode,
			obj_softap_settings.mac_filter,
			MOBILE_AP_MAX_WIFI_STA);
	if (ret != MOBILE_AP_ERROR_NONE) {
		_deinit_tethering();
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI_AP);
		goto DONE;
	}

	_delete_timeout_noti();
	_init_timeout_cb(MOBILE_AP_TYPE_WIFI_AP, (void *)obj);
	_start_timeout_cb(MOBILE_AP_TYPE_WIFI_AP, time(NULL) + WIFI_AP_CONN_TIMEOUT);
	_add_interface_routing(WIFI_IF, IP_ADDRESS_SOFTAP);
	_add_routing_rule(WIFI_IF);

DONE:
	_unblock_device_sleep();
	return ret;
}

mobile_ap_error_code_e _disable_soft_ap(Softap *obj)
{
	int ret;
	int state;
	mobile_ap_type_e type;

	type = MOBILE_AP_TYPE_WIFI_AP;
	state = MOBILE_AP_STATE_WIFI_AP;

	if (!_mobileap_is_enabled(state)) {
		ERR("Wi-Fi ap tethering has not been activated\n");
		ret = MOBILE_AP_ERROR_NOT_ENABLED;
		return ret;
	}

	_block_device_sleep();
	_del_routing_rule(WIFI_IF);
	_del_interface_routing(WIFI_IF, IP_ADDRESS_SOFTAP);
	_flush_ip_address(WIFI_IF);
	_deinit_timeout_cb(type);

	if (_remove_station_info_all(type) != MOBILE_AP_ERROR_NONE)
		ERR("_remove_station_info_all is failed. Ignore it.\n");

	ret = _mh_core_disable_softap();
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_mh_core_disable_softap is failed : %d\n", ret);
		goto DONE;
	}

	_deinit_tethering();
	_mobileap_clear_state(state);

	DBG("_disable_wifi_ap is done\n");

DONE:
	_unblock_device_sleep();
	return ret;
}

mobile_ap_error_code_e _reload_softap_settings_for_softap(Softap *obj,
		gchar *ssid, gchar *key, gint hide_mode, gint security_type)
{
	gboolean backup_prev_wifi_on = prev_wifi_on;
	mobile_ap_error_code_e ret;
	softap_settings_t *old_settings = _get_softap_settings();
	softap_settings_t new_settings;

	if (obj == NULL || ssid == NULL || !strlen(ssid)) {
		ERR("invalid parameters\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP))
		return MOBILE_AP_ERROR_NONE;

	ret = __update_softap_settings(&new_settings, ssid, key, NULL, MOBILE_AP_WIFI_CHANNEL, hide_mode,
			false, MOBILE_AP_MAX_WIFI_STA, (softap_security_type_e)security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("__update_softap_settings is failed\n");
		return ret;
	}

	if (__is_equal_softap_settings(&new_settings, old_settings) == TRUE) {
		DBG("No need to reload settings\n");
		return MOBILE_AP_ERROR_NONE;
	}

	prev_wifi_on = FALSE;
	ret = _disable_soft_ap(obj);

	prev_wifi_on = backup_prev_wifi_on;
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_disable_softap is failed : %d\n", ret);
		return ret;
	}

	ret = _enable_soft_ap(obj, ssid, key, !hide_mode,
			(softap_security_type_e)security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_softap is failed : %d\n", ret);
		return ret;
	}
	softap_emit_soft_ap_on(obj);

	return MOBILE_AP_ERROR_NONE;
}

gboolean tethering_enable_wifi_tethering(Tethering *obj,
		GDBusMethodInvocation *context, gchar *ssid,
		gchar *key, gchar *mode, gint channel, gint visibility, gint mac_filter, gint max_sta, gint security_type)
{
	DBG("+\n");
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	gboolean ret_val = FALSE;
	bool wifi_state = false;
	g_assert(obj != NULL);
	g_assert(context != NULL);

	if (g_context) {
		DBG("It is turnning on\n");
		tethering_complete_enable_wifi_tethering(obj, g_context,
				MOBILE_AP_ERROR_IN_PROGRESS);
		return FALSE;
	}
	g_context = context;

	if (!_is_allowed(MOBILE_AP_TYPE_WIFI)) {
		DBG("DPM policy restricts Wi-Fi tethering\n");
		ret = MOBILE_AP_ERROR_NOT_PERMITTED;
		_create_security_restriction_noti(MOBILE_AP_TYPE_WIFI);
		goto DONE;
	}

	wifi_settings.ssid = g_strdup(ssid);
	if (security_type == SOFTAP_SECURITY_TYPE_WPA2_PSK) {
		wifi_settings.key = g_strdup(key);
		wifi_settings.security_type = SOFTAP_SECURITY_TYPE_WPA2_PSK;
	} else {
		wifi_settings.security_type = SOFTAP_SECURITY_TYPE_OPEN;
	}
	wifi_settings.hide_mode = (!visibility);

	if (mode != NULL)
		wifi_settings.mode = g_strdup(mode);

	wifi_settings.channel = channel;
	wifi_settings.max_sta = max_sta;

	if (wifi_recovery_timeout_id) {
		DBG("Wi-Fi recovery is cancelled\n");
		g_source_remove(wifi_recovery_timeout_id);
		wifi_recovery_timeout_id = 0;
		prev_wifi_on = TRUE;
	}

	if (__is_wifi_direct_on() == TRUE) {
		DBG("Wi-Fi and Wi-Fi direct are turned on\n");
		if (__turn_off_wifi_direct(obj) != MOBILE_AP_ERROR_NONE) {
			ERR("_turn_off_wifi_direct is failed\n");
			ret = MOBILE_AP_ERROR_INTERNAL;
			goto DONE;
		}

		return TRUE;
	}

	wifi_is_activated(&wifi_state);
	if (wifi_state == true) {
		DBG("Wi-Fi is turned on\n");
		if (__turn_off_wifi(obj) != MOBILE_AP_ERROR_NONE) {
			ERR("_turn_off_wifi is failed\n");
			ret = MOBILE_AP_ERROR_INTERNAL;
			goto DONE;
		}

		return TRUE;
	}

	ret = _enable_wifi_tethering(obj, ssid, key, mode, channel, !visibility,
			mac_filter, max_sta, (softap_security_type_e)security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_wifi_tethering is failed\n");
	} else {
		tethering_emit_wifi_on(obj);
		_create_tethering_active_noti();
		ret_val = TRUE;
	}

DONE:
	tethering_complete_enable_wifi_tethering(obj, g_context, ret);
	g_context = NULL;

	g_free(wifi_settings.ssid);
	g_free(wifi_settings.key);
	g_free(wifi_settings.mode);
	memset(&wifi_settings, 0, sizeof(wifi_settings));

	return ret_val;
}

gboolean tethering_disable_wifi_tethering(Tethering *obj,
		GDBusMethodInvocation *context)
{
	int ret = MOBILE_AP_ERROR_NONE;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = _disable_wifi_tethering(obj);

	tethering_emit_wifi_off(obj, NULL);
	tethering_complete_disable_wifi_tethering(obj, context,
			MOBILE_AP_DISABLE_WIFI_TETHERING_CFM, ret);


	if (ret != MOBILE_AP_ERROR_NONE)
		return FALSE;

	return TRUE;
}

gboolean tethering_enable_wifi_ap(Tethering *obj, GDBusMethodInvocation *context,
		gchar *ssid, gchar *key, gint visibility, gint security_type)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	gboolean ret_val = FALSE;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	if (wifi_recovery_timeout_id) {
		DBG("Wi-Fi recovery is cancelled\n");
		g_source_remove(wifi_recovery_timeout_id);
		wifi_recovery_timeout_id = 0;
	}

	ret = _enable_wifi_ap(obj, ssid, key, !visibility, (softap_security_type_e)security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_wifi_tethering is failed\n");
	} else {
		tethering_emit_wifi_ap_on(obj);
		ret_val = TRUE;
	}
	tethering_complete_enable_wifi_ap(obj, context, ret);
	return ret_val;
}

gboolean tethering_disable_wifi_ap(Tethering *obj,
		GDBusMethodInvocation *context)
{
	int ret = MOBILE_AP_ERROR_NONE;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = _disable_wifi_ap(obj);
	tethering_emit_wifi_ap_off(obj, NULL);
	tethering_complete_disable_wifi_ap(obj, g_context,
			MOBILE_AP_ENABLE_WIFI_AP_CFM, ret);

	if (ret != MOBILE_AP_ERROR_NONE)
		return FALSE;

	return TRUE;
}

gboolean tethering_reload_wifi_settings(Tethering *obj,
		GDBusMethodInvocation *context, gchar *ssid,
		gchar *key, gchar *mode, gint channel, gint visibility, gint mac_filter, gint max_sta, gint security_type)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	gboolean ret_val = TRUE;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = _reload_softap_settings(obj, ssid, key, mode, channel, !visibility, mac_filter, max_sta, security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_reload_softap_settings is failed\n");
		ret_val = FALSE;
	}

	tethering_complete_reload_wifi_settings(obj, context, ret);

	return ret_val;
}

gboolean tethering_set_mtu(Tethering *obj,
		GDBusMethodInvocation *context, gint mtu)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	ret = _mh_core_set_mtu(mtu);

	tethering_complete_set_mtu(obj, context, ret);

	return TRUE;
}

gboolean tethering_change_mac(Tethering *obj,
		GDBusMethodInvocation *context, gchar *mac)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	ret = _mh_core_change_mac(mac);

	tethering_complete_change_mac(obj, context, ret);

	return TRUE;
}

gboolean tethering_enable_port_forwarding(Tethering *obj,
		GDBusMethodInvocation *context, gboolean enable)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	ret = _mh_core_enable_port_forwarding(enable);

	tethering_complete_enable_port_forwarding(obj, context, ret);
	return TRUE;
}

gboolean tethering_add_port_forwarding_rule(Tethering *obj, GDBusMethodInvocation *context,
		gchar *ifname, gchar *protocol, gchar *org_ip, gint org_port, gchar *final_ip, gint final_port)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	ret = _mh_core_add_port_forwarding_rule(ifname, protocol, org_ip, org_port, final_ip, final_port);

	tethering_complete_add_port_forwarding_rule(obj, context, ret);
	return TRUE;
}

gboolean tethering_reset_port_forwarding_rule(Tethering *obj,
		GDBusMethodInvocation *context)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	ret = _mh_core_reset_port_forwarding_rule();

	tethering_complete_reset_port_forwarding_rule(obj, context, ret);
	return TRUE;
}

gboolean tethering_enable_port_filtering(Tethering *obj,
		GDBusMethodInvocation *context, gboolean enable)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	ret = _mh_core_enable_port_filtering(enable);

	tethering_complete_enable_port_filtering(obj, context, ret);
	return TRUE;
}

gboolean tethering_add_port_filtering_rule(Tethering *obj,
		GDBusMethodInvocation *context, gint port, gchar *protocol, gboolean allow)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	ret = _mh_core_add_port_filtering_rule(port, protocol, allow);

	tethering_complete_add_port_filtering_rule(obj, context, ret);
	return TRUE;
}

gboolean tethering_add_custom_port_filtering_rule(Tethering *obj,
		GDBusMethodInvocation *context, gint port1, gint port2, gchar *protocol, gboolean allow)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	ret = _mh_core_add_custom_port_filtering_rule(port1, port2, protocol, allow);

	tethering_complete_add_custom_port_filtering_rule(obj, context, ret);
	return TRUE;
}

gboolean tethering_set_vpn_passthrough_rule(Tethering *obj,
		GDBusMethodInvocation *context, gint vpn_type, gboolean enable)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	ret = _mh_core_set_vpn_passthrough_rule(vpn_type, enable);

	tethering_complete_set_vpn_passthrough_rule(obj, context, ret);
	return TRUE;
}

gboolean tethering_reload_wifi_ap_settings(Tethering *obj,
		GDBusMethodInvocation *context, gchar *ssid,
	gchar *key, gint visibility, gint security)
{

	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	gboolean ret_val = TRUE;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = _reload_softap_settings_for_ap(obj, ssid, key, !visibility, security);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_reload_softap_settings_for_ap is failed\n");
		ret_val = FALSE;
	}

	tethering_complete_reload_wifi_ap_settings(obj, context, ret);
	return ret_val;
}

gboolean _is_trying_wifi_operation(void)
{
	return (g_context || wifi_recovery_timeout_id ? TRUE : FALSE);
}

static char *__get_key_manager_alias(const char* name)
{
	size_t alias_len = strlen(name) + strlen(ckmc_owner_id_system) + strlen(ckmc_owner_id_separator);
	char *ckm_alias = (char *)malloc(alias_len + 1);
	if (!ckm_alias) {
		ERR("Fail to allocate memory\n");
		return NULL;
	}

	memset(ckm_alias, 0, alias_len);
	strncat(ckm_alias, ckmc_owner_id_system, strlen(ckmc_owner_id_system));
	strncat(ckm_alias, ckmc_owner_id_separator, strlen(ckmc_owner_id_separator));
	strncat(ckm_alias, name, strlen(name));

	return ckm_alias;
}

static mobile_ap_error_code_e __set_passphrase(const char *passphrase, const unsigned int size)
{
	if (passphrase == NULL || size == 0)
		return MOBILE_AP_ERROR_INVALID_PARAM;

	int ret = -1;
	char *alias;
	ckmc_raw_buffer_s ckmc_buf;
	ckmc_policy_s ckmc_policy;

	ckmc_policy.password = NULL;
	ckmc_policy.extractable = true;

	ckmc_buf.data = (unsigned char *) passphrase;
	ckmc_buf.size = strlen(passphrase) + 1;

	alias = __get_key_manager_alias(MOBILE_AP_WIFI_PASSPHRASE_STORE_KEY);

	ret = ckmc_remove_data(alias);
	if (ret != CKMC_ERROR_NONE && ret != CKMC_ERROR_DB_ALIAS_UNKNOWN) {
		ERR("Fail to remove old data : %d", ret);
		if (alias)
			free(alias);

		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = ckmc_save_data(alias, ckmc_buf, ckmc_policy);
	if (ret != CKMC_ERROR_NONE) {
		ERR("Fail to save the passphrase : %d", ret);
		if (alias)
			free(alias);

		return MOBILE_AP_ERROR_INTERNAL;
	}

	if (alias)
		free(alias);

	return MOBILE_AP_ERROR_NONE;
}

static unsigned int __generate_initial_passphrase(char *passphrase, unsigned int size)
{
	if (passphrase == NULL || size == 0 || size < MOBILE_AP_WIFI_KEY_MIN_LEN + 1)
		return 0;

	guint32 rand_int = 0;
	int index = 0;

	for (index = 0; index < MOBILE_AP_WIFI_KEY_MIN_LEN; index++) {
		rand_int = g_random_int_range('a', 'z');
		passphrase[index] = rand_int;
	}

	passphrase[index] = '\0';
	return index;
}

static mobile_ap_error_code_e __get_passphrase(char *passphrase,
		unsigned int passphrase_size, unsigned int *passphrase_len)
{
	if (passphrase == NULL || passphrase_size == 0) {
		ERR("Invalid parameter\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	int ret = 0;
	char *alias = NULL;
	char *passwd = NULL;
	char tmp[MOBILE_AP_WIFI_KEY_MAX_LEN + 1] = {0, };
	ckmc_raw_buffer_s *ckmc_buf;

	alias = __get_key_manager_alias(MOBILE_AP_WIFI_PASSPHRASE_STORE_KEY);
	ret = ckmc_get_data(alias, passwd, &ckmc_buf);
	if (ret < 0) {
		DBG("Create new password\n");
		ret = __generate_initial_passphrase(tmp, sizeof(tmp));

		if (ret == 0) {
			ERR("generate_initial_passphrase failed : %d\n", *passphrase_len);
			if (alias)
				free(alias);

			return MOBILE_AP_ERROR_INTERNAL;
		} else {
			*passphrase_len = ret;
			g_strlcpy(passphrase, tmp, (*passphrase_len)+1);

			if (__set_passphrase(passphrase, *passphrase_len) != MOBILE_AP_ERROR_NONE) {
				DBG("set_passphrase is failed : %s, %d", passphrase, *passphrase_len);
				if (alias)
					free(alias);

				return MOBILE_AP_ERROR_INTERNAL;
			}
		}
	} else {
		*passphrase_len = ckmc_buf->size;
		g_strlcpy(passphrase, (char *)ckmc_buf->data, (*passphrase_len) + 1);
	}

	if (alias)
		free(alias);

	return MOBILE_AP_ERROR_NONE;
}

gboolean tethering_enable_dhcp(Tethering *obj,
		GDBusMethodInvocation *context, gboolean enable)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	if (enable)
		ret = _mh_core_execute_dhcp_server();
	else
		ret = _mh_core_terminate_dhcp_server();

	tethering_complete_enable_dhcp(obj, context, ret);

	return TRUE;
}

gboolean tethering_dhcp_range(Tethering *obj,
		GDBusMethodInvocation *context, gchar *rangestart, gchar *rangestop)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	ret = _mh_core_execute_dhcp_server_range(rangestart, rangestop);

	tethering_complete_dhcp_range(obj, context, ret);
	return TRUE;
}

gboolean tethering_get_wifi_tethering_passphrase(Tethering *obj,
		GDBusMethodInvocation *context)
{
	char passphrase_buf[MOBILE_AP_WIFI_KEY_MAX_LEN + 1] = {0, };
	unsigned int len = 0;
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	ret = __get_passphrase(passphrase_buf, sizeof(passphrase_buf), &len);
	if (ret != MOBILE_AP_ERROR_NONE) {
		tethering_complete_get_wifi_tethering_passphrase(obj, context, 0ULL, 0, ret);
		return false;
	}

	tethering_complete_get_wifi_tethering_passphrase(obj, context, passphrase_buf, len, ret);

	return true;
}

gboolean tethering_set_wifi_tethering_passphrase(Tethering *obj,
		GDBusMethodInvocation *context, gchar *passphrase)
{
	char old_passphrase[MOBILE_AP_WIFI_KEY_MAX_LEN + 1] = {0, };
	unsigned int old_len = 0;
	unsigned int passphrase_len = strlen(passphrase);
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	ret = __get_passphrase(old_passphrase, sizeof(old_passphrase), &old_len);
	if (ret == MOBILE_AP_ERROR_NONE && old_len == passphrase_len && !g_strcmp0(old_passphrase, passphrase)) {
		ret =  MOBILE_AP_ERROR_NONE;
		tethering_complete_set_wifi_tethering_passphrase(obj, context, ret);
		return true;
	}
	ret = __set_passphrase(passphrase, passphrase_len);
	tethering_complete_set_wifi_tethering_passphrase(obj, context, ret);

	return true;
}

gboolean softap_enable(Softap *obj, GDBusMethodInvocation *context,
		gchar *ssid, gchar *key, gint hide_mode, gint security_type)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	gboolean ret_val = FALSE;

	DBG("+");

	g_assert(obj != NULL);
	g_assert(context != NULL);

	if (wifi_recovery_timeout_id) {
		DBG("Wi-Fi recovery is cancelled\n");
		g_source_remove(wifi_recovery_timeout_id);
		wifi_recovery_timeout_id = 0;
	}

	ret = _enable_soft_ap(obj, ssid, key, !hide_mode,
			(softap_security_type_e)security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_wifi_tethering is failed\n");
	} else {
		softap_emit_soft_ap_on(obj);
		ret_val = TRUE;
	}
	softap_complete_enable(obj, context, ret);
	return ret_val;
}

gboolean softap_disable(Softap *obj,
		GDBusMethodInvocation *context)
{
	int ret = MOBILE_AP_ERROR_NONE;

	DBG("+");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = _disable_soft_ap(obj);
	softap_emit_soft_ap_off(obj, NULL);
	softap_complete_disable(obj, context, ret);

	if (ret != MOBILE_AP_ERROR_NONE)
		return FALSE;

	return TRUE;
}

gboolean softap_reload_settings(Softap *obj,
		GDBusMethodInvocation *context, gchar *ssid,
		gchar *key, gint visibility, gint security_type)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	gboolean ret_val = TRUE;

	DBG("+");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = _reload_softap_settings_for_softap(obj, ssid, key, !visibility, security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_reload_softap_settings is failed\n");
		ret_val = FALSE;
	}

	softap_complete_reload_settings(obj, context, ret);

	return ret_val;
}

gboolean softap_set_wps_pin(Softap *obj,
		GDBusMethodInvocation *context, gchar *wps_pin)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	ret = _mh_core_set_wps_pin(wps_pin);
	softap_complete_set_wps_pin(obj, context, ret);

	return TRUE;
}

gboolean softap_push_wps_button(Softap *obj, GDBusMethodInvocation *context)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	ret = _mh_core_push_wps_button();
	softap_complete_push_wps_button(obj, context, ret);

	return TRUE;

}
