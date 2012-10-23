/*
 * mobileap-agent
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Hocheol Seo <hocheol.seo@samsung.com>,
 *          Injun Yang <injun.yang@samsung.com>,
 *          Seungyoun Ju <sy39.ju@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mobileap_agent.h"
#include "mobileap_common.h"
#include "mobileap_usb.h"


static void __handle_usb_disconnect_cb(keynode_t *key, void *data)
{
	if (key == NULL || data == NULL) {
		ERR("Parameter is NULL\n");
		return;
	}

	int vconf_key = 0;
	MobileAPObject *obj = (MobileAPObject *)data;

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_USB)) {
		ERR("USB tethering is not enabled\n");
		return;
	}

	if (vconf_keynode_get_type(key) != VCONF_TYPE_INT) {
		ERR("Invalid vconf key type\n");
		return;
	}

	vconf_key = vconf_keynode_get_int(key);
	DBG("key = %s, value = %d(int)\n",
			vconf_keynode_get_name(key), vconf_key);

	if (vconf_key != VCONFKEY_SYSMAN_USB_DISCONNECTED) {
		return;
	}

	DBG("USB tethering will be disabled\n");

	_disable_usb_tethering(obj);

	_emit_mobileap_dbus_signal(obj, E_SIGNAL_USB_TETHER_OFF,
			SIGNAL_MSG_NOT_AVAIL_INTERFACE);

	return;
}



static void __handle_usb_mode_change(keynode_t *key, void *data)
{
	if (key == NULL) {
		ERR("Parameter is NULL\n");
		return;
	}

	MobileAPObject *obj = (MobileAPObject *)data;
	int vconf_key = 0;
	int is_usb_enabled = FALSE;
	unsigned int cfm = 0;

	if (vconf_keynode_get_type(key) != VCONF_TYPE_INT) {
		ERR("Invalid vconf key\n");
		return;
	}

	vconf_key = vconf_keynode_get_int(key);
	DBG("key = %s, value = %d(int)\n",
			vconf_keynode_get_name(key), vconf_key);

	is_usb_enabled = _mobileap_is_enabled(MOBILE_AP_STATE_USB);
	DBG("is_usb_enabled : %d\n", is_usb_enabled);

	if (is_usb_enabled) {
		if (vconf_key != SETTING_USB_TETHERING_MODE) {
			DBG("Is progressing for usb mode change\n");
			return;
		}
		DBG("USB tethering is enabled\n");
		cfm = MOBILE_AP_ENABLE_USB_TETHERING_CFM;
		_emit_mobileap_dbus_signal(obj, E_SIGNAL_USB_TETHER_ON, NULL);
	} else {
		if (vconf_key == SETTING_USB_TETHERING_MODE) {
			DBG("Is progressing for usb mode change\n");
			return;
		}
		DBG("USB tethering is disabled\n");
		cfm = MOBILE_AP_DISABLE_USB_TETHERING_CFM;
		_emit_mobileap_dbus_signal(obj, E_SIGNAL_USB_TETHER_OFF, NULL);
	}

	vconf_ignore_key_changed(VCONFKEY_SETAPPL_USB_MODE_INT,
			__handle_usb_mode_change);

	DBG("cfm : %d\n", cfm);
	dbus_g_method_return(obj->usb_context, cfm, MOBILE_AP_ERROR_NONE);
	obj->usb_context = NULL;
}


mobile_ap_error_code_e _disable_usb_tethering(MobileAPObject *obj)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_USB)) {
		ERR("USB tethering has not been enabled\n");
		ret = MOBILE_AP_ERROR_NOT_ENABLED;
		return ret;
	}

	_deinit_tethering(obj);

	if (_remove_station_info_all(MOBILE_AP_TYPE_USB) != MOBILE_AP_ERROR_NONE) {
		ERR("_remove_station_info_all is failed. Ignore it\n");
	}

	vconf_ignore_key_changed(VCONFKEY_SYSMAN_USB_STATUS,
			__handle_usb_disconnect_cb);

	_mobileap_clear_state(MOBILE_AP_STATE_USB);

	DBG("_disable_usb_tethering is done\n");

	return ret;
}



gboolean mobileap_enable_usb_tethering(MobileAPObject *obj,
						DBusGMethodInvocation *context)
{
	int vconf_ret;
	int usb_conn = VCONFKEY_SYSMAN_USB_DISCONNECTED;
	int usb_mode = SETTING_USB_NONE_MODE;
	int ret = MOBILE_AP_ERROR_NONE;

	DBG("+\n");

	g_assert(obj != NULL);
	g_assert(context != NULL);


	if (_mobileap_is_enabled(MOBILE_AP_STATE_USB)) {
		ERR("USB tethering is already enabled\n");
		ret = MOBILE_AP_ERROR_ALREADY_ENABLED;
		dbus_g_method_return(context,
				MOBILE_AP_ENABLE_USB_TETHERING_CFM, ret);
		return FALSE;
	}

	vconf_ret = vconf_get_int(VCONFKEY_SYSMAN_USB_STATUS, &usb_conn);
	if (vconf_ret != 0) {
		ERR("Error getting vconf\n");
		ret = MOBILE_AP_ERROR_RESOURCE;
		dbus_g_method_return(context,
				MOBILE_AP_ENABLE_USB_TETHERING_CFM, ret);
		return FALSE;
	}

	if (usb_conn != VCONFKEY_SYSMAN_USB_AVAILABLE) {
		ERR("USB is not connected\n");
		ret = MOBILE_AP_ERROR_RESOURCE;
		dbus_g_method_return(context,
				MOBILE_AP_ENABLE_USB_TETHERING_CFM, ret);
		return FALSE;
	}

	if (obj->usb_context) {
		ERR("USB request is progressing\n");
		ret = MOBILE_AP_ERROR_IN_PROGRESS;
		dbus_g_method_return(context,
				MOBILE_AP_ENABLE_USB_TETHERING_CFM, ret);
		return FALSE;
	}

	if (!_mobileap_set_state(MOBILE_AP_STATE_USB)) {
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto FAIL;
	}

	if (!_init_tethering(obj)) {
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto FAIL;
	}

	vconf_ret = vconf_get_int(VCONFKEY_SETAPPL_USB_MODE_INT, &usb_mode);
	if (vconf_ret != 0) {
		ERR("Error getting vconf\n");
		_deinit_tethering(obj);
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto FAIL;
	}

	vconf_notify_key_changed(VCONFKEY_SYSMAN_USB_STATUS,
			__handle_usb_disconnect_cb, obj);

	if (usb_mode == SETTING_USB_TETHERING_MODE) {
		DBG("Don't need to wait for usb-setting\n");
		dbus_g_method_return(context,
				MOBILE_AP_ENABLE_USB_TETHERING_CFM, ret);
	} else {
		obj->usb_context = context;
		vconf_notify_key_changed(VCONFKEY_SETAPPL_USB_MODE_INT,
				__handle_usb_mode_change, (void *)obj);
	}

	DBG("-\n");

	return TRUE;

FAIL:
	_mobileap_clear_state(MOBILE_AP_STATE_USB);
	dbus_g_method_return(context,
			MOBILE_AP_ENABLE_USB_TETHERING_CFM, ret);
	return FALSE;
}



gboolean mobileap_disable_usb_tethering(MobileAPObject *obj,
						DBusGMethodInvocation *context)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	int usb_mode = SETTING_USB_NONE_MODE;
	int vconf_ret = 0;

	DBG("+\n");

	g_assert(obj != NULL);
	g_assert(context != NULL);

	if (obj->usb_context) {
		ERR("USB request is progressing\n");
		ret = MOBILE_AP_ERROR_IN_PROGRESS;
		dbus_g_method_return(context,
				MOBILE_AP_ENABLE_USB_TETHERING_CFM, ret);
		return FALSE;
	}

	ret = _disable_usb_tethering(obj);
	if (ret != MOBILE_AP_ERROR_NONE) {
		dbus_g_method_return(context,
				MOBILE_AP_DISABLE_USB_TETHERING_CFM,
				ret);
		return FALSE;
	}

	vconf_ret = vconf_get_int(VCONFKEY_SETAPPL_USB_MODE_INT, &usb_mode);
	if (vconf_ret != 0) {
		ERR("Error getting vconf : %d\n", vconf_ret);
	}

	if (usb_mode != SETTING_USB_TETHERING_MODE) {
		DBG("Don't need to wait for usb-setting\n");
		_emit_mobileap_dbus_signal(obj, E_SIGNAL_USB_TETHER_ON, NULL);
		dbus_g_method_return(context,
				MOBILE_AP_DISABLE_USB_TETHERING_CFM,
				MOBILE_AP_ERROR_NONE);
	} else {
		obj->usb_context = context;
		vconf_notify_key_changed(VCONFKEY_SETAPPL_USB_MODE_INT,
				__handle_usb_mode_change, (void *)obj);
	}

	DBG("-\n");
	return TRUE;
}

static void __add_usb_station_info_to_array(GPtrArray *array, mobile_ap_station_info_t *node)
{
	GValue value = {0, {{0}}};

	g_value_init(&value, DBUS_STRUCT_STATION);
	g_value_take_boxed(&value,
			dbus_g_type_specialized_construct(DBUS_STRUCT_STATION));
	dbus_g_type_struct_set(&value, 0, node->ip, 1, node->mac,
			2, node->hostname, G_MAXUINT);
	g_ptr_array_add(array, g_value_get_boxed(&value));
}

gboolean mobileap_get_usb_station_info(MobileAPObject *obj,
						DBusGMethodInvocation *context)
{
	g_assert(obj != NULL);
	g_assert(context != NULL);

	GPtrArray *array = g_ptr_array_new();
	mobile_ap_station_info_t *node = NULL;

	if (_get_station_info((gconstpointer)MOBILE_AP_TYPE_USB,
				_slist_find_station_by_interface,
				&node) != MOBILE_AP_ERROR_NONE) {
		DBG("There is no USB station\n");
		dbus_g_method_return(context, array);
		g_ptr_array_free(array, TRUE);
		return TRUE;
	}

	__add_usb_station_info_to_array(array, node);
	dbus_g_method_return(context, array);
	g_ptr_array_free(array, TRUE);

	return TRUE;
}

gboolean mobileap_get_usb_interface_info(MobileAPObject *obj,
		DBusGMethodInvocation *context)
{
	g_assert(obj != NULL);
	g_assert(context != NULL);

	GPtrArray *array = g_ptr_array_new();
	GValue value = {0, {{0}}};
	struct in_addr addr;

	addr.s_addr = htonl(IP_ADDRESS_USB);

	g_value_init(&value, DBUS_STRUCT_INTERFACE);
	g_value_take_boxed(&value,
			dbus_g_type_specialized_construct(DBUS_STRUCT_INTERFACE));
	dbus_g_type_struct_set(&value, 0, USB_IF, 1, inet_ntoa(addr),
			2, inet_ntoa(addr), 3, IP_SUBNET_MASK, G_MAXUINT);

	g_ptr_array_add(array, g_value_get_boxed(&value));
	dbus_g_method_return(context, array);
	g_ptr_array_free(array, TRUE);

	return TRUE;
}
