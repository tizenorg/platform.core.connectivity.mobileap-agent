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
#include <stdlib.h>
#include <pmapi.h>
#include <vconf.h>
#include <net_connection.h>

#include "mobileap_agent.h"
#include "mobileap_handler.h"
#include "mobileap_common.h"
#include "mobileap_bluetooth.h"
#include "mobileap_wifi.h"
#include "mobileap_usb.h"
#include "mobileap_network.h"

GType mobileap_object_get_type(void);
#define MOBILEAP_TYPE_OBJECT (mobileap_object_get_type())
G_DEFINE_TYPE(MobileAPObject, mobileap_object, G_TYPE_OBJECT)

GMainLoop *mainloop = NULL;
int mobileap_state = MOBILE_AP_STATE_NONE;
DBusConnection *mobileap_conn = NULL;

gboolean mobileap_deinit(MobileAPObject *obj, GError **error);
gboolean mobileap_disable(MobileAPObject *obj, DBusGMethodInvocation *context);
gboolean mobileap_get_station_info(MobileAPObject *obj,
						DBusGMethodInvocation *context);
gboolean mobileap_get_data_packet_usage(MobileAPObject *obj,
						DBusGMethodInvocation *context);
#include "mobileap-server-stub.h"

static void mobileap_object_init(MobileAPObject *obj)
{
	DBG("+\n");
	g_assert(obj != NULL);

	obj->bt_context = NULL;
	obj->usb_context = NULL;
	obj->bt_device = NULL;
	obj->rx_bytes = 0;
	obj->tx_bytes = 0;
	obj->transfer_check_count = 0;
}

static void mobileap_object_finalize(GObject *obj)
{
	DBG("+\n");

	G_OBJECT_CLASS(mobileap_object_parent_class)->finalize(obj);
}

static void mobileap_object_class_init(MobileAPObjectClass *klass)
{
	GObjectClass *object_class = (GObjectClass *)klass;
	const gchar *signalNames[E_SIGNAL_MAX] = {
		SIGNAL_NAME_NET_CLOSED,
		SIGNAL_NAME_STA_CONNECT,
		SIGNAL_NAME_STA_DISCONNECT,
		SIGNAL_NAME_WIFI_TETHER_ON,
		SIGNAL_NAME_WIFI_TETHER_OFF,
		SIGNAL_NAME_USB_TETHER_ON,
		SIGNAL_NAME_USB_TETHER_OFF,
		SIGNAL_NAME_BT_TETHER_ON,
		SIGNAL_NAME_BT_TETHER_OFF,
		SIGNAL_NAME_NO_DATA_TIMEOUT,
		SIGNAL_NAME_LOW_BATTERY_MODE,
		SIGNAL_NAME_FLIGHT_MODE
	};

	int i = 0;

	g_assert(klass != NULL);

	object_class->finalize = mobileap_object_finalize;

	DBG("Creating signals\n");

	for (i = 0; i < E_SIGNAL_MAX; i++) {
		guint signalId;

		signalId = g_signal_new(signalNames[i],
					G_OBJECT_CLASS_TYPE(klass),
					G_SIGNAL_RUN_LAST,
					0, NULL, NULL,
					g_cclosure_marshal_VOID__STRING,
					G_TYPE_NONE, 1, G_TYPE_STRING);
		klass->signals[i] = signalId;
	}

	DBG("Binding to GLib/D-Bus\n");

	dbus_g_object_type_install_info(MOBILEAP_TYPE_OBJECT,
					&dbus_glib_mobileap_object_info);
}

static void __add_station_info_to_array(gpointer data, gpointer user_data)
{
	mobile_ap_station_info_t *si = (mobile_ap_station_info_t *)data;
	GPtrArray *array = (GPtrArray *)user_data;
	GValue value = {0, {{0}}};

	g_value_init(&value, DBUS_STRUCT_STATIONS);
	g_value_take_boxed(&value,
			dbus_g_type_specialized_construct(DBUS_STRUCT_STATIONS));
	dbus_g_type_struct_set(&value, 0, si->interface, 1, si->ip,
			2, si->mac, 3, si->hostname, G_MAXUINT);
	g_ptr_array_add(array, g_value_get_boxed(&value));
}

gboolean _mobileap_set_state(int state)
{
	int vconf_ret = 0;

	DBG("Before mobileap_state : %d\n", mobileap_state);
	mobileap_state |= state;
	DBG("After mobileap_state : %d\n", mobileap_state);

	vconf_ret = vconf_set_int(VCONFKEY_MOBILE_HOTSPOT_MODE, mobileap_state);
	if (vconf_ret != 0) {
		ERR("vconf_set_int is failed : %d\n", vconf_ret);
		return FALSE;
	}

	return TRUE;
}

int _mobileap_is_disabled(void)
{
	return !mobileap_state;
}

int _mobileap_is_enabled(int state)
{
	return (mobileap_state & state) ? 1 : 0;
}

gboolean _mobileap_clear_state(int state)
{
	int vconf_ret = 0;

	DBG("Before mobileap_state : %d\n", mobileap_state);
	mobileap_state &= (~state);
	DBG("After mobileap_state : %d\n", mobileap_state);

	vconf_ret = vconf_set_int(VCONFKEY_MOBILE_HOTSPOT_MODE, mobileap_state);
	if (vconf_ret != 0) {
		ERR("vconf_set_int is failed : %d\n", vconf_ret);
		return FALSE;
	}

	return TRUE;
}

static void __block_device_sleep(void)
{
	int ret = 0;

	ret = pm_lock_state(LCD_OFF, STAY_CUR_STATE, 0);
	if (ret < 0)
		ERR("PM control [ERROR] result = %d\n", ret);
	else
		DBG("PM control [SUCCESS]\n");
}

static void __unblock_device_sleep(void)
{
	int ret = 0;

	ret = pm_unlock_state(LCD_OFF, PM_SLEEP_MARGIN);
	if (ret < 0)
		ERR("PM control [ERROR] result = %d\n", ret);
	else
		DBG("PM control [SUCCESS]\n");
}

gboolean _init_tethering(MobileAPObject *obj)
{
	DBG("obj->init_count: %d\n", obj->init_count);

	if (obj->init_count > 0) {
		DBG("Already env. is initialized for tethering: %d\n",
				obj->init_count);
		obj->init_count++;
		return TRUE;
	}

	obj->init_count++;

	DBG("Set masquerading / Run DHCP\n");
	__block_device_sleep();

	_open_network();

	_mh_core_execute_dhcp_server();

	return TRUE;
}

gboolean _deinit_tethering(MobileAPObject *obj)
{
	DBG("obj->init_count: %d\n", obj->init_count);

	if (obj->init_count > 1) {
		DBG("Already deinitialized\n");
		obj->init_count--;
		return TRUE;
	} else if (obj->init_count <= 0) {
		ERR("Already deinitialized\n");
		obj->init_count = 0;
		return TRUE;
	}

	obj->init_count = 0;

	DBG("Terminate DHCP / IPTABLES\n");
	_mh_core_terminate_dhcp_server();
	_close_network();
	__unblock_device_sleep();

	return TRUE;
}


gboolean mobileap_deinit(MobileAPObject *obj, GError **error)
{
	DBG("+\n");
	g_assert(obj != NULL);

	if (_mobileap_is_disabled()) {
		DBG("Mobile AP is not activated, so we quit the mobileap-agent.\n");
		g_main_loop_quit(mainloop);
	}

	return TRUE;
}

gboolean mobileap_disable(MobileAPObject *obj, DBusGMethodInvocation *context)
{
	int ret = MOBILE_AP_ERROR_NONE;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	if (_mobileap_is_disabled()) {
		ERR("Mobile hotspot has not been enabled\n");
		ret = MOBILE_AP_ERROR_NOT_ENABLED;
		dbus_g_method_return(context, MOBILE_AP_DISABLE_CFM, ret);
		return FALSE;
	}

	_disable_wifi_tethering(obj);
	_disable_bt_tethering(obj);
	_disable_usb_tethering(obj);

	dbus_g_method_return(context, MOBILE_AP_DISABLE_CFM, ret);

	return TRUE;
}

gboolean mobileap_get_station_info(MobileAPObject *obj,
						DBusGMethodInvocation *context)
{
	DBG("+\n");

	GPtrArray *array = g_ptr_array_new();

	g_assert(obj != NULL);
	g_assert(context != NULL);

	_station_info_foreach(__add_station_info_to_array, array);

	dbus_g_method_return(context, MOBILE_AP_GET_STATION_INFO_CFM, array);
	g_ptr_array_free(array, TRUE);

	DBG("-\n");

	return TRUE;
}

gboolean mobileap_get_data_packet_usage(MobileAPObject *obj,
						DBusGMethodInvocation *context)
{
	char *if_name = NULL;
	unsigned long long wifi_tx_bytes = 0;
	unsigned long long wifi_rx_bytes = 0;
	unsigned long long bt_tx_bytes = 0;
	unsigned long long bt_rx_bytes = 0;
	unsigned long long usb_tx_bytes = 0;
	unsigned long long usb_rx_bytes = 0;
	unsigned long long tx_bytes = 0;
	unsigned long long rx_bytes = 0;

	if (_get_network_interface_name(&if_name) == FALSE) {
		ERR("No network interface\n");
		dbus_g_method_return(context, MOBILE_AP_GET_DATA_PACKET_USAGE_CFM,
				0, 0);
		return FALSE;
	}

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI))
		_get_data_usage(WIFI_IF, if_name,
				&wifi_tx_bytes, &wifi_rx_bytes);

	if (_mobileap_is_enabled(MOBILE_AP_STATE_BT))
		_get_data_usage(BT_IF_ALL, if_name,
				&bt_tx_bytes, &bt_rx_bytes);

	if (_mobileap_is_enabled(MOBILE_AP_STATE_USB))
		_get_data_usage(USB_IF, if_name,
				&usb_tx_bytes, &usb_rx_bytes);
	free(if_name);

	tx_bytes = wifi_tx_bytes + bt_tx_bytes + usb_tx_bytes;
	rx_bytes = wifi_rx_bytes + bt_rx_bytes + usb_rx_bytes;

	dbus_g_method_return(context, MOBILE_AP_GET_DATA_PACKET_USAGE_CFM,
			tx_bytes, rx_bytes);

	return TRUE;
}


static void __reset_interface(MobileAPObject *obj)
{
	obj->rx_bytes = 0;
	obj->tx_bytes = 0;
	obj->transfer_check_count = 0;
}


static gboolean __check_data_transfer_cb(gpointer data)
{
	MobileAPObject *obj = (MobileAPObject *)data;
	GIOChannel *io = NULL;
	gchar *line = NULL;

	char *if_name = NULL;
	gchar iface[IF_BUF_LEN] = {0, };
	unsigned long long rx_bytes = 0;
	unsigned long long tx_bytes = 0;

	if (_mobileap_is_disabled()) {
		ERR("Nothing is to be done.\n");
		return TRUE;
	}

	if (_get_network_interface_name(&if_name) == FALSE)
		return TRUE;

	io = g_io_channel_new_file(PROC_NET_DEV, "r", NULL);
	if (!io) {
		ERR("g_io_channel_new_file failed\n");
		return TRUE;
	}

	while (g_io_channel_read_line(io, &line, NULL, NULL, NULL) == G_IO_STATUS_NORMAL) {

		line = g_strdelimit(line, ":", ' ');
		sscanf(line, "%29s %19lld %*s %*s %*s %*s %*s %*s %*s %19lld %*s %*s %*s %*s %*s",
								iface, &rx_bytes, &tx_bytes);

		g_free(line);

		if (g_ascii_strcasecmp(iface, if_name) == 0) {
			break;
		}
	}

	g_io_channel_unref(io);
	free(if_name);

	/*DBG("rx:%lld tx:%lld\n", rx_bytes, tx_bytes);*/
	if (obj->rx_bytes < rx_bytes || obj->tx_bytes < tx_bytes) {
		obj->rx_bytes = rx_bytes;
		obj->tx_bytes = tx_bytes;
		obj->transfer_check_count = 0;
	} else {
		obj->transfer_check_count++;

		/* 30 minutes */
		if (obj->transfer_check_count == MAX_TRANSFER_CHECK_COUNT) {
			_emit_mobileap_dbus_signal(obj,
					E_SIGNAL_NO_DATA_TIMEOUT, NULL);
			__reset_interface(obj);
			_disable_wifi_tethering(obj);
		}
	}

	return TRUE;
}


static DBusHandlerResult __dnsmasq_signal_filter(DBusConnection *conn,
		DBusMessage *msg, void *user_data)
{
	if (!user_data) {
		ERR("Invalid param\n");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	char *ip_addr = NULL;
	char *mac = NULL;
	char *name = NULL;
	char *bt_remote_device_name = NULL;
	DBusError error;
	mobile_ap_type_e type = MOBILE_AP_TYPE_MAX;
	MobileAPObject *obj = (MobileAPObject *)user_data;
	mobile_ap_station_info_t *info = NULL;

	dbus_error_init(&error);
	if (dbus_message_is_signal(msg, DNSMASQ_DBUS_INTERFACE,
				"DhcpConnected")) {
		if (!dbus_message_get_args(msg, &error,
					DBUS_TYPE_STRING, &ip_addr,
					DBUS_TYPE_STRING, &mac,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID)) {
			ERR("Cannot read message, cause: %s\n", error.message);
			dbus_error_free(&error);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		DBG("DhcpConnected signal : %s  %s %s\n", ip_addr, mac, name);

		if (_get_tethering_type_from_ip(ip_addr, &type) != MOBILE_AP_ERROR_NONE)
			return DBUS_HANDLER_RESULT_HANDLED;

		info = (mobile_ap_station_info_t *)malloc(sizeof(mobile_ap_station_info_t));
		if (info == NULL) {
			ERR("malloc failed\n");
			return DBUS_HANDLER_RESULT_HANDLED;
		}

		info->interface = type;
		g_strlcpy(info->ip, ip_addr, sizeof(info->ip));
		g_strlcpy(info->mac, mac, sizeof(info->mac));
		if (type == MOBILE_AP_TYPE_WIFI || type == MOBILE_AP_TYPE_USB) {
			if (name[0] == '\0')
				g_strlcpy(info->hostname,
						MOBILE_AP_NAME_UNKNOWN,
						sizeof(info->hostname));
			else
				g_strlcpy(info->hostname, name,
						sizeof(info->hostname));
		} else if (type == MOBILE_AP_TYPE_BT) {
			_bt_get_remote_device_name(obj, mac, &bt_remote_device_name);
			if (bt_remote_device_name == NULL)
				g_strlcpy(info->hostname,
						MOBILE_AP_NAME_UNKNOWN,
						sizeof(info->hostname));
			else {
				g_strlcpy(info->hostname, bt_remote_device_name,
						sizeof(info->hostname));
				free(bt_remote_device_name);
			}
		}

		_add_station_info(info);
		_send_dbus_station_info("DhcpConnected", info);

		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, DNSMASQ_DBUS_INTERFACE,
				"DhcpLeaseDeleted")) {
		if (!dbus_message_get_args(msg, &error,
					DBUS_TYPE_STRING, &ip_addr,
					DBUS_TYPE_STRING, &mac,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID)) {
			ERR("Cannot read message, cause: %s\n", error.message);
			dbus_error_free(&error);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		DBG("DhcpLeaseDeleted signal : %s  %s %s\n", ip_addr, mac, name);

		_remove_station_info(mac, _slist_find_station_by_mac);

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

int main(int argc, char **argv)
{
	MobileAPObject *mobileap_obj = NULL;
	DBusError dbus_error;
	char *rule = "type='signal',interface='"DNSMASQ_DBUS_INTERFACE"'";
	DBusGConnection *mobileap_bus = NULL;
	DBusGProxy *mobileap_bus_proxy = NULL;
	guint result = 0;
	GError *error = NULL;
	int mobileap_vconf_key = VCONFKEY_MOBILE_HOTSPOT_MODE_NONE;

	g_type_init();

	if (vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &mobileap_vconf_key)) {
		ERR("vconf_get_int FAIL\n");
		mobileap_state = MOBILE_AP_STATE_NONE;
	} else {
		ERR("vconf_get_int OK(mobileap_vconf_key value is %d)\n",
				 mobileap_vconf_key);
		mobileap_state = mobileap_vconf_key;
	}

	mainloop = g_main_loop_new(NULL, FALSE);
	if (mainloop == NULL) {
		ERR("Couldn't create GMainLoop\n");
		goto failure;
	}

	mobileap_bus = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error != NULL) {
		ERR("Couldn't connect to system bus[%s]\n", error->message);
		goto failure;
	}

	mobileap_conn = dbus_g_connection_get_connection(mobileap_bus);

	DBG("Registering the well-known name (%s)\n", SOFTAP_SERVICE_NAME);

	mobileap_bus_proxy = dbus_g_proxy_new_for_name(mobileap_bus,
						       DBUS_SERVICE_DBUS, DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS);
	if (mobileap_bus_proxy == NULL) {
		ERR("Failed to get a proxy for D-Bus\n");
		goto failure;
	}

	if (!dbus_g_proxy_call(mobileap_bus_proxy,
			       "RequestName",
			       &error,
			       G_TYPE_STRING,
			       SOFTAP_SERVICE_NAME,
			       G_TYPE_UINT, 0, G_TYPE_INVALID, G_TYPE_UINT, &result, G_TYPE_INVALID)) {
		ERR("D-Bus.RequestName RPC failed[%s]\n", error->message);
		goto failure;
	}

	if (result != 1) {
		ERR("Failed to get the primary well-known name.\n");
		goto failure;
	}

	g_object_unref(mobileap_bus_proxy);
	mobileap_bus_proxy = NULL;

	mobileap_obj = g_object_new(MOBILEAP_TYPE_OBJECT, NULL);
	if (mobileap_obj == NULL) {
		ERR("Failed to create one MobileAP instance.\n");
		goto failure;
	}

	/* Registering it on the D-Bus */
	dbus_g_connection_register_g_object(mobileap_bus,
			SOFTAP_SERVICE_OBJECT_PATH, G_OBJECT(mobileap_obj));

	DBG("Ready to serve requests.\n");

	_init_network(NULL);
	_register_wifi_station_handler();
	_register_vconf_cb((void *)mobileap_obj);

	/* check tx/rx every 10 seconds */
	g_timeout_add(10000, __check_data_transfer_cb, mobileap_obj);

	dbus_error_init(&dbus_error);
	dbus_bus_add_match(mobileap_conn, rule, &dbus_error);
	if (dbus_error_is_set(&dbus_error)) {
		ERR("Cannot add D-BUS match rule, cause: %s", dbus_error.message);
		dbus_error_free(&dbus_error);
		goto failure;
	}

	DBG("Listening to D-BUS signals from dnsmasq");
	dbus_connection_add_filter(mobileap_conn, __dnsmasq_signal_filter, mobileap_obj, NULL);

	g_main_loop_run(mainloop);

	_unregister_vconf_cb((void *)mobileap_obj);
	_deinit_network();

 failure:
	ERR("Terminate the mobileap-agent\n");

	if (mobileap_bus)
		dbus_g_connection_unref(mobileap_bus);
	if (mobileap_bus_proxy)
		g_object_unref(mobileap_bus_proxy);
	if (mobileap_obj)
		g_object_unref(mobileap_obj);

	return 0;
}
