/*
 * mobileap-agent
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd.
 * All rights reserved.
 *
 * Contact: Hocheol Seo <hocheol.seo@samsung.com>,
 *          Injun Yang <injun.yang@samsung.com>,
 *          Seungyoun Ju <sy39.ju@samsung.com>
 *
 * Copyright (C) 2011-2012  Intel Corporation. All rights reserved.
 *
 * Contact: Guoqiang Liu <guoqiangx.liu@intel.com>
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

#include <stdio.h>
#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <stdlib.h>

#include "mobileap_connman.h"

gint __enable_tethering(const gchar *path, const gchar *ssid,
		const gchar *security, const gchar *key, gint hide_mode)
{
	gint ret = MOBILE_AP_ERROR_NONE;
	const gchar *psk = NULL;
	gboolean hidden = hide_mode ? TRUE:FALSE;
	GError *error = NULL;
	GDBusProxyFlags flags = G_DBUS_PROXY_FLAGS_NONE
		|G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
		|G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS;
	GDBusProxy *technology_proxy = NULL;

	if (path == NULL) {
		ERR("Invalid param\n");
		ret = MOBILE_AP_ERROR_INTERNAL;
		goto done;
	}

	technology_proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SYSTEM,
					flags,
					NULL,
					CONNMAN_SERVICE,
					path,
					CONNMAN_TECHNOLOGY_INTERFACE,
					NULL,
					&error);
	if (!technology_proxy) {
		ERR("Couldn't create the proxy object: %s\n",
					error->message);
		g_error_free(error);
		ret = MOBILE_AP_ERROR_INTERNAL;
		goto done;
	}

	if (ssid != NULL && key != NULL && security != NULL) {
		if (strcmp(security, "open") == 0)
			psk = "";
		else
			psk = key;

		g_dbus_proxy_call_sync(technology_proxy, "SetProperty",
					g_variant_new("(sv)",
					"TetheringIdentifier",
					g_variant_new_string(ssid)),
					G_DBUS_CALL_FLAGS_NONE,
					-1,
					NULL,
					&error);
		if (error) {
			ERR("SetProperty failed[%s]", error->message);
			g_error_free(error);
			ret = MOBILE_AP_ERROR_INTERNAL;
			goto done;
		}

		g_dbus_proxy_call_sync(technology_proxy, "SetProperty",
					g_variant_new("(sv)",
					"TetheringPassphrase",
					g_variant_new_string(psk)),
					G_DBUS_CALL_FLAGS_NONE,
					-1,
					NULL,
					&error);
		if (error) {
			ERR("SetProperties failed[%s]", error->message);
			g_error_free(error);
			ret = MOBILE_AP_ERROR_INTERNAL;
			goto done;
		}

		g_dbus_proxy_call_sync(technology_proxy, "SetProperty",
					g_variant_new("(sv)",
					"Hidden",
					g_variant_new_boolean(hidden)),
					G_DBUS_CALL_FLAGS_NONE,
					-1,
					NULL,
					&error);
		if (error) {
			ERR("SetProperties failed[%s]", error->message);
			g_error_free(error);
			ret = MOBILE_AP_ERROR_INTERNAL;
			goto done;
		}
	}

	g_dbus_proxy_call_sync(technology_proxy, "SetProperty",
					g_variant_new("(sv)",
					"Tethering",
					g_variant_new_boolean(TRUE)),
					G_DBUS_CALL_FLAGS_NONE,
					-1,
					NULL,
					&error);
	if (error) {
		ERR("SetProperties failed[%s]", error->message);
		g_error_free(error);
		ret = MOBILE_AP_ERROR_INTERNAL;
		goto done;
	}

done:
	return ret;
}

gint __disable_tethering(const gchar *path)
{
	gint ret = MOBILE_AP_ERROR_NONE;
	GError *error = NULL;
	GDBusProxyFlags flags = G_DBUS_PROXY_FLAGS_NONE
		|G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
		|G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS;
	GDBusProxy *technology_proxy = NULL;

	if (path == NULL) {
		ERR("Invalid param\n");
		ret = MOBILE_AP_ERROR_INTERNAL;
		goto done;
	}

	technology_proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SYSTEM,
					flags,
					NULL,
					CONNMAN_SERVICE	,
					path,
					CONNMAN_TECHNOLOGY_INTERFACE,
					NULL,
					&error);
	if (!technology_proxy) {
		ERR("Couldn't create the proxy object: %s\n",
				error->message);
		g_error_free(error);
		ret = MOBILE_AP_ERROR_INTERNAL;
		goto done;
	}

	g_dbus_proxy_call_sync(technology_proxy, "SetProperty",
					g_variant_new("(sv)",
					"Tethering",
					g_variant_new_boolean(FALSE)),
					G_DBUS_CALL_FLAGS_NONE,
					-1,
					NULL,
					&error);
	if (error) {
		ERR("SetProperties failed[%s]", error->message);
		g_error_free(error);
		ret = MOBILE_AP_ERROR_INTERNAL;
		goto done;
	}

done:
	return ret;
}

static const gchar *type2string(enum technology_type type)
{
	switch (type) {
	case TECH_TYPE_WIFI:
		return "wifi";
	case TECH_TYPE_BLUETOOTH:
		return "bluetooth";
	case TECH_TYPE_USB:
		return "gadget";
	default:
		return "unknown";
	}
}

gboolean __get_technology_path_by_type(enum technology_type tech_type,
					gchar **path)
{
	gboolean ret = TRUE;
	GError *error = NULL;
	GDBusProxyFlags flags = G_DBUS_PROXY_FLAGS_NONE
		|G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
		|G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS;
	GDBusProxy *manager_proxy = NULL;
	GVariant *technology_list = NULL;
	const gchar *type_str = NULL;

	if (path == NULL) {
		ERR("Invalid param\n");
		ret = MOBILE_AP_ERROR_INTERNAL;
		goto done;
	}

	type_str = type2string(tech_type);
	if (!g_strcmp0("unknown", type_str)) {
		ERR("Error Type: %d\n", tech_type);
		ret = FALSE;
		goto done;
	}

	manager_proxy = g_dbus_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
					flags,
					NULL,
					CONNMAN_SERVICE,
					CONNMAN_MANAGER_PATH,
					CONNMAN_MANAGER_INTERFACE,
					NULL,
					&error);
	if (!manager_proxy) {
		ERR("Couldn't create the proxy: %s\n", error->message);
		g_error_free(error);
		ret = FALSE;
		goto done;
	}

	technology_list = g_dbus_proxy_call_sync(manager_proxy,
					"GetTechnologies",
					NULL,
					G_DBUS_CALL_FLAGS_NONE,
					-1,
					NULL,
					NULL);
	if (!technology_list) {
		ERR("GetTechnologies failed[%s]", error->message);
		g_error_free(error);
		ret = FALSE;
		goto done;
	}

	if (!g_strcmp0("a(oa{sv})",
			g_variant_get_type_string(technology_list))) {
		ERR("interface mismatch !!!");
		g_variant_unref(technology_list);
		ret = FALSE;
		goto done;
	}

	GVariantIter iter;
	GVariant *child;

	g_variant_iter_init(&iter, technology_list);
	child = g_variant_iter_next_value(&iter);
	g_variant_iter_init(&iter, child);
	g_variant_unref(child);

	while ((child = g_variant_iter_next_value(&iter))) {
		DBG("type '%s'\n", g_variant_get_type_string(child));
		if (g_variant_is_container(child)) {
			GVariantIter iter_t;
			GVariant *child_t;

			g_variant_iter_init(&iter_t, child);
			child_t = g_variant_iter_next_value(&iter_t);

			if (!g_strcmp0("o",
					g_variant_get_type_string(child_t))) {
				gsize size;
				const gchar *o_path = NULL;
				o_path = g_variant_get_string(child_t, &size);

				DBG("path '%s'\n", o_path);
				if (g_str_has_suffix(o_path, type_str)) {
					*path = g_strdup(o_path);
					g_variant_unref(child_t);
					g_variant_unref(child);
					return ret;
				}
			}
			g_variant_unref(child_t);
		}
		g_variant_unref(child);
	}
	ret = FALSE;

done:
	return ret;
}

int connman_enable_tethering(enum technology_type type, const char *ssid,
			const char *security, const char *key, int hide_mode)
{
	gchar *path = NULL;
	int ret = MOBILE_AP_ERROR_INTERNAL;

	if (type == TECH_TYPE_WIFI
		&& (ssid == NULL || security == NULL || key == NULL)) {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	if (!__get_technology_path_by_type(type, &path)) {
		ERR("Enable tethering Error, Uknown technology: %d\n", type);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = __enable_tethering(path, ssid, security, key, hide_mode);

	g_free(path);
	return ret;
}

int connman_disable_tethering(enum technology_type type)
{
	gchar *path = NULL;
	int ret = MOBILE_AP_ERROR_INTERNAL;

	if (!__get_technology_path_by_type(type, &path)) {
		ERR("Disable tethering Error, Uknown technology: %d\n", type);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = __disable_tethering(path);

	g_free(path);
	return ret;
}
