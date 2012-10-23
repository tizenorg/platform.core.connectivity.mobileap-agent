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

#include <stdlib.h>

#include "mobileap_agent.h"
#include "mobileap_network.h"

static connection_h connection = NULL;
static connection_profile_h cprof = NULL;

static void __print_profile(connection_profile_h profile)
{
#define __check_connection_return(conn_ret)	\
	do {	\
		if (conn_ret != CONNECTION_ERROR_NONE)	\
			ERR("connection API fail : 0x%X\n", conn_ret);	\
	} while(0)

	if (profile == NULL)
		return;

	int conn_ret;
	bool roaming;
	char *apn;
	char *user_name;
	char *password;
	char *home_url;
	connection_cellular_network_type_e network_type;
	connection_cellular_service_type_e service_type;
	connection_cellular_auth_type_e auth_type;

	conn_ret = connection_profile_get_cellular_network_type(profile, &network_type);
	__check_connection_return(conn_ret);
	DBG("Network type : %d\n", network_type);

	conn_ret = connection_profile_get_cellular_service_type(profile, &service_type);
	__check_connection_return(conn_ret);
	DBG("Service type : %d\n", service_type);

	conn_ret = connection_profile_get_cellular_apn(profile, &apn);
	__check_connection_return(conn_ret);
	DBG("APN : %s\n", apn);
	free(apn);

	conn_ret = connection_profile_get_cellular_auth_info(profile, &auth_type,
			&user_name, &password);
	__check_connection_return(conn_ret);
	DBG("Auth type : %d\n", auth_type);
	DBG("User name : %s\n", user_name);
	DBG("Password : %s\n", password);
	free(user_name);
	free(password);

	conn_ret = connection_profile_get_cellular_home_url(profile, &home_url);
	__check_connection_return(conn_ret);
	DBG("Home url : %s\n", home_url);
	free(home_url);

	conn_ret = connection_profile_is_cellular_roaming(profile, &roaming);
	__check_connection_return(conn_ret);
	DBG("Roaming : %d\n", roaming);

#undef __check_connection_return
	return;
}

static void __connection_opened_cb(connection_error_e result, void *user_data)
{
	if (cprof == NULL) {
		ERR("Current profile is not set\n");
		return;
	}

	if (result != CONNECTION_ERROR_NONE) {
		ERR("connection open is failed : 0x%X\n", result);
		connection_profile_destroy(cprof);
		cprof = NULL;
		return;
	}

	if (_mobileap_is_disabled()) {
		_close_network();
		return;
	}

	if (_set_masquerade() == FALSE) {
		ERR("_set_masquerade is failed\n");
		_close_network();
		return;
	}

	return;
}

static void __connection_closed_cb(connection_error_e result, void *user_data)
{
	if (result != CONNECTION_ERROR_NONE)
		ERR("Connection close is failed : 0x%X\n", result);
	else
		DBG("Connection is closed\n");

	connection_profile_destroy(cprof);
	cprof = NULL;

	return;
}

static gboolean __get_connected_prof(connection_profile_h *r_prof, connection_profile_type_e *r_net_type)
{
	int conn_ret;
	connection_profile_h profile = NULL;
	connection_profile_type_e net_type = CONNECTION_PROFILE_TYPE_CELLULAR;

	conn_ret = connection_get_current_profile(connection, &profile);
	if (conn_ret != CONNECTION_ERROR_NONE) {
		ERR("connection_get_current_profile is failed : %d\n", conn_ret);
		return FALSE;
	}

	conn_ret = connection_profile_get_type(profile, &net_type);
	if (conn_ret != CONNECTION_ERROR_NONE) {
		ERR("connection_profile_get_type is failed : 0x%X\n", conn_ret);
		connection_profile_destroy(profile);
		return FALSE;
	}

	*r_prof = profile;
	*r_net_type = net_type;

	return TRUE;
}

static gboolean __is_tethering_cellular_prof(connection_profile_h profile)
{
	int conn_ret;
	connection_cellular_service_type_e svc_type;

	conn_ret = connection_profile_get_cellular_service_type(profile, &svc_type);
	if (conn_ret != CONNECTION_ERROR_NONE) {
		ERR("connection_profile_get_cellular_service_type is failed : 0x%X\n", conn_ret);
		return FALSE;
	}

	if (svc_type != CONNECTION_CELLULAR_SERVICE_TYPE_TETHERING)
		return FALSE;

	return TRUE;
}

static gboolean __get_tethering_cellular_prof(connection_profile_h *profile, gboolean *is_connected)
{
	int conn_ret;
	connection_profile_state_e pstat = CONNECTION_PROFILE_STATE_DISCONNECTED;

	conn_ret = connection_get_default_cellular_service_profile(connection,
			CONNECTION_CELLULAR_SERVICE_TYPE_TETHERING, profile);
	if (conn_ret != CONNECTION_ERROR_NONE) {
		ERR("There is no tethering profile : 0x%X\n", conn_ret);
		return FALSE;
	}

	conn_ret = connection_profile_get_state(*profile, &pstat);
	if (conn_ret != CONNECTION_ERROR_NONE) {
		ERR("connection_profile_get_state is failed : 0x%X\n", conn_ret);
		connection_profile_destroy(*profile);
		return FALSE;
	}

	if (pstat != CONNECTION_PROFILE_STATE_CONNECTED)
		*is_connected = FALSE;
	else
		*is_connected = TRUE;

	return TRUE;
}

static gboolean __get_network_prof(connection_profile_h *r_prof, gboolean *is_connected)
{
	connection_profile_h profile;
	connection_profile_h tether_prof;
	connection_profile_type_e net_type = CONNECTION_PROFILE_TYPE_CELLULAR;

	if (__get_connected_prof(&profile, &net_type) != TRUE) {
		ERR("There is no available network\n");
		return FALSE;
	}

	if (net_type == CONNECTION_PROFILE_TYPE_CELLULAR) {
		if (__is_tethering_cellular_prof(profile) == TRUE)
			goto DONE;

		if (__get_tethering_cellular_prof(&tether_prof, is_connected) == FALSE) {
			DBG("There is no tethering service cellular\n");
			goto DONE;
		}
		connection_profile_destroy(profile);

		*r_prof = tether_prof;
		return TRUE;
	}

DONE:
	*r_prof = profile;
	*is_connected = TRUE;
	return TRUE;
}

static void __connection_type_changed_cb(connection_type_e type, void *user_data)
{
	if (_mobileap_is_disabled()) {
		DBG("Tethering is not enabled\n");
		return;
	}

	DBG("Changed connection type is %s\n",
			type == CONNECTION_TYPE_DISCONNECTED ? "DISCONNECTED" :
			type == CONNECTION_TYPE_WIFI ? "Wi-FI" :
			type == CONNECTION_TYPE_CELLULAR ? "Cellular" :
			type == CONNECTION_TYPE_ETHERNET ? "Ethernet" :
			"Unknown");

	_close_network();
	if (type == CONNECTION_TYPE_DISCONNECTED)
		return;

	_open_network();
	return;
}

gboolean _get_network_interface_name(char **if_name)
{
	int conn_ret = 0;

	if (cprof == NULL)
		return FALSE;

	conn_ret = connection_profile_get_network_interface_name(cprof, if_name);
	if (conn_ret != CONNECTION_ERROR_NONE) {
		ERR("connection_profile_get_network_interface_name is failed : 0x%X\n", conn_ret);
		return FALSE;
	}

	return TRUE;
}

gboolean _set_masquerade(void)
{
	char *if_name = NULL;

	if (_get_network_interface_name(&if_name) == FALSE) {
		ERR("_get_network_interface_name is failed\n");
		return FALSE;
	}
	DBG("Network interface : %s\n", if_name);

	_mh_core_enable_masquerade(if_name);
	free(if_name);

	return TRUE;
}

gboolean _unset_masquerade(void)
{
	char *if_name = NULL;

	if (_get_network_interface_name(&if_name) == FALSE) {
		ERR("_get_network_interface_name is failed\n");
		return FALSE;
	}
	DBG("Network interface : %s\n", if_name);

	_mh_core_disable_masquerade(if_name);
	free(if_name);

	return TRUE;
}

gboolean _open_network(void)
{
	connection_profile_h profile = NULL;
	gboolean is_connected = FALSE;
	int conn_ret;

	if (__get_network_prof(&profile, &is_connected) == FALSE) {
		ERR("__get_network_prof is failed\n");
		return FALSE;
	}
	cprof = profile;

	if (is_connected == FALSE) {
		conn_ret = connection_open_profile(connection, cprof,
				__connection_opened_cb, NULL);
		if (conn_ret != CONNECTION_ERROR_NONE) {
			ERR("connection_open_profile is failed : 0x%X\n", conn_ret);
			connection_profile_destroy(cprof);
			cprof = NULL;
			return FALSE;
		}

		return TRUE;
	}

	if (_set_masquerade() == FALSE) {
		ERR("_set_masquerade is failed\n");
		_close_network();
		return FALSE;
	}

	return TRUE;
}

gboolean _close_network(void)
{
	int conn_ret;

	if (cprof == NULL)
		return TRUE;

	if (_unset_masquerade() == FALSE)
		ERR("_unset_masquerade is failed\n");

	if (__is_tethering_cellular_prof(cprof) == TRUE) {
		conn_ret = connection_close_profile(connection, cprof,
				__connection_closed_cb, NULL);
		if (conn_ret != CONNECTION_ERROR_NONE) {
			ERR("connection_close_profile is failed : 0x%X\n", conn_ret);
			return FALSE;
		}

		return TRUE;
	}

	connection_profile_destroy(cprof);
	cprof = NULL;

	return TRUE;
}

gboolean _init_network(void *user_data)
{
	int conn_ret;

	conn_ret = connection_create(&connection);
	if (conn_ret != CONNECTION_ERROR_NONE) {
		ERR("connection_create is failed : 0x%X\n", conn_ret);
		return FALSE;
	}

	conn_ret = connection_set_type_changed_cb(connection,
			__connection_type_changed_cb, user_data);
	if (conn_ret != CONNECTION_ERROR_NONE) {
		ERR("connection_set_type_changed cb is failed : 0x%X\n", conn_ret);
		connection_destroy(connection);
		connection = NULL;
		return FALSE;
	}

	return TRUE;
}

gboolean _deinit_network(void)
{
	int conn_ret;

	if (connection == NULL) {
		ERR("Connection handle is not initialized\n");
		return TRUE;
	}

	conn_ret = connection_unset_type_changed_cb(connection);
	if (conn_ret != CONNECTION_ERROR_NONE) {
		ERR("connection_unset_type_changed_cb is failed : %d\n", conn_ret);
	}

	connection_destroy(connection);
	connection = NULL;

	return TRUE;
}
