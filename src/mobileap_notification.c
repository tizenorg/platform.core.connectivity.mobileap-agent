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
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <stdio.h>
#include <string.h>
#include <notification.h>

#include "mobileap_agent.h"

#define MH_NOTI_APP_NAME	"org.tizen.tethering"

static int connected_noti_id = 0;
static int timeout_noti_id = 0;

int _create_timeout_noti(const char *content, const char *title,
		const char *icon_path)
{
	DBG("+\n");
	notification_h noti = NULL;
	notification_error_e ret = NOTIFICATION_ERROR_NONE;

	if (timeout_noti_id) {
		noti = notification_load(APPNAME, timeout_noti_id);
		if (noti == NULL) {
			DBG("Notification can be deleted already\n");
		} else {
			ret = notification_delete(noti);
			if (ret != NOTIFICATION_ERROR_NONE) {
				ERR("Fail to notification_delete [%d]\n", ret);

				ret = notification_free(noti);
				if (ret != NOTIFICATION_ERROR_NONE)
					ERR("Fail to notification_free [%d]\n", ret);
				return MOBILE_AP_ERROR_INTERNAL;
			}

			ret = notification_free(noti);
			if (ret != NOTIFICATION_ERROR_NONE) {
				ERR("Fail to notification_free [%d]\n", ret);
				return MOBILE_AP_ERROR_INTERNAL;
			}
		}
		timeout_noti_id = 0;
	}

	noti = notification_new(NOTIFICATION_TYPE_NOTI,
			NOTIFICATION_GROUP_ID_NONE, NOTIFICATION_PRIV_ID_NONE);
	if (!noti) {
		ERR("Fail to notification_new [%d]\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = notification_set_property(noti,
			NOTIFICATION_PROP_VOLATILE_DISPLAY);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_property [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_layout(noti, NOTIFICATION_LY_NOTI_EVENT_SINGLE);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_image [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_image(noti,
			NOTIFICATION_IMAGE_TYPE_ICON, icon_path);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_image [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_text(noti,
			NOTIFICATION_TEXT_TYPE_TITLE,
			title,
			NULL, NOTIFICATION_VARIABLE_TYPE_NONE);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_text [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_text(noti,
			NOTIFICATION_TEXT_TYPE_CONTENT,
			content,
			NULL, NOTIFICATION_VARIABLE_TYPE_NONE);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_text [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_pkgname(noti, APPNAME);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_pkgname [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_application(noti, MH_NOTI_APP_NAME);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_application [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_insert(noti, &timeout_noti_id);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_insert [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_free(noti);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_free [%d]\n", ret);
		goto FAIL;
	}

	DBG("-\n");
	return MOBILE_AP_ERROR_NONE;

FAIL:
	ret = notification_free(noti);
	if (ret != NOTIFICATION_ERROR_NONE)
		ERR("Fail to notification_free [%d]\n", ret);

	return MOBILE_AP_ERROR_INTERNAL;
}

int _create_connected_noti(const char *content, const char *title,
		const char *icon_path)
{
	DBG("+\n");
	notification_h noti = NULL;
	notification_error_e ret = NOTIFICATION_ERROR_NONE;

	noti = notification_new(NOTIFICATION_TYPE_ONGOING,
			NOTIFICATION_GROUP_ID_NONE, NOTIFICATION_PRIV_ID_NONE);
	if (!noti) {
		ERR("Fail to notification_new [%d]\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = notification_set_property(noti,
			NOTIFICATION_PROP_DISABLE_AUTO_DELETE |
			NOTIFICATION_PROP_VOLATILE_DISPLAY);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_property [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_layout(noti, NOTIFICATION_LY_ONGOING_EVENT);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_image [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_image(noti, NOTIFICATION_IMAGE_TYPE_ICON, icon_path);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_image [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_text(noti,
			NOTIFICATION_TEXT_TYPE_TITLE,
			title,
			NULL, NOTIFICATION_VARIABLE_TYPE_NONE);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_text [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_text(noti,
			NOTIFICATION_TEXT_TYPE_CONTENT,
			content,
			NULL, NOTIFICATION_VARIABLE_TYPE_NONE);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_text [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_pkgname(noti, APPNAME);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_pkgname [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_application(noti, MH_NOTI_APP_NAME);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_application [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_insert(noti, &connected_noti_id);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_insert [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_free(noti);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_free [%d]\n", ret);
		goto FAIL;
	}

	DBG("-\n");
	return MOBILE_AP_ERROR_NONE;

FAIL:
	ret = notification_free(noti);
	if (ret != NOTIFICATION_ERROR_NONE)
		ERR("Fail to notification_free [%d]\n", ret);
	return MOBILE_AP_ERROR_INTERNAL;
}

int _update_connected_noti(const char *content)
{
	DBG("+\n");

	if (content == NULL) {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	notification_h noti = NULL;
	notification_error_e ret = NOTIFICATION_ERROR_NONE;

	noti = notification_load(APPNAME, connected_noti_id);
	if (noti == NULL) {
		ERR("notification_load is failed\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = notification_set_text(noti, NOTIFICATION_TEXT_TYPE_CONTENT,
			content, NULL, NOTIFICATION_VARIABLE_TYPE_NONE);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_text [%d]\n", ret);

		ret = notification_free(noti);
		if (ret != NOTIFICATION_ERROR_NONE)
			ERR("Fail to notification_free [%d]\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = notification_update(noti);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_update [%d]\n", ret);

		ret = notification_free(noti);
		if (ret != NOTIFICATION_ERROR_NONE)
			ERR("Fail to notification_free [%d]\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = notification_free(noti);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_free [%d]\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	DBG("-\n");
	return MOBILE_AP_ERROR_NONE;
}

int _delete_connected_noti(void)
{
	DBG("+\n");
	notification_h noti = NULL;
	notification_error_e ret;

	noti = notification_load(APPNAME, connected_noti_id);
	if (noti == NULL) {
		ERR("notification_load is failed\n");
		connected_noti_id = 0;
		return MOBILE_AP_ERROR_INTERNAL;
	}
	connected_noti_id = 0;

	ret = notification_delete(noti);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_delete [%d]\n", ret);

		ret = notification_free(noti);
		if (ret != NOTIFICATION_ERROR_NONE)
			ERR("Fail to notification_free [%d]\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = notification_free(noti);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_free [%d]\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	DBG("-\n");
	return MOBILE_AP_ERROR_NONE;
}

