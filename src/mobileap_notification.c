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
#include <notification.h>

#include "mobileap_agent.h"


#define NOTI_PRIV_ID 0

notification_h _create_notification(void)
{
	DBG("+\n");
	notification_h noti = NULL;
	notification_error_e ret = NOTIFICATION_ERROR_NONE;

	noti = notification_new(NOTIFICATION_TYPE_NOTI, -1, NOTI_PRIV_ID);
	if (!noti) {
		ERR("Fail to notification_new [%d]\n", ret);
		return NULL;
	}

	ret = notification_set_property(noti,
			NOTIFICATION_PROP_DISABLE_AUTO_DELETE | NOTIFICATION_PROP_VOLATILE_DISPLAY);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_property [%d]\n", ret);
		return NULL;
	}

	DBG("-\n");
	return noti;
}

int _insert_notification(notification_h noti,
				char *title,
				char *content,
				char *icon_path)
{
	DBG("+\n");
	notification_error_e ret;

	if (!noti)
		return MOBILE_AP_ERROR_INVALID_PARAM;

	DBG("Insert noti : %d \n", noti);

	ret = notification_set_image(noti, NOTIFICATION_IMAGE_TYPE_ICON, icon_path);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_image [%d]\n", ret);
		goto error;
	}

	ret = notification_set_text(noti, NOTIFICATION_TEXT_TYPE_TITLE,
				title, NULL, NOTIFICATION_VARIABLE_TYPE_NONE);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_text [%d]\n", ret);
		goto error;
	}

	ret = notification_set_text(noti, NOTIFICATION_TEXT_TYPE_CONTENT,
				content, NULL, NOTIFICATION_VARIABLE_TYPE_NONE);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_text [%d]\n", ret);
		goto error;
	}

	ret = notification_insert(noti, NULL);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_insert [%d]\n", ret);
		goto error;
	}

	ret = notification_free(noti);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_free [%d]\n", ret);
		goto error;
	}

	DBG("-\n");
	return ret;

error:
	return MOBILE_AP_ERROR_INTERNAL;
}

int _delete_notification(void)
{
	DBG("+\n");
	notification_error_e ret;

	ret = notification_delete_all_by_type(NULL, NOTIFICATION_TYPE_NOTI);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_delete_all_by_type [%d]\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	DBG("-\n");
	return MOBILE_AP_ERROR_NONE;
}


int _set_notification_app_launch(notification_h noti)
{
	DBG("+\n");
	notification_error_e ret;

	if (!noti)
		return MOBILE_AP_ERROR_INVALID_PARAM;

	ret = notification_set_application(noti, "org.tizen.tethering");
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_application [%d]\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	DBG("-\n");
	return MOBILE_AP_ERROR_NONE;
}

