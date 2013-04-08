/*
 * mobileap-agent
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
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

#ifndef __MOBILEAP_CONNMAN_H__
#define __MOBILEAP_CONNMAN_H__

#include "mobileap_agent.h"

enum technology_type {
	TECH_TYPE_WIFI,
	TECH_TYPE_BLUETOOTH,
	TECH_TYPE_USB,
	TECH_TYPE_MAX,
};

#define CONNMAN_MANAGER_PATH		"/"
#define CONNMAN_SERVICE			"net.connman"
#define CONNMAN_TECHNOLOGY_INTERFACE	"net.connman.Technology"
#define CONNMAN_MANAGER_INTERFACE	"net.connman.Manager"

int connman_enable_tethering(enum technology_type type, const char *ssid,
			const char *security, const char *key, int hide_mode);
int connman_disable_tethering(enum technology_type type);
#endif
