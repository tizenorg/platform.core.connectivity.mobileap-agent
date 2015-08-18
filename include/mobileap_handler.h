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

#ifndef __MOBILEAP_HANDLER_H__
#define __MOBILEAP_HANDLER_H__

#include <time.h>
#include <alarm.h>

typedef struct {
	void *obj;
	unsigned int state;
} changed_state_t;

void _register_vconf_cb(void *user_data);
void _unregister_vconf_cb(void);

gboolean _is_power_save_survival_mode(void);
int _sp_timeout_handler(alarm_id_t alarm_id, void *user_param);
void _init_timeout_cb(mobile_ap_type_e type, void *user_data);
void _start_timeout_cb(mobile_ap_type_e type, time_t end_time);
void _stop_timeout_cb(mobile_ap_type_e type);
void _deinit_timeout_cb(mobile_ap_type_e type);

#endif
