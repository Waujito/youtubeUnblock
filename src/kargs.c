/*
  youtubeUnblock - https://github.com/Waujito/youtubeUnblock

  Copyright (C) 2024-2025 Vadim Vetrov <vetrovvd@gmail.com>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "config.h"
#include "types.h"
#include <linux/moduleparam.h>
#include "types.h"
#include "args.h"
#include "logging.h"

#define MAX_ARGC 1024
static char *argv[MAX_ARGC];

static int params_set(const char *cval, const struct kernel_param *kp) {
	int ret = 0;

	int cv_len = strlen(cval);
	if (cv_len >= 1 && cval[cv_len - 1] == '\n') {
		cv_len--;
	}

	const char *ytb_prefix = "youtubeUnblock ";
	int ytbp_len = strlen(ytb_prefix);
	int len = cv_len + ytbp_len; 

	char *val = kmalloc(len + 1, GFP_KERNEL); // 1 for null-terminator
	strncpy(val, ytb_prefix, ytbp_len);
	strncpy(val + ytbp_len, cval, cv_len);
	val[len] = '\0';

	int argc = 0;
	argv[argc++] = val;
	
	for (int i = 0; i < len; i++) {
		if (val[i] == ' ') {
			val[i] = '\0';

			// safe because of null-terminator
			if (val[i + 1] != ' ' && val[i + 1] != '\0') {
				argv[argc++] = val + i + 1;
			}
		}
	}

	ret = yparse_args(argc, argv);
	kfree(val);
	return ret;
}

static int params_get(char *buffer, const struct kernel_param *kp) {
	size_t len = print_config(buffer, 4000);
	return len;
}

static const struct kernel_param_ops params_ops = {
	.set = params_set,
	.get = params_get,
};

module_param_cb(parameters, &params_ops, NULL, 0664);
