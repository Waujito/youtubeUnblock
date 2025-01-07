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

#ifndef LOGGING_H
#define LOGGING_H
#include "config.h"

#ifdef KERNEL_SPACE
#include <linux/kernel.h>
#include <linux/module.h>
#define printf pr_info
#define perror pr_err

#define LOG_ERR KERN_ERR
#define LOG_INFO KERN_INFO
#define LOG_WARN KERN_WARNING

#define print_message(level, msg, ...) \
	(printk(level msg, ##__VA_ARGS__))

#else
#include <stdio.h> // IWYU pragma: export
#include <errno.h>
#include <syslog.h> 

#define print_message(level, msg, ...) \
	(config.syslog ? (void)(syslog((level), msg, ##__VA_ARGS__)) : (void)(printf(msg, ##__VA_ARGS__) + fflush(stdout)))

#endif /* PROGRAM_SPACE */

/**
 * Defined in args.c
 */
#define LOGGING_BUFSIZE 4096
extern char ylgh_buf[LOGGING_BUFSIZE];
extern size_t ylgh_leftbuf;
extern char *ylgh_curptr;
extern int ylgh_ndnl;

#define LOG_LEVEL (config.verbose)

/**
 * For flushing only. Use log_buf_write for writing.
 */
#define log_buf_flush(level) __extension__ ({		\
	if (ylgh_leftbuf != LOGGING_BUFSIZE) {		\
		print_message(level, "%s", ylgh_buf);\
		ylgh_curptr = ylgh_buf;		\
		ylgh_leftbuf = LOGGING_BUFSIZE;		\
	}						\
})

#define log_buf(level, msg, ...) __extension__ ({			\
	int lgrtrt;							\
	lgrtrt=snprintf(ylgh_curptr, ylgh_leftbuf, msg, ##__VA_ARGS__);	\
	if (lgrtrt < 0 || lgrtrt >= ylgh_leftbuf) {			\
		ylgh_leftbuf = 0;					\
		log_buf_flush(level);					\
	} else {							\
		ylgh_leftbuf -= lgrtrt;					\
		ylgh_curptr += lgrtrt;				\
	}								\
})

#define log_buf_write(level) __extension__ ({		\
	if (ylgh_ndnl) {				\
		log_buf(level, "\n");			\
		ylgh_ndnl = 0;				\
	}						\
	log_buf_flush(level);				\
})

#define log_message(level, msg, ...) __extension__ ({			\
	if (ylgh_leftbuf != LOGGING_BUFSIZE) {				\
		log_buf_write(LOG_INFO);				\
		log_buf(level, "[NOTICE] ");				\
	}								\
	log_buf(level, msg, ##__VA_ARGS__);				\
	ylgh_ndnl = 1;							\
	log_buf_write(level);						\
})

#ifdef KERNEL_SPACE
#define lgerror(code, msg, ...) \
	(log_message(LOG_ERR, msg ": %d", ##__VA_ARGS__, code))
#else
#define lgerror(code, msg, ...) \
	log_message(LOG_ERR, msg ": %s", ##__VA_ARGS__, strerror(-code));
#endif


#define lgerr(msg, ...) \
(log_message(LOG_ERR, msg, ##__VA_ARGS__))

#define lgwarning(msg, ...) \
(log_message(LOG_WARN, msg, ##__VA_ARGS__))


#define lginfo(msg, ...) \
(log_message(LOG_INFO, msg, ##__VA_ARGS__))

#define lgdebug(msg, ...) \
(LOG_LEVEL >= VERBOSE_DEBUG ? log_message(LOG_INFO, msg, ##__VA_ARGS__) : (void)0)

#define lgtrace(msg, ...) \
(LOG_LEVEL >= VERBOSE_TRACE ? log_message(LOG_INFO, msg, ##__VA_ARGS__) : (void)0)

#define lgtrace_start() \
	lgtrace("---[TRACE PACKET START]---")

#define lgtrace_wr(msg, ...)  __extension__ ({			\
	if (LOG_LEVEL >= VERBOSE_TRACE) {			\
		ylgh_ndnl = 1;					\
		log_buf(LOG_INFO, msg, ##__VA_ARGS__);		\
		if (config.instaflush) {			\
			log_buf_flush(LOG_INFO);		\
		}						\
	}							\
})

#define lgtrace_addp(msg, ...) \
	lgtrace_wr(msg ", ", ##__VA_ARGS__)

#define lgtrace_write() \
	(LOG_LEVEL >= VERBOSE_TRACE ? log_buf_write(LOG_INFO) : (void)0)

#define lgtrace_end() __extension__ ({		\
	if (LOG_LEVEL >= VERBOSE_TRACE) {	\
		log_buf_write(LOG_INFO);	\
		print_message(LOG_INFO, "\n");	\
	}					\
})

#endif /* LOGGING_H */
