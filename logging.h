#ifndef LOGGING_H
#define LOGGING_H
#include "config.h"

#define LOG_LEVEL (config.verbose)

#ifdef KERNEL_SPACE
#include <linux/printk.h>
#define printf pr_info
#define perror pr_err
#define lgerror(msg, ret, ...) __extension__ ({		\
	printf(msg ": %d\n", ##__VA_ARGS__, ret);	\
})
#else
#include <stdio.h> // IWYU pragma: export
#include <errno.h>
#define lgerror(msg, ret, ...) __extension__ ({			\
	errno = -(ret);						\
	printf(msg ": %s\n", ##__VA_ARGS__, strerror(errno));	\
})
#endif /* PROGRAM_SPACE */

#define lgdebug(msg, ...) \
(LOG_LEVEL >= VERBOSE_DEBUG ? printf(msg, ##__VA_ARGS__) : 0)

#define lgdebugmsg(msg, ...) lgdebug(msg "\n", ##__VA_ARGS__)


#define lgtrace(msg, ...) \
(LOG_LEVEL >= VERBOSE_TRACE ? printf(msg, ##__VA_ARGS__) : 0)

#define lgtracemsg(msg, ...) lgtrace(msg "\n", __VA_ARGS__)

#define lgtrace_start(msg, ...) \
(LOG_LEVEL >= VERBOSE_TRACE ? printf("[TRACE] " msg " ( ", ##__VA_ARGS__) : 0)

#define lgtrace_addp(msg, ...) \
(LOG_LEVEL >= VERBOSE_TRACE ? printf(msg", ", ##__VA_ARGS__) : 0)

#define lgtrace_end() \
(LOG_LEVEL >= VERBOSE_TRACE ? printf(") \n") : 0)

#endif /* LOGGING_H */
