#ifndef LOGGING_H
#define LOGGING_H
#include "config.h"

#define LOG_LEVEL (config.verbose)

#ifdef KERNEL_SPACE
#include <linux/kernel.h>
#include <linux/module.h>
#define printf pr_info
#define perror pr_err

#define LOG_ERR KERN_ERR
#define LOG_INFO KERN_INFO
#define LOG_WARN KERN_WARNING

#define log_message(level, msg, ...) \
	(printk(level msg, ##__VA_ARGS__))

#define lgerror(ret, msg, ...) \
	(log_message(LOG_ERR, msg ": %d\n", ##__VA_ARGS__, ret))

#else
#include <stdio.h> // IWYU pragma: export
#include <errno.h>
#include <syslog.h> 

#define log_message(level, msg, ...) \
(config.syslog ? (void)(syslog((level), msg, ##__VA_ARGS__)) : (void)(printf(msg, ##__VA_ARGS__)))

#define lgerror(ret, msg, ...) __extension__ ({			\
	errno = -(ret);						\
	log_message(LOG_ERR, msg ": %s\n", ##__VA_ARGS__, strerror(errno));	\
})
#endif /* PROGRAM_SPACE */

#define lgerr(msg, ...) \
(log_message(LOG_ERR, msg, ##__VA_ARGS__))

#define lgwarning(msg, ...) \
(log_message(LOG_WARN, msg, ##__VA_ARGS__))


#define lginfo(msg, ...) \
(log_message(LOG_INFO, msg, ##__VA_ARGS__))

#define print_message(...) \
(lginfo(__VA_ARGS__))

#define lgdebug(msg, ...) \
(LOG_LEVEL >= VERBOSE_DEBUG ? log_message(LOG_INFO, msg, ##__VA_ARGS__) : (void)0)

#define lgdebugmsg(msg, ...) lgdebug(msg "\n", ##__VA_ARGS__)


#define lgtrace(msg, ...) \
(LOG_LEVEL >= VERBOSE_TRACE ? log_message(LOG_INFO, msg, ##__VA_ARGS__) : (void)0)

#define lgtracemsg(msg, ...) lgtrace(msg "\n", __VA_ARGS__)

#define lgtrace_start(msg, ...) \
(LOG_LEVEL >= VERBOSE_TRACE ? log_message(LOG_INFO, "[TRACE] " msg " ( ", ##__VA_ARGS__) : (void)0)

#define lgtrace_addp(msg, ...) \
(LOG_LEVEL >= VERBOSE_TRACE ? log_message(LOG_INFO, msg", ", ##__VA_ARGS__) : (void)0)

#define lgtrace_end() \
(LOG_LEVEL >= VERBOSE_TRACE ? log_message(LOG_INFO, ") \n") : (void)0)

#endif /* LOGGING_H */
