#ifndef __OS_H_50e2a6b4bce849f794e249a3334cb890__
#define __OS_H_50e2a6b4bce849f794e249a3334cb890__
/******************************************************************************/
#ifndef int8
#define int8            int8_t
#endif

#ifndef uint8
#define uint8           uint8_t
#endif

#ifndef int16
#define int16           int16_t
#endif

#ifndef uint16
#define uint16          uint16_t
#endif

#ifndef int32
#define int32           int32_t
#endif

#ifndef uint32
#define uint32          uint32_t
#endif

#ifndef float32
#define float32         float32_t
#endif

#ifndef int64
#define int64           int64_t
#endif

#ifndef uint64
#define uint64          uint64_t
#endif

#ifndef float64
#define float64         float64_t
#endif

#ifndef uint
#define uint            uint_t
#endif

#ifndef ulong
#define ulong           ulong_t
#endif

#ifndef uintptr
#define uintptr         uintptr_t
#endif

#ifdef  bool
#undef  bool
#endif
#define bool            int

#ifdef  true
#undef  true
#endif
#define true            1

#ifdef  false
#undef  false
#endif
#define false           0

#ifndef byte
#define byte            uint8_t
#endif

/* just for sourceinsight */
#define size_t          size_t
/******************************************************************************/
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <malloc.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <time.h>
#include <math.h>
#include <utime.h>
#include <dirent.h>
#include <syslog.h>
#include <ucontext.h>
#include <byteswap.h>
#include <libgen.h>
#include <netdb.h>
#include <termios.h>
#include <ulimit.h>
#include <utmp.h>
#include <sched.h>
#include <mntent.h>
#include <limits.h>
#include <dlfcn.h>
#include <endian.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timex.h>
#include <sys/utsname.h>
#include <sys/mount.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/inotify.h>
#include <sys/utsname.h>
#include <netpacket/packet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>
/******************************************************************************/
#define os_malloc(_size)            malloc(_size)
#define os_calloc(_count, _size)    calloc(_count, _size)
#define os_realloc(_ptr, _size)     realloc(_ptr, _size)
#define os_free(_ptr)   do{ \
    if (_ptr) {             \
        free(_ptr);         \
        (_ptr) = NULL;      \
    } \
}while(0)

#ifndef OS_ALIGN
#define OS_ALIGN(_x, _align)            (((_x)+(_align)-1) & ~((_align)-1))
#endif

#ifndef os_do_nothing
#define os_do_nothing()                 do{}while(0)
#endif

#ifndef is_good_value
#define is_good_value(_v, _begin, _end) ((_v) >= (_begin) && (_v) < (_end))
#endif

#ifndef is_good_enum
#define is_good_enum(_id, _end)         is_good_value(_id, 0, _end)
#endif

#ifndef __space
#define __space         " "
#endif

#ifndef __tab
#define __tab           __space __space __space __space
#endif

#ifndef __tab2
#define __tab2          __tab __tab
#endif

#ifndef __tab3
#define __tab3          __tab2 __tab
#endif

#ifndef __tab4
#define __tab4          __tab3 __tab
#endif

#ifndef __crlf
#define __crlf          "\n"
#endif

#ifndef __crlf2
#define __crlf2         __crlf __crlf
#endif

#ifndef __crlf3
#define __crlf3         __crlf2 __crlf
#endif

#ifndef __crlf4
#define __crlf4         __crlf3 __crlf
#endif

#ifndef __notes
#define __notes         "#"
#endif

#ifndef __unknow
#define __unknow        "unknow"
#endif

#ifndef __true
#define __true          "true"
#endif

#ifndef __false
#define __false         "false"
#endif

#ifndef __success
#define __success       "success"
#endif

#ifndef __failed
#define __failed        "failed"
#endif

#ifndef __yes
#define __yes           "yes"
#endif

#ifndef __no
#define __no            "no"
#endif

#ifndef bool_string
#define bool_string(_is_ture)                       ((_is_ture)?__true:__false)
#endif

#ifndef success_string
#define success_string(_is_ture)                    ((_is_ture)?__success:__failed)
#endif

#ifndef yes_string
#define yes_string(_is_ture)                        ((_is_ture)?__yes:__no)
#endif

#ifndef os_println
#define os_println(_fmt, _args...)                  os_printf(_fmt __crlf, ##_args)
#endif

#ifndef os_snprintf
#define os_snprintf(_buf, _size, _fmt,_args...)     snprintf(_buf, _size, _fmt, ##_args)
#endif

/*
* snprintf for array buffer + offset
*/
#ifndef os_soprintf
#define os_soprintf(_buf, _offset, _fmt, _args...)  os_snprintf(_buf+(_offset), sizeof(_buf)-(_offset), _fmt, ##_args)
#endif

/*
* snprintf for array buffer
*/
#ifndef os_saprintf
#define os_saprintf(_buf, _fmt, _args...)           os_snprintf(_buf, sizeof(_buf), _fmt, ##_args)
#endif

/*
* just for single-thread, unsafe for multi-thread
*
* @ip: network sort
*/
static inline char *
os_ipstring(uint32 ip)
{
    struct in_addr in = {.s_addr = ip};
    
    return (char *)inet_ntoa(in);
}

static inline char *
os_time_string(time_t t)
{
    static char current[1+sizeof("1900-01-01#00:00:00")];

    struct tm *tm = gmtime(&t);

    os_saprintf(current, "%04d-%02d-%02d#%02d:%02d:%02d",
                1900 + tm->tm_year,
                1 + tm->tm_mon,
                tm->tm_mday,
                tm->tm_hour,
                tm->tm_min,
                (61==tm->tm_sec)?59:tm->tm_sec);

    return current;
}

#include "dump.h"
/******************************************************************************/
#endif
