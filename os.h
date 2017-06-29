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
#ifndef OS_IFNAME_LEN
#define OS_IFNAME_LEN           (16 - 1)
#endif

#ifndef OS_LINE_SHORT
#define OS_LINE_SHORT           (128 - 1)
#endif

#ifndef OS_LINE_LEN
#define OS_LINE_LEN             (1*1024 - 1)
#endif

#ifndef OS_PAGE_LEN
#define OS_PAGE_LEN             (4*1024 - 1)
#endif

#ifndef OS_BLOCK_LEN
#define OS_BLOCK_LEN            (16*1024 - 1)
#endif

#ifndef OS_FILE_LEN
#define OS_FILE_LEN             (64*1024 - 1)
#endif

#ifndef OS_BIG_LEN
#define OS_BIG_LEN              (256*1024 - 1)
#endif

#ifndef OS_HUGE_LEN
#define OS_HUGE_LEN             (1024*1024 - 1)
#endif

#ifndef OS_FILENAME_LEN
#define OS_FILENAME_LEN         OS_LINE_LEN
#endif

#define os_malloc(_size)            malloc(_size)
#define os_calloc(_count, _size)    calloc(_count, _size)
#define os_realloc(_ptr, _size)     realloc(_ptr, _size)
#define os_free(_ptr)   do{ \
    if (_ptr) {             \
        free(_ptr);         \
        (_ptr) = NULL;      \
    } \
}while(0)

#ifndef os_count_of
#define os_count_of(x)                  (sizeof(x)/sizeof((x)[0]))
#endif

#ifndef OS_ALIGN
#define OS_ALIGN(_x, _align)            (((_x)+(_align)-1) & ~((_align)-1))
#endif

#ifndef os_objscpy
#define os_objscpy(_dst, _src)          memcpy(_dst, _src, sizeof(*(_src)))
#endif

#ifndef os_objdcpy
#define os_objdcpy(_dst, _src)          memcpy(_dst, _src, sizeof(*(_dst)))
#endif

#ifndef os_objcpy
#define os_objcpy(_dst, _src)           os_objdcpy(_dst, _src)
#endif

#ifndef os_do_nothing
#define os_do_nothing()                 do{}while(0)
#endif

#ifndef os_extern_unused_var
#define os_extern_unused_var            extern int ____os_extern_unused_var____
#endif

#ifndef is_good_value
#define is_good_value(_v, _begin, _end) ((_v) >= (_begin) && (_v) < (_end))
#endif

#ifndef is_good_enum
#define is_good_enum(_id, _end)         is_good_value(_id, 0, _end)
#endif

#ifndef os_min
#define os_min(_x, _y)  ((_x)<(_y)?(_x):(_y))
#endif

#ifndef os_max
#define os_max(_x, _y)  ((_x)>(_y)?(_x):(_y))
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
#define os_println(_fmt, _args...)                  printf(_fmt __crlf, ##_args)
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

static inline bool
is_option_args(char *args)
{
    return args && args[0] && args[1] && args[2] && '-'==args[0] && '-'==args[1];
}

typedef FILE* STREAM;

#define os_fopen(_file, _mode)      fopen(_file, _mode)
#define os_feof(_stream)            (_stream?!!feof(_stream):true)
#define os_fflush(_stream)          fflush(_stream)
#define os_ferror(_stream)          ferror(_stream)
#define os_fdopen(_fd, _flag)       fdopen(_fd, _flag)

static inline int
os_fsize(const char *file)
{
    struct stat st;
    int err;
    
    err = stat(file, &st);
    if (err<0) {
        return -errno;
    } else {
        return st.st_size;
    }
}

static inline int
os_fread(STREAM stream, void *buf, int size)
{
    int err = fread(buf, 1, size, stream);

    return (err<0)?-errno:err;
}

static inline int
os_fwrite(STREAM stream, const void *buf, int size)
{
    int err = fwrite(buf, 1, size, stream);
    
    os_fflush(stream);
    
    return (err<0)?-errno:err;
}

static inline int
os_readfile(const char *file, void *buf, int size)
{
    STREAM f = NULL;
    int err = 0;

    f = os_fopen(file, "r");
    if (NULL==f) {
        err = -errno; goto error;
    }

    int len = os_fread(f, buf, size);
    if (size!=len) {
        err = -errno; goto error;
    }

error:
    fclose(f);

    return err;
}

static inline int
os_readfileall(const char *file, char **content, uint32 *filesize)
{
    char *buf = NULL;
    int size, err = 0;
    
    size = os_fsize(file);
    if (size<0) {
        goto error;
    }

    buf = (char *)os_malloc(size);
    if (NULL==buf) {
        goto error;
    }
    
    err = os_readfile(file, buf, size);
    if (err<0) {
        goto error;
    }

    *filesize   = size;
    *content    = buf;
    
    return err;
error:
    os_free(buf);

    return err;
}


#ifndef OS_BKDR_NUMBER
#define OS_BKDR_NUMBER      31
#endif

typedef uint32 bkdr_t;
#define BKDR_PUSH(a, b)     ((a) * OS_BKDR_NUMBER + (b))

static inline bkdr_t
os_bkdr_push(bkdr_t bkdr, const void *binary, uint32 len)
{
    if (binary && len) {
        int i;

        for (i=0; i<len; i++) {
            bkdr = BKDR_PUSH(bkdr, *((byte *)binary + i));
        }
    }

    return bkdr;
}

static inline bkdr_t
os_bkdr(const void *binary, uint32 len)
{
    return os_bkdr_push(0, binary, len);
}
/******************************************************************************/
#include "dump.h"
#include "sha2.h"
/******************************************************************************/
/*
* return:
*   <= 0: error
*     >0: success, file size
*/
static inline int
os_fdigest(const char *file, byte digest[])
{
    char *buf = NULL;
    int size, err = 0;
    
    size = os_fsize(file);
    if (size<0) {
        goto error;
    }

    buf = (char *)os_malloc(size);
    if (NULL==buf) {
        goto error;
    }
    
    err = os_readfile(file, buf, size);
    if (err<0) {
        goto error;
    }

    sha256(buf, size, digest);
    
    return size;
error:
    os_free(buf);

    return err;
}
/******************************************************************************/
#endif
