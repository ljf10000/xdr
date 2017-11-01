#ifndef __OS_H_50e2a6b4bce849f794e249a3334cb890__
#define __OS_H_50e2a6b4bce849f794e249a3334cb890__
#include "error.h"
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

#ifndef lanmbda
#define lanmbda(_type, _body)   ({ _type _lanmbda _body _lanmbda; })
#endif

#ifndef ilanmbda
#define ilanmbda(_type, _body)  lanmbda(int, _body)
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

#ifndef os_memzero
#define os_memzero(_obj, _size)         memset(_obj, 0, _size)
#endif

#ifndef os_objzero
#define os_objzero(_obj)                os_memzero(_obj, sizeof(*(_obj)))
#endif

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

#ifndef os_fake_declare
#define os_fake_declare                 extern int __os_value_not_used_forever
#endif

#ifndef is_good_value
#define is_good_value(_v, _begin, _end) ((_v) >= (_begin) && (_v) < (_end))
#endif

#ifndef is_good_enum
#define is_good_enum(_id, _end)         is_good_value(_id, 0, _end)
#endif

#ifndef is_good_fd
#define is_good_fd(_fd)                 ((_fd)>=0)
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

#ifndef __error
#define __error         "error"
#endif

#ifndef __ok
#define __ok            "ok"
#endif

#ifndef bool_string
#define bool_string(_is_ture)                       ((_is_ture)?__true:__false)
#endif

#ifndef success_string
#define success_string(_is_success)                 ((_is_success)?__success:__failed)
#endif

#ifndef yes_string
#define yes_string(_is_yes)                         ((_is_yes)?__yes:__no)
#endif

#ifndef ok_string
#define ok_string(_err)                             (0==(_err)?__ok:__error)
#endif

#ifndef os_printf
#define os_printf(_fmt, _args...)                   printf(_fmt, ##_args)
#endif

#ifndef os_println
#define os_println(_fmt, _args...)                  printf(_fmt __crlf, ##_args)
#endif

#ifndef os_trace
#define os_trace(_print, _call, _fmt, _args...) ({  \
    int __err;                                  \
    _print("try " _fmt " ...", ##_args);        \
    __err = (_call);                            \
    _print(__tab "%s:%d " _fmt, ok_string(__err), __err, ##_args); \
    __err;                                      \
})  /* end */
#endif

#ifndef os_sprintf
#define os_sprintf(_buf, _fmt, _args...)            sprintf(_buf, _fmt, ##_args)
#endif

#ifndef os_vsprintf
#define os_vsprintf(_buf, _fmt, _args)              vsprintf(_buf, _fmt, _args)
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

#ifndef os_assert
#define os_assert(x)            assert(x)
#endif

#ifndef os_assertV
#define os_assertV(_x)          (os_assert(0), _x)
#endif

#if 0
/*
* ENUM: c enum macro
*
*/
#define XXX_ENUM_MAPPER(_) \
    _(NAME_A, VALUE_A), \
    _(NAME_A, VALUE_B), \
    _(NAME_A, VALUE_C), \
    /* end */
DECLARE_ENUM(MOD, mod, MOD_ENUM_MAPPER, MOD_END);

static inline enum_ops_t *mod_ops(void);
static inline bool is_good_mod(int id);
static inline char *mod_getnamebyid(int id);
static inline int mod_getidbyname(const char *name);

#define MOD_NAME_A      MOD_NAME_A
#define MOD_NAME_B      MOD_NAME_B
#define MOD_NAME_C      MOD_NAME_C
#define MOD_END         MOD_END
#endif

#define __ENUM_MAP_VALUE(_MOD, _name, _value)   _MOD##_##_name = _value
#define __ENUM_MAP_NAME(_MOD, _name, _value)    [_MOD##_##_name] = #_name

#define DECLARE_ENUM(_MOD, _mod, _mapper, _end) \
    enum {                          \
        _mapper(__ENUM_MAP_VALUE)   \
                                    \
        _end                        \
    };                              \
                                    \
    static inline bool              \
    is_good_##_mod(int id)          \
    {                               \
        return is_good_enum(id, _end); \
    }                               \
                                    \
    static inline char **           \
    _mod##_strings(void)            \
    {                               \
        static char *array[_end] = { _mapper(__ENUM_MAP_NAME) }; \
                                    \
        return array;               \
    }                               \
                                    \
    static inline char *            \
    _mod##_getnamebyid(int id)      \
    {                               \
        char **array = _mod##_strings(); \
                                    \
        return is_good_##_mod(id)?array[id]:__unknow; \
    }                               \
                                    \
    static inline int               \
    _mod##_getidbyname(const char *s) \
    {                               \
        char **array = _mod##_strings(); \
                                    \
        return os_array_search_str(array, s, 0, _end); \
    }                               \
                                    \
    os_fake_declare                 \
    /* end */
    

enum {
    __MV_GO             = 0,
    __MV_BREAK          = 1,
};

typedef int32 mv_t;

typedef union {
    mv_t v;

    struct {
        int32 error:24;
        int32 control:8;
    } v2;
    
    struct {
        int32 error:16;
        int32 control:8;
        int32 private:8;
    } v3;
    
    struct {
        int32 error:8;
        int32 control:8;
        int32 private:8;
        int32 value:8;
    } v4;
}
mv_u;

#define MV_INITER               { .v = 0 }

#define mv2_error(_mv)          (_mv).v2.error
#define mv2_control(_mv)        (_mv).v2.control
#define __mv2_INITER(_control, _error)  { \
    .v2 = {                 \
        .error  = _error,   \
        .control= _control, \
    }                       \
}

static inline mv_t 
__mv2_return(int control, int error)
{
    mv_u mv = __mv2_INITER(control, error);

    return mv.v;
}

#define mv2_break(_result)      __mv2_return(__MV_BREAK, _result)
#define mv2_go(_result)         __mv2_return(__MV_GO, _result)
enum { mv2_ok = 0 };

#define is_mv2_break(_mv)       (__MV_BREAK==mv2_control(_mv))
#define is_mv2_go(_mv)          (__MV_GO==mv2_control(_mv))

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
    return args 
        && '-'==args[0]
        && '-'==args[1]
        && args[2];
}

static inline bool
os_fexist(const char *file)
{
    int fd = open(file, O_RDONLY, S_IRUSR | S_IRGRP);

    return fd<0?false:(close(fd), true);
}

static inline int
os_fsize(const char *file)
{
    struct stat st;

    return 0==stat(file, &st)?st.st_size:-errno;
}

static inline void *
os_mmap(char *file, size_t length, off_t offset, bool readonly)
{
    int fflag = readonly?O_RDONLY:(O_CREAT|O_RDWR);
    int mflag = readonly?MAP_PRIVATE:MAP_SHARED;
    int prot  = readonly?PROT_READ:(PROT_READ|PROT_WRITE);

    int fd = open(file, fflag);
    if (fd<0) {
        return NULL;
    }

    if (0==length) {
        length = os_fsize(file);
    }

    if (!readonly) {
        ftruncate(fd, length);
    }

    void *buffer = mmap(NULL, length, prot, mflag, fd, offset);
    close(fd);

    return buffer;
}

static inline int
os_mmap_w(char *file, void *buf, int len, int flag)
{
    void *mem = os_mmap(file, len, 0, false);
    if (NULL==mem) {
        return -errno;
    }

    memcpy(mem, buf, len);
    msync(mem, len, flag);
    munmap(mem, len);

    return 0;
}

static inline int
os_mmap_w_sync(char *file, void *buf, int len)
{
    return os_mmap_w(file, buf, len, MS_SYNC);
}

static inline int
os_mmap_w_async(char *file, void *buf, int len)
{
    return os_mmap_w(file, buf, len, MS_ASYNC);
}

static inline int
os_mmap_r(char *file, int (*handle)(void *buf, int len))
{
    int size = os_fsize(file);
    if (size<0) {
        return size;
    }
    
    void *mem = os_mmap(file, size, 0, true);
    if (NULL==mem) {
        return -errno;
    }

    int err = (*handle)(mem, size);

    munmap(mem, size);

    return err;
}

#ifndef os_array_search
#define os_array_search(_array, _obj, _cmp, _begin, _end) ({ \
    int i;              \
    int idx = (_end);   \
                        \
    for (i=(_begin); i<(_end); i++) {   \
        if (0==_cmp((_array)[i], _obj)) { \
            idx = i;    \
            break;      \
        }               \
    }                   \
                        \
    idx;                \
})  /* end */
#endif

#define os_array_search_str(_array, _string, _begin, _end) \
    os_array_search(_array, _string, strcmp, _begin, _end)

#define UXXCMP(_type, _a, _b)   (*(_type *)(_a) == *(_type *)(_b))
#define U16CMP(_a, _b)          UXXCMP(uint16, _a, _b)
#define U32CMP(_a, _b)          UXXCMP(uint32, _a, _b)
#define U64CMP(_a, _b)          UXXCMP(uint64, _a, _b)

static inline bool
OS_HAS_SUFFIX(char *s, int len, char *suffix, int suffix_len)
{
    return (len > suffix_len)?U32CMP(s + len - suffix_len, suffix):false;
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
    int handle(void *buf, int len)
    {
        sha256((const byte *)buf, len, digest);

        return 0;
    }
    
    return os_mmap_r((char *)file, handle);
}

static inline int
os_chex2int(int ch)
{
    switch(ch) {
        case '0' ... '9':
            return ch - '0';
        case 'a' ... 'f':
            return ch - 'a' + 10;
        case 'A' ... 'F':
            return ch - 'A' + 10;
        default:
            return os_assertV(0);
    }
}

static inline int
os_hex2bin(char *hex, byte *buf, int size)
{
    int i;
    int len = strlen(hex);

    if (len%2) {
        return -EBADHEX;
    }
    else if ((size + size) < len) {
        return -ENOSPACE;
    }

    int hexlen = len/2;
    for (i=0; i<hexlen; i++) {
        buf[i] = 16 * os_chex2int(hex[2*i]) + os_chex2int(hex[2*i+1]);
    }

    return hexlen;
}

static inline int
os_bin2hex(char *hex, int space, byte *buf, int size)
{
    int i, len = size+size;
    
    if (len < space) {
        return -ENOSPACE;
    }

    for (i=0; i<size; i++) {
        os_sprintf(hex + 2*i, "%.2X", buf[i]);
    }
    hex[len] = 0;
    
    return len;
}

typedef struct inotify_event inotify_ev_t;

#define INOTIFY_EVSIZE  (sizeof(inotify_ev_t) + NAME_MAX + 1)

static inline inotify_ev_t *
inotify_ev_next(inotify_ev_t *ev)
{
    return (inotify_ev_t *)((char *)ev + sizeof(inotify_ev_t) + ev->len);
}

static inline int 
inotify_ev_len(inotify_ev_t *ev)
{
    char *p = ev->name + ev->len;

    do{}while(0==*--p);

    return p - ev->name + 1;
}
/******************************************************************************/
#endif
