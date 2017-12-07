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
#define __STDC_FORMAT_MACROS

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
#include <inttypes.h>
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
#include <pthread.h>
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
/* Force a compilation error if condition is true, but also produce a
   result (of value 0 and type size_t), so the expression can be used
   e.g. in a structure initializer (or where-ever else comma expressions
   aren't permitted). */
#ifndef BUILD_BUG_ON
#define BUILD_BUG_ON(_condition)            (void)sizeof(struct { int:-!!(_condition); })
#endif

#ifndef BUILD_BUG_NOT_ARRAY
#define BUILD_BUG_NOT_ARRAY(_array)         BUILD_BUG_ON(sizeof(_array)==sizeof(void *))
#endif

#ifndef BUILD_BUG_NOT_OBJECT
#define BUILD_BUG_NOT_OBJECT(_obj)          BUILD_BUG_ON(sizeof(_obj)==sizeof(void *))
#endif

#ifndef offsetof
#define offsetof(_TYPE, _MEMBER)            __builtin_offsetof(_TYPE, _MEMBER)
#endif

#ifndef container_of
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the container.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(_ptr, _type, _member) \
	    ((_type *)((char *)(_ptr) - offsetof(_type, _member)))
#endif

#ifndef os_count_of
#define os_count_of(x)              (sizeof(x)/sizeof((x)[0]))
#endif

#define SYMBOL_TO_STRING_HELPER(x)  #x
#define SYMBOL_TO_STRING(x)         SYMBOL_TO_STRING_HELPER(x)

#ifndef OS_ALIGN
#define OS_ALIGN(_x, _align)        (((_x)+(_align)-1) & ~((_align)-1))
#endif
#define OS_FORMAT_SIZE(_fmt)        OS_ALIGN(sizeof(_fmt), 4)

#ifndef OS_ALIGNED
#define OS_ALIGNED(_align)          __attribute__ ((aligned (_align)))
#endif

#ifndef OS_ALIGNP
#define OS_ALIGNP                   OS_ALIGNED(sizeof(void *))
#endif

#ifndef NO_ALIGN
#define NO_ALIGN                    OS_ALIGNED(1)
#endif

#ifndef OS_PAGESIZE
#define OS_PAGESIZE                 (4*1024)
#endif

#ifndef OS_CACHELINE
#define OS_CACHELINE                64
#endif

#ifndef OS_CACHEALIGN
#define OS_CACHEALIGN               OS_ALIGNED(OS_CACHELINE)
#endif

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
#define bool_string(_is_ture)           ((_is_ture)?__true:__false)
#endif

#ifndef success_string
#define success_string(_is_success)     ((_is_success)?__success:__failed)
#endif

#ifndef yes_string
#define yes_string(_is_yes)             ((_is_yes)?__yes:__no)
#endif

#ifndef ok_string
#define ok_string(_err)                 ((_err)<0?__error:__ok)
#endif

#define os_malloc(_size)            malloc(_size)
#define os_calloc(_count, _size)    calloc(_count, _size)
#define os_realloc(_ptr, _size)     realloc(_ptr, _size)
#define os_free(_ptr)   do{ \
    if (_ptr) {             \
        free(_ptr);         \
        _ptr = NULL;        \
    } \
}while(0)

#ifndef os_memzero
#define os_memzero(_obj, _size)     memset(_obj, 0, _size)
#endif

#ifndef os_objzero
#define os_objzero(_obj)            os_memzero(_obj, sizeof(*(_obj)))
#endif

#ifndef os_objscpy
#define os_objscpy(_dst, _src)      memcpy(_dst, _src, sizeof(*(_src)))
#endif

#ifndef os_objdcpy
#define os_objdcpy(_dst, _src)      memcpy(_dst, _src, sizeof(*(_dst)))
#endif

#ifndef os_objcpy
#define os_objcpy(_dst, _src)       os_objdcpy(_dst, _src)
#endif

#ifndef os_do_nothing
#define os_do_nothing()             do{}while(0)
#endif

#ifndef os_fake_declare
#define os_fake_declare             extern int __the_value_not_used_forever
#endif

#ifndef is_good_value
#define is_good_value(_v, _begin, _end) ((_v) >= (_begin) && (_v) < (_end))
#endif

#ifndef is_good_enum
#define is_good_enum(_id, _end)         is_good_value(_id, 0, _end)
#endif

#ifndef os_close
#define os_close(_fd)   ({  \
    int m_err = 0;          \
    if ((_fd)>=0) {         \
        m_err = close(_fd); \
        _fd = -1;           \
    }                       \
                            \
    m_err;                  \
})  /* end */
#endif

#ifndef os_fclose
#define os_fclose(_stream)   ({  \
    int m_err = 0;          \
    if (_stream) {          \
        m_err = fclose(_stream); \
        _stream = NULL;     \
    }                       \
                            \
    m_err;                  \
})  /* end */
#endif

#ifndef os_min
#define os_min(_x, _y)  ((_x)<(_y)?(_x):(_y))
#endif

#ifndef os_max
#define os_max(_x, _y)  ((_x)>(_y)?(_x):(_y))
#endif

#ifndef os_printf
#define os_printf(_fmt, _args...)                   printf(_fmt, ##_args)
#endif

#ifndef os_println
#define os_println(_fmt, _args...)                  printf(_fmt __crlf, ##_args)
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
*/
#define XXX_ENUM_MAPPER(_)  \
    _(MOD, NAME_A, VALUE_A) \
    _(MOD, NAME_A, VALUE_B) \
    _(MOD, NAME_A, VALUE_C) \
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

#define __ENUM_MAP_VALUE(_MOD, _name, _value)   _MOD##_##_name = _value,
#define __ENUM_MAP_NAME(_MOD, _name, _value)    [_MOD##_##_name] = #_name,

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

typedef uint32 os_ip4_t;

#define OS_FORMAT_IPSTRING      "255.255.255.255"
#define OS_IPSTRING_LEN         OS_FORMAT_SIZE(OS_FORMAT_IPSTRING)
typedef char ip_string_t[OS_IPSTRING_LEN];

static inline char *
os_ipstring(os_ip4_t ip, ip_string_t string)
{
    return (char *)inet_ntop(AF_INET, &ip, string, OS_IPSTRING_LEN);
}

static inline char *
unsafe_ipstring(os_ip4_t ip)
{
    static ip_string_t string;

    return os_ipstring(ip, string);
}

#define OS_FORMAT_FULLTIME      "1900-01-01#00:00:00"
#define OS_FULLTIME_STRING_LEN  OS_FORMAT_SIZE(OS_FORMAT_FULLTIME)
typedef char time_string_t[OS_FULLTIME_STRING_LEN];

static inline char *
os_time_string(time_t t, time_string_t string)
{
    struct tm *tm = gmtime(&t);

    os_snprintf(string, OS_FULLTIME_STRING_LEN,
                "%04d-%02d-%02d#%02d:%02d:%02d",
                1900 + tm->tm_year,
                1 + tm->tm_mon,
                tm->tm_mday,
                tm->tm_hour,
                tm->tm_min,
                (61==tm->tm_sec)?59:tm->tm_sec);

    return string;
}

static inline char *
unsafe_time_string(time_t t)
{
    static time_string_t string;

    return os_time_string(t, string);
}

static inline bool
is_good_str(const char *s)
{
    return s && s[0];
}

static inline bool
is_option_args(char *args)
{
    return args 
        && '-'==args[0]
        && '-'==args[1]
        && args[2];
}

#define OS_VAR(_name)       __the_os_##_name##_sb_var
#define OS_VAR_MAPPER(_)    \
    _(int,      option)     \
    _(int,      levle)      \
    _(time_t,   time)       \
    _(uint32,   seq)        \
    /* end */

#define __DECLARE_VARS(_type, _name)    _type OS_VAR(_name);
#define __EXTERN_VARS(_type, _name)     extern __DECLARE_VARS(_type, _name)

#define DECLARE_OS_VARS                 OS_VAR_MAPPER(__DECLARE_VARS)   os_fake_declare
#define  EXTERN_OS_VARS                 OS_VAR_MAPPER(__EXTERN_VARS)    os_fake_declare

EXTERN_OS_VARS;

static inline void
set_option(int flag)
{
    OS_VAR(option) |= flag;
}

static inline void
clr_option(int flag)
{
    OS_VAR(option) &= ~flag;
}

static inline bool
is_option(int flag)
{
    return flag==(flag & OS_VAR(option));
}

#define option_analysis(_opt, _cmd)         nameflag_analysis(_opt, _cmd)

#define option_dump(_opt, _fmt, _args...)   do{ \
    if (is_option(_opt)) {                      \
        os_println(_fmt, ##_args);              \
    }                                           \
}while(0)

#define os_fstat(_file, _st)    stat(_file, _st)

static inline int
os_fsize(const char *file)
{
    struct stat st;

    return 0==os_fstat(file, &st)?st.st_size:-errno;
}

static inline mode_t
os_fmode(const char *file)
{
    struct stat st;

    return 0==os_fstat(file, &st)?st.st_mode:0;
}

static inline bool
os_fisdir(const char *file)
{
    mode_t mode = os_fmode(file);
    
    return S_ISDIR(mode);
}

static inline bool
os_fexist(const char *file)
{
    int fd = open(file, O_RDONLY, S_IRUSR | S_IRGRP);
    if (fd<0) {
        return false;
    } else {
        close(fd);
        
        return true;
    }
}

static inline int
os_fhandle(const char *file, int (*handle)(const char *file, int fd))
{
    int fd = open(file, O_RDONLY, S_IRUSR | S_IRGRP);
    if (fd<0) {
        return -errno;
    }
    
    int err = (*handle)(file, fd);
    close(fd);

    return err;
}

#ifndef os_munmap
#define os_munmap(_file, _mem, _size)  ({  \
    int m_err = 0;                  \
                                    \
    if (_mem) {                     \
        m_err = munmap(_mem, _size);\
        if (m_err<0) {              \
            m_err = -errno;         \
            os_println("munmap %s error:%d ...", _file, m_err); \
        } else {                    \
            _mem = NULL;            \
        }                           \
    }                               \
                                    \
    m_err;                          \
})  /* end */
#endif

#ifndef os_mmap
#define os_mmap(_size, _prot, _flag, _fd, _offset)              ({  \
    void *m_mm = mmap(NULL,  _size, _prot, _flag, _fd, _offset);    \
                                                                    \
    (MAP_FAILED==m_mm)?NULL:m_mm;                                   \
})
#endif

static inline int
os_mmap_w(const char *file, void *buf, int len, bool sync)
{
    char *action;
    void *mem = NULL;
    int fd = -1, err = 0;
    
    fd = open(file, O_CREAT|O_RDWR, 0664);
    if (fd<0) {
        err = -errno; action = "open"; goto ERROR;
    }
    
    err = ftruncate(fd, len);
    if (err<0) {
        err = -errno; action = "ftruncate"; goto ERROR;
    }

    mem = os_mmap(len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (NULL==mem) {
        err = -errno; action = "mmap"; goto ERROR;
    }
    
    memcpy(mem, buf, len);
    msync(mem, len, sync?MS_SYNC:MS_ASYNC);
    madvise(mem, len, MADV_DONTNEED);
    
ERROR:
    if (err<0) {
        os_println("%s %s error:%d", action, file, -errno);
    }

    os_munmap(file, mem, len);
    os_close(fd);

    return err;
}

static inline int
os_mmap_w_sync(const char *file, void *buf, int len)
{
    return os_mmap_w(file, buf, len, true);
}

static inline int
os_mmap_w_async(const char *file, void *buf, int len)
{
    return os_mmap_w(file, buf, len, false);
}

static inline int
os_mmap_r(const char *file, int (*handle)(void *buf, int len))
{
    char *action;
    void *mem = NULL;
    int fd = -1, err = 0, size;
    
    size = os_fsize(file);
    if (size<0) {
        err = size; action = "fsize"; goto ERROR;
    }

    fd = open(file, O_RDONLY);
    if (fd<0) {
        err = -errno; action = "open"; goto ERROR;
    }
    
    mem = os_mmap(size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (NULL==mem) {
        err = -errno; action = "mmap"; goto ERROR;
    }

    err = (*handle)(mem, size);
    if (err<0) {
        action = "handle"; goto ERROR;
    }
    
ERROR:
    if (err<0) {
        os_println("%s %s error:%d", action, file, -errno);
    }

    os_munmap(file, mem, size);
    os_close(fd);

    return err;
}

enum {
    MM_F_WRITE      = 0x0001,
    MM_F_EXEC       = 0x0002,
    MM_F_SHARED     = 0x0004,
};

typedef struct {
    void        *addr;
    uint32      offset;
    uint32      size;
    uint32      flag;
    int         fd;
} mmap_t;

#define INVALID_MMAP_OFFSET         ((uint32)(-1))
#define MMAP_OBJ(_mm, _offset)      ((byte *)(_mm)->addr + _offset)
#define MMAP_OFFSET(_mm, _obj)      ((byte *)(_obj) - (byte *)(_mm)->addr)

static inline byte *
mmap_obj(mmap_t *mm, uint32 offset)
{
    return MMAP_OBJ(mm, offset);
}

static inline uint32
mmap_offset(mmap_t *mm, void *obj)
{
    if (obj >= mm->addr) {
        return MMAP_OFFSET(mm, obj);
    } else {
        return INVALID_MMAP_OFFSET;
    }
}

static inline bool
mmap_enough(mmap_t *mm, uint32 offset, uint32 size)
{
    return offset + size <= mm->size;
}

#ifndef use_blist_dprint
#define use_blist_dprint    0
#endif

#if use_blist_dprint
#define blist_dprint(_fmt, _args...)    os_println(_fmt, ##_args)
#else
#define blist_dprint(_fmt, _args...)    os_do_nothing()
#endif

#ifndef bpointer_t
#define bpointer_t     uint32
#endif

#define INVALID_BPOINTER    0

typedef struct {
    bpointer_t next;
    bpointer_t prev;
} blist_head_t;

#define BLIST_OBJ(_mm, _type, _ptr)     (_type *)mmap_obj(_mm, _ptr)
#define blist_entry(obj, type, member)  container_of(obj, type, member)

static inline blist_head_t *
blist_obj(mmap_t *mm, bpointer_t ptr)
{
    return (blist_head_t *)MMAP_OBJ(mm, ptr);
}

static inline bpointer_t
blist_ptr(mmap_t *mm, void *obj)
{
    return MMAP_OFFSET(mm, obj);
}

static inline blist_head_t *
blist_objnext(mmap_t *mm, bpointer_t ptr)
{
    return blist_obj(mm, blist_obj(mm, ptr)->next);
}

static inline blist_head_t *
blist_objprev(mmap_t *mm, bpointer_t ptr)
{
    return blist_obj(mm, blist_obj(mm, ptr)->prev);
}

#define BLIST_FIRST(mm, list)   blist_obj(mm, list)->next
#define BLIST_TAIL(mm, list)    blist_obj(mm, list)->prev

#if 0
static inline void
INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}
#else
static inline void
INIT_BLIST_HEAD(mmap_t *mm, bpointer_t list)
{
    blist_head_t *objlist = blist_obj(mm, list);
    
	objlist->next = list;
	objlist->prev = list;
}
#endif

#if 0
/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}
#else
static inline void
__blist_add(mmap_t *mm, 
        bpointer_t new, 
        bpointer_t prev, 
        bpointer_t next)
{
    blist_head_t *objnew    = blist_obj(mm, new);
    blist_head_t *objprev   = blist_obj(mm, prev);
    blist_head_t *objnext   = blist_obj(mm, next);

	objnext->prev   = new;
	objnew->next    = next;
	objnew->prev    = prev;
	objprev->next   = new;
}
#endif

#if 0

/**
 * list_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}
#else
static inline void
blist_add(mmap_t *mm,
        bpointer_t new, 
        bpointer_t head)
{
	__blist_add(mm, new, head, blist_obj(mm, head)->next);

	blist_dprint("blist, add %u to head", new);
}
#endif

#if 0
/**
 * list_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}
#else
static inline void
blist_add_tail(mmap_t *mm, 
        bpointer_t new, 
        bpointer_t head)
{
	__blist_add(mm, new, blist_obj(mm, head)->prev, head);

	blist_dprint("blist, add %u to tail", new);

}
#endif

#if 0

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}
#else
static inline void
__blist_del(mmap_t *mm,
        bpointer_t prev, 
        bpointer_t next)
{
    blist_head_t *objprev = blist_obj(mm, prev);
    blist_head_t *objnext = blist_obj(mm, next);
    
	objnext->prev = prev;
	objprev->next = next;
}
#endif

#if 0
/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}
#else
static inline void
__blist_del_entry(mmap_t *mm, bpointer_t entry)
{
    blist_head_t *objentry = blist_obj(mm, entry);
    
	__blist_del(mm, objentry->prev, objentry->next);
}
#endif

#if 0
static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = NULL;
	entry->prev = NULL;
}
#else
static inline void
blist_del(mmap_t *mm, bpointer_t entry)
{
    blist_head_t *objentry = blist_obj(mm, entry);
    
	__blist_del(mm, objentry->prev, objentry->next);
	objentry->next = INVALID_BPOINTER;
	objentry->prev = INVALID_BPOINTER;

	blist_dprint("blist, del %u", entry);
}
#endif

#if 0
/**
 * list_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
static inline void list_del_init(struct list_head *entry)
{
	__list_del_entry(entry);
	INIT_LIST_HEAD(entry);
}
#else
static inline void
blist_del_init(mmap_t *mm, bpointer_t entry)
{
	__blist_del_entry(mm, entry);
	INIT_BLIST_HEAD(mm, entry);

	blist_dprint("blist, del&init %u", entry);
}
#endif

#if 0
/**
 * list_is_last - tests whether @list is the last entry in list @head
 * @list: the entry to test
 * @head: the head of the list
 */
static inline int list_is_last(const struct list_head *list,
				const struct list_head *head)
{
	return list->next == head;
}
#else
static inline bool
blist_is_last(mmap_t *mm, 
        bpointer_t list, 
        bpointer_t head)
{
    return blist_obj(mm, list)->next == head;
}
#endif

#if 0
/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}
#else
static inline bool
blist_empty(mmap_t *mm, bpointer_t head)
{
    return blist_obj(mm, head)->next == head;
}
#endif

#if 0
/**
 * list_is_singular - tests whether a list has just one entry.
 * @head: the list to test.
 */
static inline int list_is_singular(const struct list_head *head)
{
	return !list_empty(head) && (head->next == head->prev);
}
#else
static inline int
blist_is_singular(mmap_t *mm, bpointer_t head)
{
    blist_head_t *objhead = blist_obj(mm, head);

	return !blist_empty(mm, head) && (objhead->next == objhead->prev);
}

#endif

#if 0
/**
 * list_for_each	-	iterate over a list
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)
#else
#define blist_for_each(mm, pos, head) \
    for (pos = blist_obj(mm, head)->next; pos != (head); pos = blist_obj(mm, pos)->next)
#endif

#if 0
/**
 * list_for_each_safe - iterate over a list safe against removal of list entry
 * @pos:	the &struct list_head to use as a loop cursor.
 * @n:		another &struct list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; \
	    pos != (head); \
		pos = n, n = pos->next)
#else
#define blist_for_each_safe(mm, pos, n, head) \
	for (pos = blist_obj(mm, head)->next, n = blist_obj(mm, pos)->next; \
	    pos != (head); \
		pos = n, n = blist_obj(mm, pos)->next)
#endif

#if 0
static inline bool
is_in_list(struct list_head *node)
{
    return (node->next && node->prev) && false==list_empty(node);
}
#else
static inline bool
is_in_list(mmap_t *mm, bpointer_t node)
{
    blist_head_t *objnode = blist_obj(mm, node);
    
    return (objnode->next && objnode->prev) && !blist_empty(mm, node);
}
#endif

static inline bpointer_t
blist_first(mmap_t *mm, bpointer_t list)
{
    return blist_empty(mm, list) ? INVALID_BPOINTER : BLIST_FIRST(mm, list);
}

static inline bpointer_t
blist_tail(mmap_t *mm, bpointer_t list)
{
    return blist_empty(mm, list) ? INVALID_BPOINTER : BLIST_TAIL(mm, list);
}

#ifndef use_bhash_dprint
#define use_bhash_dprint    0
#endif

#if use_bhash_dprint
#define bhash_dprint(_fmt, _args...)    os_println(_fmt, ##_args)
#else
#define bhash_dprint(_fmt, _args...)    os_do_nothing()
#endif

typedef blist_head_t bhash_bucket_t;
typedef blist_head_t bhash_node_t;

typedef struct {
    bhash_bucket_t bucket[0];
} hash_t;

typedef int bhash_nhandle_t(mmap_t *mm, bpointer_t hash, bpointer_t node);
typedef int bhash_dhandle_t(mmap_t *mm, bpointer_t hash);

typedef struct {
    bhash_nhandle_t *cmp;
    bhash_nhandle_t *change;
    bhash_nhandle_t *handle;
    bhash_nhandle_t *idxbyn;
    bhash_dhandle_t *idxbyd;
} bhash_op_t;

static inline hash_t *
bhash(mmap_t *mm, bpointer_t hash)
{
    return (hash_t *)MMAP_OBJ(mm, hash);
}

static inline bpointer_t
bhash_bucket_helper(mmap_t *mm, hash_t *h, uint32 idx)
{
    return blist_ptr(mm, &h->bucket[idx]);
}

static inline bpointer_t
bhash_bucket(mmap_t *mm, bpointer_t hash, uint32 idx)
{
    return bhash_bucket_helper(mm, bhash(mm, hash), idx);
}

static inline bhash_node_t *
bhash_obj(mmap_t *mm, bpointer_t ptr)
{
    return (bhash_node_t *)MMAP_OBJ(mm, ptr);
}

static inline int
bhash_init(mmap_t *mm, bpointer_t hash, uint32 size)
{
    hash_t *h = bhash(mm, hash);
    uint32 i;
    
    for (i=0; i<size; i++) {
        INIT_BLIST_HEAD(mm, bhash_bucket_helper(mm, h, i));
    }

    bhash_dprint("bhash[%u], init", hash);
    
    return 0;
}

static inline bpointer_t
bhash_bucket_first(mmap_t *mm, bpointer_t hash, uint32 idx)
{
    bpointer_t bucket = bhash_bucket(mm, hash, idx);

    return blist_first(mm, bucket);
}

static inline bpointer_t
bhash_bucket_tail(mmap_t *mm, bpointer_t hash, uint32 idx)
{
    bpointer_t bucket = bhash_bucket(mm, hash, idx);

    return blist_tail(mm, bucket);
}

static inline void
bhash_del(mmap_t *mm, bpointer_t hash, bpointer_t node)
{
    blist_del(mm, node);

    bhash_dprint("bhash[%u], del %u", hash, node);
}

static inline void
bhash_add(mmap_t *mm, bpointer_t hash, bpointer_t node, bhash_op_t *op)
{
    bpointer_t bucket = bhash_bucket(mm, hash, (*op->idxbyn)(mm, hash, node));
    
    blist_add(mm, node, bucket);

    bhash_dprint("bhash[%u], bucket[%u], add %u", hash, bucket, node);
}

static inline void
bhash_change(mmap_t *mm, bpointer_t hash, bpointer_t node, bhash_op_t *op)
{
    bhash_del(mm, hash, node);
    (*op->change)(mm, hash, node);
    bhash_add(mm, hash, node, op);
}

#define bhash_bucket_foreach(mm, bucket, node) \
    blist_for_each(mm, node, bucket)

#define bhash_bucket_foreach_safe(mm, bucket, node, n) \
    blist_for_each_safe(mm, node, n, bucket)

static inline bpointer_t
bhash_find(mmap_t *mm, bpointer_t hash, bhash_op_t *op)
{
    bpointer_t bucket = bhash_bucket(mm, hash, (*op->idxbyd)(mm, hash));
    bpointer_t node;

    bhash_bucket_foreach(mm, bucket, node) {
        if (0==(*op->cmp)(mm, hash, node)) {
            return node;
        }
    }
    
    return INVALID_BPOINTER;
}

#ifndef os_array_search
#define os_array_search(_array, _obj, _cmp, _begin, _end) ({ \
    int m_i, m_idx = (_end);    \
                                \
    for (m_i=(_begin); m_i<(_end); m_i++) {   \
        if (0==_cmp((_array)[m_i], _obj)) { \
            m_idx = m_i;        \
            break;      \
        }               \
    }                   \
                        \
    m_idx;              \
})  /* end */
#endif

#define os_array_search_str(_array, _string, _begin, _end) \
    os_array_search(_array, _string, strcmp, _begin, _end)

#define UXXEQ(_type, _a, _b)    (*(_type *)(_a) == *(_type *)(_b))
#define U16EQ(_a, _b)           UXXEQ(uint16, _a, _b)
#define U32EQ(_a, _b)           UXXEQ(uint32, _a, _b)
#define U64EQ(_a, _b)           UXXEQ(uint64, _a, _b)

static inline char *
os_strmcpy(void *dst, void *src, int len)
{
    memcpy(dst, src, len);
    ((char *)dst)[len] = 0;

    return (char *)dst;
}

static inline bool
os_str_has_suffix(char *s, int len, char *suffix, int suffix_len)
{
    return (len > suffix_len)?U32EQ(s + len - suffix_len, suffix):false;
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
    
    return os_mmap_r(file, handle);
}

static inline int
os_hex2byte(int ch)
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
__byte2hex(int ch)
{
    switch(ch) {
        case 0 ... 9:
            return '0' + ch;
        case 0xA ... 0xF:
            return 'A' + ch - 0xA;
        default:
            return os_assertV('0');
    }
}

static inline void
os_byte2hex(int ch, char bin[2])
{
    bin[0] = __byte2hex(ch >>4);
    bin[1] = __byte2hex(ch & 0xf);
}

static inline int
os_hex2bin(char *hex, byte *bin, int size)
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
        bin[i] = 16 * os_hex2byte(hex[2*i]) + os_hex2byte(hex[2*i+1]);
    }

    return hexlen;
}

static inline int
os_bin2hex(char *hex, int space, byte *bin, int size)
{
    int i, len = size+size;
    
    if (len < space) {
        return -ENOSPACE;
    }

    for (i=0; i<size; i++) {
        os_byte2hex(bin[i], hex + 2*i);
    }
    hex[len] = 0;
    
    return len;
}

typedef struct inotify_event inotify_ev_t;

#define INOTIFY_EVSIZE  (sizeof(inotify_ev_t) + NAME_MAX + 1)   // = 16 + 256 = 272

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

typedef struct {
    const char *name;
    const char *help;
    int flag;
} nameflag_t;

#define NAMEFLAG_INITER(_flag, _name, _help) { \
    .flag = _flag; \
    .name = _name; \
    .help = _help; \
}   /* end */

static inline int 
__nameflag_usage(nameflag_t opt[], int count)
{
    os_println(__tab "OPTION:");

    int i;

    for (i=0; i<count; i++) {
        os_println(__tab2 "%s: %s", opt[i].name, opt[i].help);
    }

    return -EHELP;
}

static inline const char *
__get_nameflag_byflag(nameflag_t opt[], int count, int flag)
{
    int i;

    for (i=0; i<count; i++) {
        if (opt[i].flag & flag) {
            return opt[i].name;
        }
    }

    return NULL;
}

static inline int
__get_nameflag_byname(nameflag_t opt[], int count, char *name)
{
    int i;

    for (i=0; i<count; i++) {
        if (0==strcmp(opt[i].name, name)) {
            return opt[i].flag;
        }
    }

    return 0;
}

static inline void
__nameflag_analysis(nameflag_t opt[], int count, char *args)
{
    int flag = __get_nameflag_byname(opt, count, args);

    set_option(flag);
}

#define get_nameflag_byflag(_opt, _flag)    __get_nameflag_byflag(_opt, os_count_of(_opt), _flag)
#define get_nameflag_byname(_opt, _flag)    __get_nameflag_byname(_opt, os_count_of(_opt), _flag)
#define nameflag_usage(_opt)                __nameflag_usage(_opt, os_count_of(_opt))
#define nameflag_analysis(_opt, _args)      __nameflag_analysis(_opt, os_count_of(_opt), _args)

#ifndef D_env_println
#define D_env_println   0
#endif

#if D_env_println
#define env_println(_fmt, _args...)     os_println(_fmt, ##_args)
#else
#define env_println(_fmt, _args...)     os_do_nothing()
#endif

#define is_good_env(_env)               is_good_str(_env)

static inline char *
env_gets(char *envname, char *deft) 
{
    if (envname) {
        char *env = getenv(envname);
        
        if (is_good_env(env)) {
            env_println("get env:%s=%s", envname, env);
            
            return env;
        } else {
            env_println("no-found env:%s, use default:%s", envname, deft);

            return deft;
        }
    } else {
        env_println("empty env, use default:%s", deft);

        return deft;
    }
}

static inline int
env_geti(char *envname, int deft) 
{
    if (NULL==envname) {
        return os_assertV(deft);
    }
    
    char *env = getenv(envname);
    if (false==is_good_env(env)) {
        env_println("no-found env:%s, use default:%d", envname, deft);
        
        return deft;
    } else {
        int value = atoi(env);

        env_println("get env:%s=%d", envname, value);

        return value;
    }
}

#ifndef os_trace
#define os_trace(_print, _call, _fmt, _args...) ({  \
    int m_err;                                  \
                                                \
    _print("try " _fmt " ...", ##_args);        \
    m_err = (_call);                            \
    _print(__tab "%s:%d " _fmt, ok_string(m_err), m_err, ##_args); \
                                                \
    m_err;                                      \
})  /* end */
#endif

#ifndef os_trace_by
#define os_trace_by(_is_trace, _print, _call, _fmt, _args...) ({  \
    int m_err;                                  \
    bool m_is_trace = _is_trace;                \
                                                \
    if (m_is_trace) {                           \
        _print("try " _fmt " ...", ##_args);    \
    }                                           \
                                                \
    m_err = (_call);                            \
                                                \
    if (m_is_trace) {                           \
        _print(__tab "%s:%d " _fmt, ok_string(m_err), m_err, ##_args); \
    }                                           \
                                                \
    m_err;                                      \
})  /* end */
#endif

#if 0
#define likely(e)       __builtin_expect((e), 1)
#define unlikely(e)     __builtin_expect((e), 0)
#define rmb()           __atomic_thread_fence(__ATOMIC_ACQUIRE)
#define wmb()           __atomic_thread_fence(__ATOMIC_RELEASE)
#define mb()            __atomic_thread_fence(__ATOMIC_SEQ_CST)
#define atomic_load(n)  __atomic_load_n(&(n), __ATOMIC_RELAXED)

#ifndef CACHE_LINE_SIZE
#define CACHE_LINE_SIZE 64
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE       4096
#endif

typedef uint64 __attribute__ ((aligned((CACHE_LINE_SIZE)))) aligned_size_t;

#define CAS_V(addr, old, x)     __sync_val_compare_and_swap(addr, old, x)
#define CAS(addr, old, x)       (CAS_V(addr, old, x) == old)
#define ATOMIC_INC(addr)        __sync_fetch_and_add(addr, 1)
#define ATOMIC_ADD(addr, n)     __sync_add_and_fetch(addr, n)
#endif

/******************************************************************************/
#include "log.h"
#endif
