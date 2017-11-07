#ifndef __DUMP_H_96bec2f065cb4415a8327409eae6d67c__
#define __DUMP_H_96bec2f065cb4415a8327409eae6d67c__
/******************************************************************************/
/*
*   raw format(like UltraEdit)

        :                                     ;
  Line  :       Hexadecimal Content           ; Raw Content
        : 0 1 2 3  4 5 6 7  8 9 A B  C D E F  ;
        :                                     ;
xxxxxxH : xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx ; cccccccccccccccc
xxxxxxH : xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx ; cccccccccccccccc
xxxxxxH : xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx ; cccccccccccccccc
xxxxxxH : xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx ; cccccccccccccccc
xxxxxxH : xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx ; cccccccccccccccc
xxxxxxH : xxxxxxxx xxxxxxxx xxxxxx            ; ccccccccccc
*/
#ifndef __DUMP_LINE_BLOCK
#define __DUMP_LINE_BLOCK           4
#endif

#ifndef __DUMP_LINE_BLOCK_BYTES
#define __DUMP_LINE_BLOCK_BYTES     4
#endif

#ifndef __DUMP_LINE_LIMIT
#define __DUMP_LINE_LIMIT           80
#endif

#ifndef __DUMP_BUFFER_MAX
#define __DUMP_BUFFER_MAX           0x1000000
#endif

enum {
    __DUMP_LINE_BYTES   = __DUMP_LINE_BLOCK_BYTES * __DUMP_LINE_BLOCK,
    __DUMP_LINE_MAX     =  (0
                            + 10 /* "xxxxxxH : " */
                            + (2 * __DUMP_LINE_BLOCK_BYTES + 1) * __DUMP_LINE_BLOCK \
                            + 2 /* "; " */
                            + __DUMP_LINE_BYTES
                            + 1 /* "\n" */
                            ),
};

#if __DUMP_LINE_MAX > __DUMP_LINE_LIMIT
#error "must __DUMP_LINE_MAX < __DUMP_LINE_LIMIT"
#endif

#ifndef __DUMP_LINE_SEPARATOR
#define __DUMP_LINE_SEPARATOR \
"=============================================================="
#endif

#ifndef __DUMP_LINE_SEPARATOR_SUB
#define __DUMP_LINE_SEPARATOR_SUB \
"--------------------------------------------------------------"
#endif

#ifndef __DUMP_LINE_HEADER
#define __DUMP_LINE_HEADER \
"        :                                     ;"                 __crlf \
"  Line  :       Hexadecimal Content           ; Raw Content"     __crlf \
"        : 0 1 2 3  4 5 6 7  8 9 A B  C D E F  ;"                 __crlf \
"        :                                     ;"                 __crlf
#endif

typedef void os_dump_line_f(FILE *stream, char *line);

#define os_dump_printf(_stream, _fmt, _args...)     fprintf(_stream, _fmt, ##_args)

static inline void
__os_dump_line(FILE *stream, int line, byte *raw, int len, os_dump_line_f *dump_line)
{
    int i, offset = 0;
    char buf[1 + __DUMP_LINE_MAX] = {0};
    
    offset += os_soprintf(buf, offset, "%.6XH :", __DUMP_LINE_BYTES*line);

    for (i=0; i<len; i++) {
        if (0 == (i%__DUMP_LINE_BLOCK_BYTES)) {
            offset += os_soprintf(buf, offset, __space);
        }
        
        offset += os_soprintf(buf, offset, "%.2X", raw[i]);
    }
    
    for (; i<__DUMP_LINE_BYTES; i++) {
        if (0 == (i%__DUMP_LINE_BLOCK_BYTES)) {
            offset += os_soprintf(buf, offset, __space);
        }
        
        offset += os_soprintf(buf, offset, __space __space);
    }
    offset += os_soprintf(buf, offset, " ; ");
    
    for (i=0; i<len; i++) {
        int c = (int)raw[i];
        
        offset += os_soprintf(buf, offset, "%c", isprint(c)?c:'.');
    }
    offset += os_soprintf(buf, offset, __crlf);

    if (dump_line) {
        (*dump_line)(stream, buf);
    } else {
        os_dump_printf(stream, "%s", buf);
    }
}

static inline void
__os_dump_buffer(FILE *stream, void *buffer, int len, os_dump_line_f *dump_line)
{
    int i, line, tail;
    byte *raw = (byte *)buffer;

    if (len<0) {
        return;
    } else if (len > __DUMP_BUFFER_MAX) {
        len = __DUMP_BUFFER_MAX;
    }
    
    line = OS_ALIGN(len, __DUMP_LINE_BYTES)/__DUMP_LINE_BYTES;
    tail = len%__DUMP_LINE_BYTES;
    tail = tail?tail:__DUMP_LINE_BYTES;
    
    if (dump_line) {
        (*dump_line)(stream, __DUMP_LINE_HEADER);
    } else {
        os_dump_printf(stream, __DUMP_LINE_HEADER);
    }
    
    for (i=0; i<(line-1); i++) {
        __os_dump_line(stream, i, raw + i * __DUMP_LINE_BYTES, __DUMP_LINE_BYTES, dump_line);
    }
    __os_dump_line(stream, line, raw + i * __DUMP_LINE_BYTES, tail, dump_line);
}

#define os_dump_buffer(_stream, _buf, _len)      __os_dump_buffer(_stream, _buf, _len, NULL)
/******************************************************************************/
#endif /* __DUMP_H_96bec2f065cb4415a8327409eae6d67c__ */
