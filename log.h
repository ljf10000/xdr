#ifndef __LOG_H_b2542f544ba74c4884dcafa501f8c8cd__
#define __LOG_H_b2542f544ba74c4884dcafa501f8c8cd__
/******************************************************************************/
typedef struct {
    char *file;
    void *buf;
    int fd;
    int current;
    int size;
} log_t;

/******************************************************************************/
#endif /* __LOG_H_b2542f544ba74c4884dcafa501f8c8cd__ */

