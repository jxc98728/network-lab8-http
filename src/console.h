#ifndef CONSOLE_H
#define CONSOLE_H

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdarg.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#define COLOR_RED ((COLOR_RESET & 0xFFF0) | 0x000C)
#define COLOR_GREEN ((COLOR_RESET & 0xFFF0) | 0x000A)
#define COLOR_BLUE ((COLOR_RESET & 0xFFF0) | 0x0009)
#define COLOR_YELLOW ((COLOR_RESET & 0xFFF0) | 0x000E)
#define COLOR_MAGENTA ((COLOR_RESET & 0xFFF0) | 0x000D)
#define COLOR_CYAN ((COLOR_RESET & 0xFFF0) | 0x000B)
#define COLOR_BOLD (COLOR_RESET | FOREGROUND_INTENSITY)
#define set_color(COLOR) SetConsoleTextAttribute(handle, COLOR)
#elif __linux__
#include <pthread.h>
#define COLOR_RED "\x1b[1;31m"
#define COLOR_GREEN "\x1b[1;32m"
#define COLOR_BLUE "\x1b[1;34m"
#define COLOR_YELLOW "\x1b[1;33m"
#define COLOR_MAGENTA "\x1b[1;35m"
#define COLOR_CYAN "\x1b[1;36m"
#define COLOR_BOLD "\x1b[1;37m"
#define COLOR_RESET "\x1b[0m"
#define set_color(COLOR) printf(COLOR)
#endif

class console
{
public:
    console()
    {

#ifdef _WIN32
        handle = GetStdHandle(STD_OUTPUT_HANDLE);
        GetConsoleScreenBufferInfo(handle, &scr_buf);
        COLOR_RESET = scr_buf.wAttributes;
        print_mutex = CreateMutex(NULL, FALSE, NULL);
#elif __linux__
        pthread_mutex_init(&print_mutex, NULL);
#endif
    }

    inline void printText(const char *_Format, ...)
    {
        va_list args;
        va_start(args, _Format);
        vfprintf(stdout, _Format, args);
        va_end(args);
    }

    inline void printBoldText(const char *_Format, ...)
    {
        set_color(COLOR_BOLD);
        va_list args;
        va_start(args, _Format);
        vfprintf(stdout, _Format, args);
        va_end(args);
        set_color(COLOR_RESET);
    }

    inline void printRedText(const char *_Format, ...)
    {
        set_color(COLOR_RED);
        va_list args;
        va_start(args, _Format);
        vfprintf(stdout, _Format, args);
        va_end(args);
        set_color(COLOR_RESET);
    }

    inline void printYellowText(const char *_Format, ...)
    {
        set_color(COLOR_YELLOW);
        va_list args;
        va_start(args, _Format);
        vfprintf(stdout, _Format, args);
        va_end(args);
        set_color(COLOR_RESET);
    }

    inline void printMagentaText(const char *_Format, ...)
    {
        set_color(COLOR_MAGENTA);
        va_list args;
        va_start(args, _Format);
        vfprintf(stdout, _Format, args);
        va_end(args);
        set_color(COLOR_RESET);
    }

    inline void printCyanText(const char *_Format, ...)
    {
        set_color(COLOR_CYAN);
        va_list args;
        va_start(args, _Format);
        vfprintf(stdout, _Format, args);
        va_end(args);
        set_color(COLOR_RESET);
    }

    inline void printGreenText(const char *_Format, ...)
    {
        set_color(COLOR_GREEN);
        va_list args;
        va_start(args, _Format);
        vfprintf(stdout, _Format, args);
        va_end(args);
        set_color(COLOR_RESET);
    }

    inline void printBlueText(const char *_Format, ...)
    {
        set_color(COLOR_BLUE);
        va_list args;
        va_start(args, _Format);
        vfprintf(stdout, _Format, args);
        va_end(args);
        set_color(COLOR_RESET);
    }

    inline void lock()
    {
#ifdef _WIN32
        WaitForSingleObject(print_mutex, INFINITE);
#elif __linux__
        pthread_mutex_lock(&print_mutex);
#endif
    }

    inline void unlock(void)
    {
#ifdef _WIN32
        ReleaseMutex(print_mutex);
#elif __linux__
        pthread_mutex_unlock(&print_mutex);
#endif
    }

private:
#ifdef _WIN32
    HANDLE handle;
    WORD COLOR_RESET;
    CONSOLE_SCREEN_BUFFER_INFO scr_buf;
    HANDLE print_mutex;
#elif __linux__
    pthread_mutex_t print_mutex;
#endif
};

static console Console = console();

#endif // !CONSOLE_H
