#pragma once

enum
{
    LOG_ERR,
    LOG_INFO
};

void syslog(int priority, const char *format, ...)
{
}