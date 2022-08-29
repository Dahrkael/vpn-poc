#pragma once

#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

// set to 0 to disable debug logs
#define DEBUG 1 

// custom bool type since C doesn't have one
typedef enum {
   false = 0,
   true = 1
} bool;

#define CLEAR(structure) memset(&structure, 0, sizeof(structure));

void printf_debug(const char* format, ...) 
{
#if DEBUG
   printf("[debug] ");
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
#endif
}

bool address_to_string(const struct sockaddr_storage* address, char* buffer, socklen_t length)
{
   switch (address->ss_family)
   {
      case AF_INET:
         inet_ntop(AF_INET, &((struct sockaddr_in*)address)->sin_addr, buffer, length );
      break;
      case AF_INET6:
         inet_ntop(AF_INET6, &((struct sockaddr_in6*)address)->sin6_addr, buffer, length );
      break;
      default:
         return false;
   }
   return true;
}
