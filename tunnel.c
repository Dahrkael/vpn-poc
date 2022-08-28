#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include <net/if.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <sys/ioctl.h>

#include "common.h"

// mkdir /dev/net (if it doesn't exist already)
// mknod /dev/net/tun c 10 200
// chmod 0666 /dev/net/tun
// modprobe tun

typedef struct
{
   int fd;
   char if_name[IF_NAMESIZE];
} Tunnel;

bool check_tun_privileges()
{
   int fd = open("/dev/net/tun", O_RDWR);
   bool ok = (fd > 0);
   close(fd);
   return ok;
}

int allocate_tun_device(char* device_name)
{
   if (!device_name)
      return -1;

   int tun_fd = open("/dev/net/tun", O_RDWR);
   if (tun_fd < 0)
      return -1;

   // IFF_TUN   - TUN device (no Ethernet headers)
   // IFF_NO_PI - Do not provide packet information
   struct ifreq request;
   CLEAR(request);
   request.ifr_flags = IFF_TUN | IFF_NO_PI;

   // set custom name if specified
   if( *device_name )
      strncpy(request.ifr_name, device_name, IF_NAMESIZE);

   int ret = ioctl(tun_fd, TUNSETIFF, (void*)&request);
   if ( ret < 0 )
   {
      close(tun_fd);
      return ret;
   }

   // copy back the assigned name
   strcpy(device_name, request.ifr_name);
   return tun_fd;
}

void configure_tunnel(const Tunnel* tunnel)
{
   struct ifreq request;
   memset(&request, 0, sizeof(request));
   strncpy(request.ifr_name, tunnel->if_name, IF_NAMESIZE);

   request.ifr_addr;
   ioctl(tunnel->fd, SIOCSIFADDR, (void*)&request);

   request.ifr_dstaddr;
   ioctl(tunnel->fd, SIOCSIFDSTADDR, (void*)&request);

   request.ifr_netmask;
   ioctl(tunnel->fd, SIOCSIFNETMASK, (void*)&request);

   request.ifr_mtu;
   ioctl(tunnel->fd, SIOCSIFMTU, (void*)&request);

   ioctl(tunnel->fd, SIOCGIFFLAGS, (void*)&request);
   request.ifr_flags;
   ioctl(tunnel->fd, SIOCSIFFLAGS, (void*)&request);

   //request.ifr_addr;
   //int ret = ioctl(tunnel->fd, TUNSETPERSIST, (void*)&request);

   IFF_UP;
}
