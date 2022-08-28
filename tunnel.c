#include <fcntl.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "common.h"

// mkdir /dev/net (if it doesn't exist already)
// mknod /dev/net/tun c 10 200
// chmod 0666 /dev/net/tun
// modprobe tun

// TODO TUNSETSNDBUF 

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

int32_t allocate_tun_device(char* device_name)
{
   if (!device_name)
      return -1;

   int32_t tun_fd = open("/dev/net/tun", O_RDWR);
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

   if ( ioctl(tun_fd, TUNSETIFF, (void*)&request) < 0 )
   {
      close(tun_fd);
      return -1;
   }

   // copy back the assigned name
   strcpy(device_name, request.ifr_name);
   return tun_fd;
}

bool tunnel_get_flags(Tunnel* tunnel, uint16_t* flags)
{
   if (tunnel->fd == -1)
      return false;

   struct ifreq request;
   CLEAR(request);
   int ret = ioctl(tunnel->fd, SIOCGIFFLAGS, (void*)&request);
   if ( ret == -1)
      return false;

   *flags = request.ifr_flags;
   return true;
}

bool tunnel_set_flags(Tunnel* tunnel, const uint16_t flags, const bool keep_current)
{
   if (tunnel->fd == -1)
      return false;

   struct ifreq request;
   CLEAR(request);

   if (keep_current && !tunnel_get_flags(tunnel, &request.ifr_flags))
      return false;

   // OR new flags to keep the old ones if set
   request.ifr_flags |= flags;
   int ret = ioctl(tunnel->fd, SIOCSIFFLAGS, (void*)&request);
   if ( ret == -1)
      return false;

   return true;
}

bool tunnel_set_name(Tunnel* tunnel, const char* name)
{
   if (tunnel->fd == -1)
      return false;

   struct ifreq request;
   CLEAR(request);
   strncpy(request.ifr_name, name, IF_NAMESIZE);

   if (!tunnel_get_flags(tunnel, &request.ifr_flags))
      return false;

   return ioctl(tunnel->fd, TUNSETIFF, (void*)&request) == 0;
}

bool tunnel_set_local_address(Tunnel* tunnel, const struct sockaddr* address)
{
   if (tunnel->fd == -1)
      return false;

   struct ifreq request;
   CLEAR(request);
   memcpy(&request.ifr_addr, &address, sizeof(request.ifr_addr));

   return ioctl(tunnel->fd, SIOCSIFADDR, (void*)&request) == 0;
}

bool tunnel_set_remote_address(Tunnel* tunnel, const struct sockaddr* address)
{
   if (tunnel->fd == -1)
      return false;

   struct ifreq request;
   CLEAR(request);
   memcpy(&request.ifr_addr, &address, sizeof(request.ifr_addr));

   return ioctl(tunnel->fd, SIOCSIFDSTADDR, (void*)&request) == 0;
}

bool tunnel_set_network_mask(Tunnel* tunnel, const struct sockaddr* mask)
{
   if (tunnel->fd == -1)
      return false;

   struct ifreq request;
   CLEAR(request);
   memcpy(&request.ifr_addr, &mask, sizeof(request.ifr_addr));

   return ioctl(tunnel->fd, SIOCSIFNETMASK, (void*)&request) == 0;
}

bool tunnel_set_mtu(Tunnel* tunnel, const uint32_t mtu)
{
   if (tunnel->fd == -1)
      return false;

   struct ifreq request;
   CLEAR(request);
   request.ifr_mtu = mtu;

   return ioctl(tunnel->fd, SIOCSIFMTU, (void*)&request) == 0;
}

bool tunnel_persist(Tunnel* tunnel, const bool on)
{
   if (tunnel->fd == -1)
      return false;

   if (on)
   {
      // try set owner and group so it can be used without root privileges
      ioctl(tunnel->fd, TUNSETOWNER, geteuid());
      //ioctl(tunnel->fd, TUNSETGROUP, group);
   }

   return ioctl(tunnel->fd, TUNSETPERSIST, on) == 0;
}

bool tunnel_up(Tunnel* tunnel)
{
   return tunnel_set_flags(tunnel, IFF_UP | IFF_RUNNING, true);
}

bool tunnel_down(Tunnel* tunnel)
{
   uint16_t flags = 0;
   if (!tunnel_get_flags(tunnel, &flags))
      return false;

   flags &= ~(IFF_UP | IFF_RUNNING);
   return tunnel_set_flags(tunnel, flags, false);
}
