#include "common.h"

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

// mkdir /dev/net (if it doesn't exist already)
// mknod /dev/net/tun c 10 200
// chmod 0666 /dev/net/tun
// modprobe tun

// TODO TUNSETSNDBUF 

typedef struct
{
   int fd;
   int socket;
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

bool tunnel_open(Tunnel* tunnel, const char* name)
{
   if (!check_tun_privileges())
   {
      printf("not enough privileges to read & write /dev/net/tun\n");
      return false;
   }

   char device_name[IF_NAMESIZE];
   // custom name is optional
   if (name && *name)
      strncpy(device_name, name, IF_NAMESIZE);

   int32_t fd = allocate_tun_device(device_name);
   if (fd < 0)
   {
      printf("failed to create or open existing TUN device %s\n", name);
      return false;
   }

   int32_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
   if (s < 0)
   {
      printf("failed to create a socket\n");
      close(fd);
      return false;
   }

   // populate the tunnel with the final data
   tunnel->fd = fd;
   tunnel->socket = s;
   strncpy(tunnel->if_name, device_name, IF_NAMESIZE);

   return true;
}

bool tunnel_get_flags(Tunnel* tunnel, const bool from_socket, uint16_t* flags)
{
   if (tunnel->fd == -1)
      return false;

   if (from_socket && tunnel->fd == -1)
      return false;

   struct ifreq request; 
   CLEAR(request);
   memcpy(&request.ifr_name, tunnel->if_name, IF_NAMESIZE);

   int ret = ioctl(from_socket ? tunnel->socket : tunnel->fd, SIOCGIFFLAGS, (void*)&request);
   if ( ret == -1)
      return false;

   *flags = request.ifr_flags;
   return true;
}

bool tunnel_set_flags(Tunnel* tunnel, const uint16_t flags, const bool keep_current, const bool to_socket)
{
   if (tunnel->fd == -1)
      return false;

   if (to_socket && tunnel->fd == -1)
      return false;

   struct ifreq request;
   CLEAR(request);
   memcpy(&request.ifr_name, tunnel->if_name, IF_NAMESIZE);

   if (keep_current && !tunnel_get_flags(tunnel, to_socket, &request.ifr_flags))
      return false;

   // OR new flags to keep the old ones if set
   request.ifr_flags |= flags;
   int ret = ioctl(to_socket ? tunnel->socket : tunnel->fd, SIOCSIFFLAGS, (void*)&request);
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

   if (!tunnel_get_flags(tunnel, false, &request.ifr_flags))
      return false;

   return ioctl(tunnel->fd, TUNSETIFF, (void*)&request) == 0;
}

bool tunnel_set_local_address(Tunnel* tunnel, const struct sockaddr_storage* address)
{
   if (tunnel->fd == -1 || tunnel->socket == -1)
      return false;

   struct ifreq request;
   CLEAR(request);
   memcpy(&request.ifr_name, tunnel->if_name, IF_NAMESIZE);
   memcpy(&request.ifr_addr, address, sizeof(address));

   if (ioctl(tunnel->socket, SIOCSIFADDR, (void*)&request) < 0)
   {
      printf_debug("%s: error setting local address\n", __FUNCTION__ );
      return false;
   }
   return true;
}

bool tunnel_set_remote_address(Tunnel* tunnel, const struct sockaddr_storage* address)
{
   if (tunnel->fd == -1 || tunnel->socket == -1)
      return false;

   struct ifreq request;
   CLEAR(request);
   memcpy(&request.ifr_name, tunnel->if_name, IF_NAMESIZE);
   memcpy(&request.ifr_addr, address, sizeof(address));

   if (ioctl(tunnel->socket, SIOCSIFDSTADDR, (void*)&request) < 0)
   {
      printf_debug("%s: error setting remote address\n", __FUNCTION__ );
      return false;
   }
   return true;
}

bool tunnel_set_addresses(Tunnel* tunnel, const struct sockaddr_storage* address_block)
{
   if (address_block->ss_family != AF_INET)
   {
      printf("error: IPv6 not implemented\n");
      return false;
   }

   // copy the block and modify the last octet to get two different ips
   struct sockaddr_storage address;
   memcpy(&address, address_block, sizeof(address));

   struct sockaddr_in* ipv4 = (struct sockaddr_in*)&address;
   uint8_t* last_octet = ((uint8_t*)&ipv4->sin_addr.s_addr)+3;

   if (*last_octet != 0)
   {
      printf("provided tunnel address is not a valid ip block\n");
      return false;
   }

   bool ok = true;

   char buffer[256];
   address_to_string(&address, buffer, sizeof(buffer));
   printf_debug("%s: block %s\n", __FUNCTION__, buffer);

   *last_octet = 2;
   address_to_string(&address, buffer, sizeof(buffer));
   printf_debug("%s: local %s\n", __FUNCTION__, buffer);
   ok = ok && tunnel_set_local_address(tunnel, &address);

   *last_octet = 1;
   address_to_string(&address, buffer, sizeof(buffer));
   printf_debug("%s: remote %s\n", __FUNCTION__, buffer);
   ok = ok && tunnel_set_remote_address(tunnel, &address);
   
   return ok;
}

bool tunnel_set_network_mask(Tunnel* tunnel, const struct sockaddr_storage* mask)
{
   if (tunnel->fd == -1 || tunnel->socket == -1)
      return false;

   struct ifreq request;
   CLEAR(request);
   memcpy(&request.ifr_name, tunnel->if_name, IF_NAMESIZE);
   memcpy(&request.ifr_addr, mask, sizeof(mask));

   return ioctl(tunnel->socket, SIOCSIFNETMASK, (void*)&request) == 0;
}

bool tunnel_set_mtu(Tunnel* tunnel, const uint32_t mtu)
{
   if (tunnel->fd == -1 || tunnel->socket == -1)
      return false;

   struct ifreq request;
   CLEAR(request);
   memcpy(&request.ifr_name, tunnel->if_name, IF_NAMESIZE);
   request.ifr_mtu = mtu;

   return ioctl(tunnel->socket, SIOCSIFMTU, (void*)&request) == 0;
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
   return tunnel_set_flags(tunnel, IFF_UP | IFF_RUNNING, true, true);
}

bool tunnel_down(Tunnel* tunnel)
{
   uint16_t flags = 0;
   if (!tunnel_get_flags(tunnel, true, &flags))
      return false;

   flags &= ~(IFF_UP | IFF_RUNNING);
   return tunnel_set_flags(tunnel, flags, false, true);
}
