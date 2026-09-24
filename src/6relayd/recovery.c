/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include "6relayd.h"

#define RECOVERY_COOLDOWN_MS 30000
#define RECOVERY_ATTEMPTS 3
#define RECOVERY_ADDR_LIMIT 128

struct recovery_state {
  const struct relayd_interface *iface;
  bool up, pending, running, reset, replaced;
  unsigned attempts;
  int64_t due, cooldown, log_after, reset_until;
};

static const struct relayd_config *config;
static struct recovery_state *states;
static size_t state_count;
static int link_socket = -1;
static void recover(struct relayd_event *event);
static struct relayd_event timer = {-1, recover, NULL};

static int64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static struct recovery_state *find_state(const struct relayd_interface *iface) {
  for (size_t i = 0; i < state_count; ++i)
    if (states[i].iface == iface)
      return &states[i];
  return NULL;
}

// Check the current kernel state, not just a possibly queued link notification.
// Never bring an interface up, and never target a replacement device by accident.
static bool link_ready(const struct relayd_interface *iface) {
  struct ifreq req = {0};
  memcpy(req.ifr_name, iface->ifname, sizeof(req.ifr_name));
  if (ioctl(link_socket, SIOCGIFINDEX, &req) < 0 ||
      req.ifr_ifindex != iface->ifindex)
    return false;
  if (ioctl(link_socket, SIOCGIFFLAGS, &req) < 0)
    return false;
  return (req.ifr_flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING);
}

static int read_sysctl(const struct relayd_interface *iface, const char *key) {
  char path[128];
  snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/%s", iface->ifname, key);
  FILE *f = fopen(path, "re");
  if (!f)
    return -1;
  int value;
  int n = fscanf(f, "%d", &value);
  fclose(f);
  return n == 1 ? value : -1;
}

static int ensure_sysctl(const struct relayd_interface *iface, const char *key,
                         int expected) {
  int old = read_sysctl(iface, key);
  if (old == expected)
    return 0;
  if (!link_ready(iface))
    return -1;
  char path[128], value[16];
  snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/%s", iface->ifname, key);
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0)
    goto error;
  int len = snprintf(value, sizeof(value), "%d\n", expected);
  ssize_t written = write(fd, value, len);
  int saved = errno;
  close(fd);
  errno = written < 0 ? saved : EIO;
  if (written != len || read_sysctl(iface, key) != expected)
    goto error;
  syslog(LOG_INFO, "Recovered %s/%s: %d -> %d", iface->ifname, key, old, expected);
  return 0;
error:
  syslog(LOG_WARNING, "Unable to restore %s/%s=%d: %s", iface->ifname, key,
         expected, strerror(errno));
  return -1;
}

static int ensure_sysctls(const struct relayd_interface *iface) {
  // Set RA policy before enabling IPv6 so that the kernel uses the right policy
  // as it recreates its link-local address and starts router discovery.
  int status = ensure_sysctl(iface, "accept_ra", iface == &config->master ? 2 : 0);
  if (ensure_sysctl(iface, "disable_ipv6", 0) < 0)
    status = -1;
  return status;
}

static void arm_timer(void) {
  int64_t first = 0;
  for (size_t i = 0; i < state_count; ++i)
    if (states[i].pending && (!first || states[i].due < first))
      first = states[i].due;
  struct itimerspec ts = {0};
  if (first) {
    ts.it_value.tv_sec = first / 1000;
    ts.it_value.tv_nsec = (first % 1000) * 1000000;
  }
  timerfd_settime(timer.socket, TFD_TIMER_ABSTIME, &ts, NULL);
}

void relayd_recovery_request(const struct relayd_interface *iface) {
  struct recovery_state *s = find_state(iface);
  if (!s || s->running || s->pending || !link_ready(iface))
    return;
  int64_t now = now_ms();
  // Repeated packet errors cannot bypass the per-interface cooldown.
  s->pending = true;
  s->attempts = 0;
  s->due = now + 250 > s->cooldown ? now + 250 : s->cooldown; // Coalesce the reset's address/route notifications.
  arm_timer();
}

bool relayd_recovery_paused(const struct relayd_interface *iface) {
  return find_state(iface) && !link_ready(iface);
}

bool relayd_recovery_preserve_neighbor(const struct relayd_interface *iface) {
  struct recovery_state *s = find_state(iface);
  if (!s)
    return false;
  if (!link_ready(iface) || read_sysctl(iface, "disable_ipv6") == 1) {
    s->reset = true;
    s->reset_until = now_ms() + 5000;
    return true;
  }
  return now_ms() < s->reset_until;
}

bool relayd_recovery_error(const struct relayd_interface *iface, int error) {
  struct recovery_state *s = find_state(iface);
  if (!s || (error != ENETUNREACH && error != EHOSTUNREACH &&
             error != ENETDOWN && error != EADDRNOTAVAIL && error != ENODEV))
    return true;
  relayd_recovery_request(iface);
  int64_t now = now_ms();
  if (now < s->log_after)
    return false;
  s->log_after = now + RECOVERY_COOLDOWN_MS;
  return true;
}

int relayd_rejoin_group(int socket, const struct in6_addr *group, int ifindex) {
  struct ipv6_mreq req = {*group, ifindex};
  if (setsockopt(socket, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &req, sizeof(req)) < 0 &&
      errno != EADDRINUSE) {
    syslog(LOG_WARNING, "Unable to restore multicast membership on interface %d: %s",
           ifindex, strerror(errno));
    return -1;
  }
  return 0;
}

// Recreate a missing connected route without changing an existing route. Kernel
// address routes use metric 256; using the learned-route metric would add duplicates.
// Do not use EXCL: the same prefix/metric also exists on the upstream interface.
static int ensure_prefix_route(const struct relayd_interface *iface,
                               const struct in6_addr *address, uint8_t prefix,
                               uint32_t lifetime) {
  struct in6_addr network = *address;
  for (unsigned bit = prefix; bit < 128; ++bit)
    network.s6_addr[bit / 8] &= ~(1u << (7 - bit % 8));
  struct {
    struct nlmsghdr nh;
    struct rtmsg rt;
    struct rtattr dst_attr;
    struct in6_addr dst;
    struct rtattr oif_attr;
    uint32_t oif;
    struct rtattr metric_attr;
    uint32_t metric;
    struct rtattr lifetime_attr;
    uint32_t lifetime;
  } req = {
      .nh = {sizeof(req), RTM_NEWROUTE, NLM_F_CREATE, 0, 0},
      .rt = {.rtm_family = AF_INET6, .rtm_dst_len = prefix,
             .rtm_table = RT_TABLE_MAIN, .rtm_protocol = RTPROT_KERNEL,
             .rtm_scope = RT_SCOPE_LINK, .rtm_type = RTN_UNICAST},
      .dst_attr = {RTA_LENGTH(sizeof(network)), RTA_DST}, .dst = network,
      .oif_attr = {RTA_LENGTH(sizeof(uint32_t)), RTA_OIF}, .oif = iface->ifindex,
      .metric_attr = {RTA_LENGTH(sizeof(uint32_t)), RTA_PRIORITY}, .metric = 256,
      .lifetime_attr = {RTA_LENGTH(sizeof(uint32_t)), RTA_EXPIRES}, .lifetime = lifetime,
  };
  if (lifetime == UINT32_MAX)
    req.nh.nlmsg_len = offsetof(__typeof__(req), lifetime_attr);
  if (relayd_netlink_request(&req.nh) < 0 && errno != EEXIST) {
    char text[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &network, text, sizeof(text));
    syslog(LOG_WARNING, "Unable to restore prefix route %s/%u on %s: %s",
           text, prefix, iface->ifname, strerror(errno));
    return -1;
  }
  return 0;
}

static int ensure_linklocal(const struct relayd_interface *iface) {
  struct ifaddrs *list;
  if (getifaddrs(&list) < 0)
    return -1;
  bool found = false;
  struct in6_addr address = IN6ADDR_ANY_INIT;
  for (struct ifaddrs *a = list; a; a = a->ifa_next) {
    if (a->ifa_addr && a->ifa_addr->sa_family == AF_INET6 &&
        !strcmp(a->ifa_name, iface->ifname)) {
      struct sockaddr_in6 *in6 = (void *)a->ifa_addr;
      if (IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr)) {
        address = in6->sin6_addr;
        found = true;
        break;
      }
    }
  }
  freeifaddrs(list);
  if (!found) {
    // Kernel-generated LL addresses usually return when IPv6 is re-enabled.
    // If only the address was flushed, recreate an EUI-64 address with DAD.
    address.s6_addr[0] = 0xfe;
    address.s6_addr[1] = 0x80;
    memcpy(&address.s6_addr[8], iface->mac, 3);
    address.s6_addr[8] ^= 2;
    address.s6_addr[11] = 0xff;
    address.s6_addr[12] = 0xfe;
    memcpy(&address.s6_addr[13], iface->mac + 3, 3);
    struct {
      struct nlmsghdr nh;
      struct ifaddrmsg ifa;
      struct rtattr attr;
      struct in6_addr address;
    } req = {
        .nh = {sizeof(req), RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, 0, 0},
        .ifa = {AF_INET6, 64, 0, RT_SCOPE_LINK, iface->ifindex},
        .attr = {RTA_LENGTH(sizeof(address)), IFA_ADDRESS}, .address = address,
    };
    if (relayd_netlink_request(&req.nh) < 0 && errno != EEXIST)
      return -1;
  }
  return ensure_prefix_route(iface, &address, 64, UINT32_MAX);
}

static int restore_addresses(const struct relayd_interface *iface) {
  if (iface == &config->master)
    return 0; // Relearn upstream configuration from RA, rather than invent it.
  struct relayd_ipaddr source[RECOVERY_ADDR_LIMIT], target[RECOVERY_ADDR_LIMIT];
  ssize_t ns = relayd_get_interface_addresses(config->master.ifindex, source,
                                             ARRAY_SIZE(source));
  ssize_t nt = relayd_get_interface_addresses(iface->ifindex, target, ARRAY_SIZE(target));
  if (ns < 0 || nt < 0 || ns == ARRAY_SIZE(source) || nt == ARRAY_SIZE(target))
    return -1; // Do not act on an incomplete snapshot.
  int status = 0;
  for (ssize_t i = 0; i < ns; ++i) {
    if (!source[i].valid)
      continue;
    bool found = false;
    for (ssize_t j = 0; j < nt; ++j)
      if (source[i].prefix == target[j].prefix &&
          IN6_ARE_ADDR_EQUAL(&source[i].addr, &target[j].addr))
        found = true;
    if (!(source[i].flags & IFA_F_NOPREFIXROUTE) &&
        ensure_prefix_route(iface, &source[i].addr, source[i].prefix,
                            source[i].valid) < 0)
      status = -1;
    if (found)
      continue;
    if (!link_ready(iface))
      return -1;
    uint32_t flags = source[i].flags & (IFA_F_NODAD | IFA_F_NOPREFIXROUTE |
                                       IFA_F_MANAGETEMPADDR);
    struct {
      struct nlmsghdr nh;
      struct ifaddrmsg ifa;
      struct rtattr address_attr;
      struct in6_addr address;
      struct rtattr cache_attr;
      struct ifa_cacheinfo cache;
      struct rtattr flags_attr;
      uint32_t flags;
    } req = {
        .nh = {sizeof(req), RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, 0, 0},
        .ifa = {AF_INET6, source[i].prefix, flags & 0xff, RT_SCOPE_UNIVERSE,
                iface->ifindex},
        .address_attr = {RTA_LENGTH(sizeof(struct in6_addr)), IFA_ADDRESS},
        .address = source[i].addr,
        .cache_attr = {RTA_LENGTH(sizeof(struct ifa_cacheinfo)), IFA_CACHEINFO},
        .cache = {.ifa_prefered = source[i].preferred, .ifa_valid = source[i].valid},
        .flags_attr = {RTA_LENGTH(sizeof(uint32_t)), IFA_FLAGS},
        .flags = flags,
    };
    if (relayd_netlink_request(&req.nh) < 0 && errno != EEXIST) {
      char text[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &source[i].addr, text, sizeof(text));
      syslog(LOG_WARNING, "Unable to restore address %s on %s: %s",
             text, iface->ifname, strerror(errno));
      status = -1;
    }
  }
  return status;
}

static void recover(struct relayd_event *event) {
  uint64_t count;
  if (read(event->socket, &count, sizeof(count)) < 0)
    return;
  for (size_t i = 0; i < state_count; ++i) {
    struct recovery_state *s = &states[i];
    if (!s->pending || s->due > now_ms())
      continue;
    if (!link_ready(s->iface)) {
      s->pending = false;
      continue;
    }
    s->running = true;
    ++s->attempts;
    syslog(LOG_INFO, "Checking IPv6 state on %s (attempt %u/%u)",
           s->iface->ifname, s->attempts, RECOVERY_ATTEMPTS);
    int status = ensure_sysctls(s->iface);
    if (!status && link_ready(s->iface)) {
      if (ensure_linklocal(s->iface) < 0)
        status = -1;
      if (restore_addresses(s->iface) < 0)
        status = -1;
      if (relayd_recover_routes(s->iface->ifindex) < 0)
        status = -1;
      if (relayd_ndp_recover(s->iface, s->reset) < 0)
        status = -1;
      if (relayd_router_recover(s->iface) < 0 ||
          relayd_dhcpv6_recover(s->iface) < 0)
        status = -1;
    }
    s->running = false;
    if (status < 0 && s->attempts < RECOVERY_ATTEMPTS) {
      s->due = now_ms() + (1000 << (s->attempts - 1));
    } else {
      if (!status)
        s->reset = false;
      s->pending = false;
      s->cooldown = now_ms() + (status < 0 ? RECOVERY_COOLDOWN_MS : 5000);
      if (status < 0)
        syslog(LOG_WARNING, "IPv6 recovery on %s paused after %u attempts",
               s->iface->ifname, s->attempts);
    }
  }
  arm_timer();
}

void relayd_recovery_event(const struct nlmsghdr *nh) {
  if (!state_count)
    return;
  if ((nh->nlmsg_type == RTM_NEWLINK || nh->nlmsg_type == RTM_DELLINK) &&
      NLMSG_PAYLOAD(nh, 0) >= sizeof(struct ifinfomsg)) {
    const struct ifinfomsg *ifi = NLMSG_DATA(nh);
    const char *name = NULL;
    int alen = IFLA_PAYLOAD(nh);
    for (struct rtattr *a = IFLA_RTA(ifi); RTA_OK(a, alen); a = RTA_NEXT(a, alen))
      if (a->rta_type == IFLA_IFNAME && RTA_PAYLOAD(a) > 0 &&
          memchr(RTA_DATA(a), 0, RTA_PAYLOAD(a)))
        name = RTA_DATA(a);
    for (size_t i = 0; i < state_count; ++i) {
      struct recovery_state *s = &states[i];
      if (s->iface->ifindex != ifi->ifi_index) {
        if (name && !strcmp(name, s->iface->ifname) && !s->replaced) {
          s->replaced = true;
          syslog(LOG_WARNING, "Interface %s was recreated with a new index; restart 6relayd",
                 name);
        }
        continue;
      }
      bool up = nh->nlmsg_type == RTM_NEWLINK &&
                (ifi->ifi_flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING);
      if (!up) {
        s->pending = false;
        s->reset = true;
        s->reset_until = now_ms() + 5000;
      } else if (!s->up) {
        s->cooldown = 0;
        s->reset = true;
        s->reset_until = now_ms() + 5000;
        relayd_recovery_request(s->iface);
      } else if (read_sysctl(s->iface, "disable_ipv6") != 0 ||
                 read_sysctl(s->iface, "accept_ra") !=
                     (s->iface == &config->master ? 2 : 0)) {
        relayd_recovery_request(s->iface);
      }
      s->up = up;
    }
    arm_timer();
  } else if (nh->nlmsg_type == RTM_DELADDR &&
             NLMSG_PAYLOAD(nh, 0) >= sizeof(struct ifaddrmsg)) {
    const struct ifaddrmsg *ifa = NLMSG_DATA(nh);
    if (ifa->ifa_family != AF_INET6)
      return;
    for (size_t i = 0; i < state_count; ++i) {
      if (states[i].iface->ifindex == (int)ifa->ifa_index) {
        if (ifa->ifa_scope == RT_SCOPE_LINK) {
          states[i].reset = true;
          states[i].reset_until = now_ms() + 5000;
        }
        relayd_recovery_request(states[i].iface);
      }
    }
  } else if (nh->nlmsg_type == RTM_DELROUTE) {
    int index = relayd_lost_route_interface(nh);
    if (!index && NLMSG_PAYLOAD(nh, 0) >= sizeof(struct rtmsg)) {
      const struct rtmsg *rt = NLMSG_DATA(nh);
      if (rt->rtm_family == AF_INET6 &&
          (rt->rtm_protocol == RTPROT_KERNEL || rt->rtm_dst_len == 0)) {
        int len = RTM_PAYLOAD(nh);
        for (struct rtattr *a = RTM_RTA(rt); RTA_OK(a, len); a = RTA_NEXT(a, len))
          if (a->rta_type == RTA_OIF && RTA_PAYLOAD(a) >= sizeof(index))
            memcpy(&index, RTA_DATA(a), sizeof(index));
      }
    }
    for (size_t i = 0; i < state_count; ++i)
      if (states[i].iface->ifindex == index)
        relayd_recovery_request(states[i].iface);
  }
}

int relayd_init_recovery(const struct relayd_config *relayd_config) {
  config = relayd_config;
  if (!config->enable_ndp_relay || !config->master.ifindex || !config->slavecount)
    return 0;
  states = calloc(config->slavecount + 1, sizeof(*states));
  if (!states)
    return -1;
  link_socket = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  timer.socket = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (link_socket < 0 || timer.socket < 0 || relayd_register_event(&timer) < 0)
    return -1;
  state_count = config->slavecount + 1;
  for (size_t i = 0; i < state_count; ++i) {
    states[i].iface = i ? &config->slaves[i - 1] : &config->master;
    states[i].up = link_ready(states[i].iface);
    if (states[i].up) {
      ensure_sysctls(states[i].iface);
      relayd_recovery_request(states[i].iface);
    }
  }
  return 0;
}

void relayd_deinit_recovery(void) {
  state_count = 0;
  free(states);
  states = NULL;
  if (timer.socket >= 0)
    close(timer.socket);
  if (link_socket >= 0)
    close(link_socket);
  timer.socket = link_socket = -1;
}
