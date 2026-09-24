/* Integration tests; run in an isolated network namespace. */
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "6relayd.h"

int relayd_open_rtnl_socket(void) {
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  assert(fd >= 0);
  struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
  assert(connect(fd, (void *)&kernel, sizeof(kernel)) == 0);
  struct timeval timeout = {2, 0};
  assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
  return fd;
}

static int count_routes(const struct in6_addr *dst, int prefix, int protocol,
                        int ifindex, const struct in6_addr *gateway) {
  int fd = relayd_open_rtnl_socket();
  struct {
    struct nlmsghdr nh;
    struct rtmsg rt;
  } req = {{sizeof(req), RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, 1, 0},
           {.rtm_family = AF_INET6}};
  assert(send(fd, &req, sizeof(req), 0) == sizeof(req));
  int found = 0;
  for (;;) {
    char buf[16384];
    ssize_t len = recv(fd, buf, sizeof(buf), 0);
    assert(len > 0);
    for (struct nlmsghdr *nh = (void *)buf; NLMSG_OK(nh, len);
         nh = NLMSG_NEXT(nh, len)) {
      if (nh->nlmsg_type == NLMSG_DONE) {
        close(fd);
        return found;
      }
      assert(nh->nlmsg_type == RTM_NEWROUTE);
      struct rtmsg *rt = NLMSG_DATA(nh);
      if (rt->rtm_protocol != protocol || rt->rtm_dst_len != prefix)
        continue;
      struct in6_addr actual_dst = IN6ADDR_ANY_INIT, actual_gw = IN6ADDR_ANY_INIT;
      int actual_ifindex = 0;
      int alen = RTM_PAYLOAD(nh);
      for (struct rtattr *a = RTM_RTA(rt); RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
        if (a->rta_type == RTA_DST)
          memcpy(&actual_dst, RTA_DATA(a), sizeof(actual_dst));
        if (a->rta_type == RTA_GATEWAY)
          memcpy(&actual_gw, RTA_DATA(a), sizeof(actual_gw));
        if (a->rta_type == RTA_OIF)
          memcpy(&actual_ifindex, RTA_DATA(a), sizeof(actual_ifindex));
      }
      struct in6_addr zero = IN6ADDR_ANY_INIT;
      if (actual_ifindex == ifindex && IN6_ARE_ADDR_EQUAL(dst, &actual_dst) &&
          IN6_ARE_ADDR_EQUAL(gateway ? gateway : &zero, &actual_gw))
        ++found;
    }
  }
}

int main(void) {
  struct relayd_interface iface = {.ifindex = if_nametoindex("test0")};
  strcpy(iface.ifname, "test0");
  assert(iface.ifindex > 0);
  struct in6_addr host, prefix, gateway, conflict;
  assert(inet_pton(AF_INET6, "2001:db8:1::123", &host) == 1);
  assert(inet_pton(AF_INET6, "2001:db8:2::", &prefix) == 1);
  assert(inet_pton(AF_INET6, "fe80::2", &gateway) == 1);
  assert(inet_pton(AF_INET6, "2001:db8:3::1", &conflict) == 1);
  assert(relayd_init_netlink(77) == 0);
  assert(relayd_setup_route(&host, 128, &iface, NULL, true) == 0);
  assert(count_routes(&host, 128, 77, iface.ifindex, NULL) == 1);
  assert(relayd_setup_route(&host, 128, &iface, NULL, true) == 0);
  assert(count_routes(&host, 128, 77, iface.ifindex, NULL) == 1);
  assert(relayd_setup_route(&host, 128, &iface, NULL, false) == 0);
  assert(count_routes(&host, 128, 77, iface.ifindex, NULL) == 0);
  assert(relayd_setup_route(&host, 128, &iface, NULL, false) == 0);
  assert(relayd_setup_route(&host, 128, &iface, NULL, true) == 0);
  assert(relayd_setup_route(&prefix, 64, &iface, &gateway, true) == 0);
  assert(count_routes(&prefix, 64, 77, iface.ifindex, &gateway) == 1);
  assert(relayd_setup_route(&prefix, 64, &iface, &gateway, false) == 0);
  assert(count_routes(&prefix, 64, 77, iface.ifindex, &gateway) == 0);
  assert(relayd_setup_route(&prefix, 64, &iface, &gateway, true) == 0);

  // A pre-existing route (even with the same protocol) is not ours to delete.
  assert(relayd_setup_route(&conflict, 128, &iface, NULL, true) == -1);
  assert(errno == EEXIST);
  assert(relayd_setup_route(&conflict, 128, &iface, NULL, false) == 0);
  struct relayd_interface missing = {.ifindex = 999999};
  strcpy(missing.ifname, "missing");
  assert(relayd_setup_route(&host, 128, &missing, NULL, true) == -1);
  assert(errno == ENODEV);
  relayd_deinit_netlink();
  assert(count_routes(&host, 128, 77, iface.ifindex, NULL) == 0);
  assert(count_routes(&prefix, 64, 77, iface.ifindex, &gateway) == 0);
  assert(count_routes(&conflict, 128, 77, iface.ifindex, NULL) == 1);
  puts("Netlink route integration tests passed");
}
