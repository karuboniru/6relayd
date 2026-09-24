/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "6relayd.h"

// Keep command replies separate from multicast notifications and dumps.
static int command_socket = -1;
static uint32_t command_seq;
static uint8_t route_protocol;
static struct list_head routes = LIST_HEAD_INIT(routes);

struct route_request {
  struct nlmsghdr nh;
  struct rtmsg rtm;
  struct rtattr rta_dst;
  struct in6_addr dst;
  struct rtattr rta_oif;
  uint32_t ifindex;
  struct rtattr rta_table;
  uint32_t table;
  struct rtattr rta_gw;
  struct in6_addr gw;
};

struct owned_route {
  struct list_head head;
  struct route_request request;
};

static int64_t monotonic_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int relayd_init_netlink(uint8_t protocol) {
  route_protocol = protocol;
  command_socket = relayd_open_rtnl_socket();
  return command_socket < 0 ? -1 : 0;
}

// A successful send only queues the operation. Wait for the kernel's ACK,
// with a bounded deadline, before reporting success to the caller.
int relayd_netlink_request(struct nlmsghdr *request) {
  if (command_socket < 0) {
    errno = EBADF;
    return -1;
  }
  request->nlmsg_flags |= NLM_F_REQUEST | NLM_F_ACK;
  request->nlmsg_seq = ++command_seq;
  request->nlmsg_pid = 0;
  if (send(command_socket, request, request->nlmsg_len, MSG_DONTWAIT) < 0)
    return -1;

  int64_t deadline = monotonic_ms() + 1000;
  for (;;) {
    int64_t remaining = deadline - monotonic_ms();
    if (remaining <= 0) {
      errno = ETIMEDOUT;
      return -1;
    }
    struct pollfd pfd = {command_socket, POLLIN, 0};
    int ready = poll(&pfd, 1, remaining);
    if (ready < 0 && errno == EINTR)
      continue;
    if (ready < 0)
      return -1;
    if (!ready)
      continue;

    union {
      struct nlmsghdr align;
      char data[RELAYD_BUFFER_SIZE];
    } buf;
    struct iovec iov = {buf.data, sizeof(buf.data)};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    ssize_t len = recvmsg(command_socket, &msg, MSG_DONTWAIT);
    if (len < 0) {
      if (errno == EINTR || errno == EAGAIN)
        continue;
      return -1;
    }
    if (msg.msg_flags & MSG_TRUNC) {
      errno = EMSGSIZE;
      return -1;
    }
    for (struct nlmsghdr *nh = (void *)buf.data; NLMSG_OK(nh, len);
         nh = NLMSG_NEXT(nh, len)) {
      if (nh->nlmsg_seq != request->nlmsg_seq)
        continue;
      if (nh->nlmsg_type != NLMSG_ERROR ||
          NLMSG_PAYLOAD(nh, 0) < sizeof(struct nlmsgerr)) {
        errno = EPROTO;
        return -1;
      }
      struct nlmsgerr *ack = NLMSG_DATA(nh);
      if (!ack->error)
        return 0;
      errno = -ack->error;
      // Deletion is idempotent if the object has already disappeared.
      if ((request->nlmsg_type == RTM_DELROUTE && errno == ESRCH) ||
          (request->nlmsg_type == RTM_DELADDR && errno == EADDRNOTAVAIL))
        return 0;
      return -1;
    }
  }
}

int relayd_setup_route(const struct in6_addr *addr, int prefixlen,
                       const struct relayd_interface *iface,
                       const struct in6_addr *gw, bool add) {
  if (!iface || iface->ifindex <= 0 || prefixlen < 0 || prefixlen > 128) {
    errno = EINVAL;
    return -1;
  }
  struct route_request req = {
      .nh = {.nlmsg_len = gw ? sizeof(req) : offsetof(struct route_request, rta_gw),
             .nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE,
             .nlmsg_flags = add ? NLM_F_CREATE | NLM_F_EXCL : 0},
      .rtm = {.rtm_family = AF_INET6,
              .rtm_dst_len = prefixlen,
              .rtm_protocol = route_protocol,
              .rtm_scope = gw ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK,
              .rtm_type = RTN_UNICAST},
      .rta_dst = {RTA_LENGTH(sizeof(*addr)), RTA_DST},
      .dst = *addr,
      .rta_oif = {RTA_LENGTH(sizeof(uint32_t)), RTA_OIF},
      .ifindex = iface->ifindex,
      .rta_table = {RTA_LENGTH(sizeof(uint32_t)), RTA_TABLE},
      .table = RT_TABLE_MAIN,
      .rta_gw = {RTA_LENGTH(sizeof(*gw)), RTA_GATEWAY},
  };
  if (gw)
    req.gw = *gw;

  struct owned_route *entry = NULL, *r;
  list_for_each_entry(r, &routes, head) {
    if (r->request.nh.nlmsg_len == req.nh.nlmsg_len &&
        !memcmp(&r->request.rtm, &req.rtm, req.nh.nlmsg_len - sizeof(req.nh))) {
      entry = r;
      break;
    }
  }
  // Never delete a route we did not successfully install.
  if (!add && !entry)
    return 0;

  struct owned_route *allocated = NULL;
  if (add && !entry && !(allocated = calloc(1, sizeof(*allocated))))
    return -1;

  int status = relayd_netlink_request(&req.nh);
  if (status < 0 && add && entry && errno == EEXIST)
    status = 0;
  if (status < 0) {
    int error = errno;
    char ipbuf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, addr, ipbuf, sizeof(ipbuf));
    syslog(LOG_ERR, "Unable to %s route %s/%d on %s (proto %u): %s",
           add ? "add" : "delete", ipbuf, prefixlen, iface->ifname,
           route_protocol, strerror(error));
    free(allocated);
    errno = error;
    return -1;
  }
  if (allocated) {
    allocated->request = req;
    list_add(&allocated->head, &routes);
  } else if (!add) {
    list_del(&entry->head);
    free(entry);
  }
  return 0;
}

void relayd_deinit_netlink(void) {
  // Do not flush every route sharing our protocol number: other interfaces
  // and other daemon instances may use it too.
  while (!list_empty(&routes)) {
    struct owned_route *r = list_first_entry(&routes, struct owned_route, head);
    r->request.nh.nlmsg_type = RTM_DELROUTE;
    r->request.nh.nlmsg_flags = 0;
    if (relayd_netlink_request(&r->request.nh) < 0)
      syslog(LOG_ERR, "Unable to remove route on interface %u: %s",
             r->request.ifindex, strerror(errno));
    list_del(&r->head);
    free(r);
  }
  if (command_socket >= 0)
    close(command_socket);
  command_socket = -1;
}
