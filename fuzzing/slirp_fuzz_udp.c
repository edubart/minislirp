#ifdef _WIN32
/* as defined in sdkddkver.h */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600 /* Vista */
#endif
#include <ws2tcpip.h>
#endif

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include "../src/libslirp.h"
#include "helper.h"

size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int connect(int sockfd, const struct sockaddr *addr,
            socklen_t addrlen)
{
    /* FIXME: fail on some addr? */
    return 0;
}

int listen(int sockfd, int backlog)
{
    return 0;
}

int bind(int sockfd, const struct sockaddr *addr,
         socklen_t addrlen)
{
    /* FIXME: fail on some addr? */
    return 0;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    /* FIXME: partial send? */
    return len;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)
{
    /* FIXME: partial send? */
    return len;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    memset(buf, 0, len);
    return len / 2;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)
{
    memset(buf, 0, len);
    memset(src_addr,0,*addrlen);
    return len / 2;
}

int setsockopt(int sockfd, int level, int optname,
               const void *optval, socklen_t optlen)
{
    return 0;
}

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
static void empty_logging_func(const gchar *log_domain,
                               GLogLevelFlags log_level, const gchar *message,
                               gpointer user_data)
{
}
#endif

/* Disables logging for oss-fuzz. Must be used with each target. */
static void fuzz_set_logging_func(void)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    g_log_set_default_handler(empty_logging_func, NULL);
#endif
}

static ssize_t send_packet(const void *pkt, size_t pkt_len, void *opaque)
{
    return pkt_len;
}

static int64_t clock_get_ns(void *opaque)
{
    return 0;
}

static void *timer_new(SlirpTimerCb cb, void *cb_opaque, void *opaque)
{
    return NULL;
}

static void timer_mod(void *timer, int64_t expire_timer, void *opaque)
{
}

static void timer_free(void *timer, void *opaque)
{
}

static void guest_error(const char *msg, void *opaque)
{
}

static void register_poll_fd(int fd, void *opaque)
{
}

static void unregister_poll_fd(int fd, void *opaque)
{
}

static void notify(void *opaque)
{
}

static const SlirpCb slirp_cb = {
    .send_packet = send_packet,
    .guest_error = guest_error,
    .clock_get_ns = clock_get_ns,
    .timer_new = timer_new,
    .timer_mod = timer_mod,
    .timer_free = timer_free,
    .register_poll_fd = register_poll_fd,
    .unregister_poll_fd = unregister_poll_fd,
    .notify = notify,
};

#define MAX_EVID 1024
static int fake_events[MAX_EVID];

static int add_poll_cb(int fd, int events, void *opaque)
{
    g_assert(fd < G_N_ELEMENTS(fake_events));
    fake_events[fd] = events;
    return fd;
}

static int get_revents_cb(int idx, void *opaque)
{
    return fake_events[idx] & ~(SLIRP_POLL_ERR|SLIRP_POLL_HUP);
}

typedef struct pcap_hdr_s {
        guint32 magic_number;   /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;


#ifdef CUSTOM_MUTATOR
extern size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

/// This is a custom mutator, this allows us to mutate only specific parts of 
/// the input and fix the checksum so the packet isn't rejected for bad reasons.
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed)
{
    size_t i, current_size = Size;
    uint8_t *Data_ptr = Data;
    uint8_t *ip_data;

    pcap_hdr_t *hdr = (void *)Data_ptr;
    pcaprec_hdr_t *rec = NULL;

    if (current_size < sizeof(pcap_hdr_t)) {
        return 0;
    }

    Data_ptr += sizeof(*hdr);
    current_size -= sizeof(*hdr);

    if (hdr->magic_number == 0xd4c3b2a1) {
        g_debug("FIXME: byteswap fields");
        return 0;
    } /* else assume native pcap file */
    if (hdr->network != 1) {
        return 0;
    }

    while (current_size > sizeof(*rec)) {
        rec = (void *)Data_ptr;
        Data_ptr += sizeof(*rec);
        current_size -= sizeof(*rec);

        if (rec->incl_len != rec->orig_len) {
            break;
        }
        if (rec->incl_len > current_size) {
            break;
        }
        ip_data = Data_ptr + 14;

        // Exclude packets that are not UDP from the mutation strategy
        if (ip_data[9] != IPPROTO_UDP) {
            Data_ptr += rec->incl_len;
            current_size -= rec->incl_len;
            continue;
        }
        // Allocate a bit more than needed, this is useful for
        // checksum calculation.
        uint8_t Data_to_mutate[MaxSize+12];
        uint8_t ip_hl = (ip_data[0] & 0xF);
        uint8_t ip_hl_in_bytes = ip_hl * 4;

        uint8_t *start_of_udp = ip_data + ip_hl_in_bytes;
        uint16_t udp_size = ntohs(*((uint16_t *)start_of_udp + 2));

        // The size inside the packet can't be trusted, if it is too big it can 
        // lead to heap overflows in the fuzzing code.
        // Fixme : don't use udp_size inside the fuzzing code, maybe use the
        //         rec->incl_len and manually calculate the size.
        if (udp_size >= MaxSize || udp_size >= rec->incl_len) {
            Data_ptr += rec->incl_len;
            current_size -= rec->incl_len;
            continue;
        }

        // Copy interesting data to the `Data_to_mutate` array
        // here we want to fuzz everything in the udp packet
        memset(Data_to_mutate,0,MaxSize+12);
        memcpy(Data_to_mutate,start_of_udp,udp_size);

        // Call to libfuzzer's mutation function.
        // Pass the whole UDP packet, mutate it and then fix checksum value 
        // so the packet isn't rejected.
        // The new size of the data is returned by LLVMFuzzerMutate.
        // Fixme: allow to change the size of the UDP packet, this will require
        //     to fix the size before calculating the new checksum and change
        //     how the Data_ptr is advanced.
        //     Most offsets bellow should be good for when the switch will be
        //     done to avoid overwriting new/mutated data.
        size_t mutated_size = LLVMFuzzerMutate(Data_to_mutate, udp_size, udp_size);

        // Set the `checksum` field to 0 to calculate the new checksum
        *((uint16_t *)Data_to_mutate + 3) = (uint16_t)0;
        // Copy the source and destination IP addresses, the UDP length and 
        // protocol number at the end of the `Data_to_mutate` array to calculate
        // the new checksum.
        for (i = 0; i < 4; i++)
        {   
            *(Data_to_mutate + mutated_size + i) = *(ip_data + 12 + i);
        }
        for (i = 0; i < 4; i++)
        {
            *(Data_to_mutate + mutated_size + 4 + i) = *(ip_data + 16 + i);
        }

        *(Data_to_mutate + mutated_size + 8) = *(start_of_udp + 4);
        *(Data_to_mutate + mutated_size + 9) = *(start_of_udp + 5);
        // The protocol is a uint8_t, it follows a 0uint8_t for checksum 
        // calculation.
        *(Data_to_mutate + mutated_size + 11) = IPPROTO_UDP;

        uint16_t new_checksum = compute_checksum(Data_to_mutate, mutated_size + 12);
        *((uint16_t *)Data_to_mutate + 3) = new_checksum;

        // Copy the mutated data back to the `Data` array
        memcpy(start_of_udp,Data_to_mutate,mutated_size);

        Data_ptr += rec->incl_len;
        current_size -= rec->incl_len;
    }
    return Size;
}
#endif //CUSTOM_MUTATOR


// Fuzzing strategy is the following : 
//  The custom mutator :
//      - extract the packets from the pcap one by one,
//      - mutates the ip header and put it back inside the pcap
//          this is required because we need the pcap structure to separate them
//          before we send them to slirp.
//  LLVMFuzzerTestOneInput :
//      - build a slirp instance,
//      - extract the packets from the pcap one by one,
//      - send the data to `slirp_input`
//      - call `slirp_pollfds_fill` and `slirp_pollfds_poll` to advance slirp
//      - cleanup slirp when the whole pcap has been unwrapped.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Slirp *slirp = NULL;
    struct in_addr net = { .s_addr = htonl(0x0a000200) }; /* 10.0.2.0 */
    struct in_addr mask = { .s_addr = htonl(0xffffff00) }; /* 255.255.255.0 */
    struct in_addr host = { .s_addr = htonl(0x0a000202) }; /* 10.0.2.2 */
    struct in_addr dhcp = { .s_addr = htonl(0x0a00020f) }; /* 10.0.2.15 */
    struct in_addr dns = { .s_addr = htonl(0x0a000203) }; /* 10.0.2.3 */
    struct in6_addr ip6_prefix;
    struct in6_addr ip6_host;
    struct in6_addr ip6_dns;
    int ret, vprefix6_len = 64;
    const char *vhostname = NULL;
    const char *tftp_server_name = NULL;
    const char *tftp_export = NULL;
    const char *bootfile = NULL;
    const char **dnssearch = NULL;
    const char *vdomainname = NULL;
    const pcap_hdr_t *hdr = (const void *)data;
    const pcaprec_hdr_t *rec = NULL;
    uint32_t timeout = 0;

    if (size < sizeof(pcap_hdr_t)) {
        return 0;
    }
    data += sizeof(*hdr);
    size -= sizeof(*hdr);

    if (hdr->magic_number == 0xd4c3b2a1) {
        g_debug("FIXME: byteswap fields");
        return 0;
    } /* else assume native pcap file */
    if (hdr->network != 1) {
        return 0;
    }

    fuzz_set_logging_func();

    ret = inet_pton(AF_INET6, "fec0::", &ip6_prefix);
    g_assert_cmpint(ret, ==, 1);

    ip6_host = ip6_prefix;
    ip6_host.s6_addr[15] |= 2;
    ip6_dns = ip6_prefix;
    ip6_dns.s6_addr[15] |= 3;

    slirp =
        slirp_init(false, true, net, mask, host, true, ip6_prefix, vprefix6_len,
                   ip6_host, vhostname, tftp_server_name, tftp_export, bootfile,
                   dhcp, dns, ip6_dns, dnssearch, vdomainname, &slirp_cb, NULL);

    while (size > sizeof(*rec)) {
        rec = (const void *)data;
        data += sizeof(*rec);
        size -= sizeof(*rec);
        if (rec->incl_len != rec->orig_len) {
            g_debug("unsupported rec->incl_len != rec->orig_len");
            break;
        }
        if (rec->incl_len > size) {
            break;
        }

        slirp_input(slirp, data, rec->incl_len);
        slirp_pollfds_fill(slirp, &timeout, add_poll_cb, NULL);
        slirp_pollfds_poll(slirp, 0, get_revents_cb, NULL);

        data += rec->incl_len;
        size -= rec->incl_len;
    }

    slirp_cleanup(slirp);

    return 0;
}
