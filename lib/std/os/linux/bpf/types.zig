pub fn BigEndian(comptime T: type) type {
    switch (T) {
        u16, u32, u64 => {},
        else => @compileError("width must be 16, 32, or 64"),
    }

    return packed struct {
        data: T,

        const Self = @This();

        pub fn from(val: T) Self {
            return Self{
                .data = std.mem.nativeToBig(T, val),
            };
        }

        pub fn native(self: Self) T {
            return std.mem.bigToNative(T, self.data);
        }
    };
}

fn MdPtr(comptime T: type) type {
    comptime {
        std.debug.assert(@sizeOf(T) <= @sizeOf(u64));
    }

    return packed union {
        val: T,
        _: u64,
    };
}

/// User bpf_sock_addr struct to access socket fields and sockaddr struct passed
/// by user and intended to be used by socket (e.g. to bind to, depends on
/// attach type).
pub const BpfSockAddr = packed struct {
    user_family: u32,
    user_ip4: u32,
    user_ip6: [4]u32,
    user_port: u32,
    family: u32,
    type: u32,
    protocol: u32,
    msg_src_ip4: u32,
    msg_src_ip6: [4]u32,
    sk: MdPtr(*Sock),
};

pub const FibLookup = packed struct {
    family: u8,
    l4_protocol: u8,
    sport: BigEndian(u16),
    dport: BigEndian(u16),
    tot_len: u16,
    ifindex: u32,
    input_output: packed union {
        tos: u8,
        flowinfo: BigEndian(u32),
        rt_metric: u32,
    },
    src: packed union {
        ipv4: BigEndian(u32),
        ipv6: [4]u32,
    },
    h_vlan_proto: BigEndian(u16),
    h_vlan_TCI: BigEndian(u16),
    smac: [6]u8,
    dmac: [6]u8,
};

pub const PerfEventData = packed struct {};

pub const PerfEventValue = packed struct {
    counter: u64,
    enabled: u64,
    running: u64,
};

pub const PidNsInfo = packed struct {
    pid: u32,
    tgid: u32,
};

pub const SkBuff = packed struct {
    len: u32,
    pkt_type: u32,
    mark: u32,
    queue_mapping: u32,
    protocol: u32,
    vlan_present: u32,
    vlan_tci: u32,
    vlan_proto: u32,
    priority: u32,
    ingress_ifindex: u32,
    ifindex: u32,
    tc_index: u32,
    cb: [5]u32,
    hash: u32,
    tc_classid: u32,
    data: u32,
    data_end: u32,
    napi_id: u32,
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [4]u32,
    local_ip6: [4]u32,
    remote_port: u32,
    local_port: u32,
    data_meta: u32,
    flow_keys: MdPtr(*FlowKeys),
    tstamp: u64,
    wire_len: u32,
    gso_segs: u32,
    sk: MdPtr(*Sock),
    gso_size: u32,
};

pub const SkLookup = packed struct {
    sk: MdPtr(*Sock),
    family: u32,
    protocol: u32,
    remote_ip4: u32,
    remote_ip6: [4]u32,
    remote_port: u32,
    local_ip4: u32,
    local_ip6: [4]u32,
    local_port: u32,
};

pub const SkMsgBuff = packed struct {};

pub const SkReuseportMd = packed struct {
    data: u64,
    data_end: u64,
    len: u32,
    eth_protocol: u32,
    ip_protocol: u32,
    bind_inany: u32,
    hash: u32,
};

pub const Sock = packed struct {};
pub const SockAddr = packed struct {};

/// User bpf_sock_ops struct to access socket values and specify request ops and
/// their replies.  Some of this fields are in network (bigendian) byte order
/// and may need to be converted before use (bpf_ntohl() defined in
/// samples/bpf/bpf_endian.h).  New fields can only be added at the end of this
/// structure
pub const SockOps = packed struct {
    op: u32,
    optional: packed union {
        args: [4]u32,
        reply: u32,
        replylong: [4]u32,
    },
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [4]u32,
    local_ip6: [4]u32,
    remote_port: u32,
    local_port: u32,
    is_fullsock: u32,
    snd_cwnd: u32,
    srtt_us: u32,
    bpf_sock_ops_cb_flags: u32,
    state: u32,
    rtt_min: u32,
    snd_ssthresh: u32,
    rcv_nxt: u32,
    snd_nxt: u32,
    snd_una: u32,
    mss_cache: u32,
    ecn_flags: u32,
    rate_delivered: u32,
    rate_interval_us: u32,
    packets_out: u32,
    retrans_out: u32,
    total_retrans: u32,
    segs_in: u32,
    data_segs_in: u32,
    segs_out: u32,
    data_segs_out: u32,
    lost_out: u32,
    sacked_out: u32,
    sk_txhash: u32,
    bytes_received: u64,
    bytes_acked: u64,
    sk: MdPtr(*Sock),
};

pub const SockTuple = packed union {
    ipv4: packed struct {
        saddr: BigEndian(u32),
        daddr: BigEndian(u32),
        sport: BigEndian(u16),
        dport: BigEndian(u16),
    },
    ipv6: packed struct {
        saddr: [4]BigEndian(u32),
        daddr: [4]BigEndian(u32),
        sport: BigEndian(u16),
        dport: BigEndian(u16),
    },
};

pub const SpinLock = packed struct {
    val: u32,
};

pub const SysCtl = packed struct {
    /// sysctl is being read (0) or written (1), allows 1, 2, 4-byte read, but
    /// no write
    write: u32,

    /// sysctl file position to read from, write to. Allows 1,2,4-byte write.
    file_pos: u32,
};

pub const Tcp6Sock = packed struct {};
pub const TcpRequestSock = packed struct {};
pub const TcpSock = packed struct {};
pub const TcpTimewaitSock = packed struct {};

pub const TunnelKey = packed struct {
    id: u32,
    remote: extern union {
        ipv4: u32,
        ipv6: [4]u32,
    },
    tos: u8,
    ttl: u8,
    ext: u16,
    label: u32,
};

pub const Udp6Sock = packed struct {};

pub const XdpMd = packed struct {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
};

pub const XfrmStat = packed struct {
    reqid: u32,
    spi: u32,
    family: u16,
    ext: u16,
    remote: packed union {
        ipv4: u32,
        ipv6: [4]u32,
    },
};
