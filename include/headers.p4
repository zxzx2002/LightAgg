/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
const bit<16> TYPE_MYTUNNEL = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_REGMIG = 0x1414;  
const bit<16> TYPE_COUNTFLAG = 0x1515;

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header myTunnel_t {
    bit<16> proto_id;
    bit<48> ig_tstamp;
    bit<48> eg_tstamp;
}

header regMig_t {
    bit<32> index;
    bit<32> value0;
    bit<32> value1;
    bit<32> value2;
    bit<8>  if_finish;
    bit<32> hash_check;

    bit<48> ingress_tstamp;
    bit<48> egress_tstamp;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header bth_t {
    bit<8>  opcode;
    bit<1>  se;
    bit<1>  m;
    bit<2>  padcnt;
    bit<4>  tver;
    bit<16> pkey;
    bit<8>  fecn_becn_resv;
    bit<24> dest_qp;
    bit<1>  ack_req;
    bit<7>  resv;
    bit<24> psn;
}

header reth_t {
    bit<64> virtual_address; 
    bit<32> r_key;           
    bit<32> dma_length;      
}

header countFlag_t {
    bit<8> is_counted;  
}

struct metadata {
    bit<32> index_sketch0;
    bit<32> index_sketch1;
    bit<32> index_sketch2;
    bit<32> computed_hash;

    bit<32> index;
    bit<1>  flag1;
    bit<1>  flag2;
}

struct headers {
    ethernet_t   ethernet;
    countFlag_t  countFlag;  
    myTunnel_t   myTunnel;   
    regMig_t     regMig;     
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp; 
    bth_t        bth; 
    reth_t       reth; 
}