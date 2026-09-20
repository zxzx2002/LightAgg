/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/
parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        transition reject;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser MyIngressParser(packet_in packet,
                out headers hdr,
                out metadata meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {  

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(packet, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_COUNTFLAG: parse_countFlag;  
            TYPE_MYTUNNEL: parse_myTunnel;
            TYPE_IPV4: parse_ipv4;
            TYPE_REGMIG: parse_regMig;
            default: accept;
        }
    }

    state parse_countFlag {
        packet.extract(hdr.countFlag);
        transition select(packet.lookahead<bit<16>>()) {
            TYPE_MYTUNNEL: parse_myTunnel;
            default: parse_ipv4;
        }
    }

    state parse_myTunnel {
        packet.extract(hdr.myTunnel);
        transition select(hdr.myTunnel.proto_id) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_regMig {
        packet.extract(hdr.regMig);
        transition parse_ipv4; 
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6  : parse_tcp;
            17 : parse_udp; 
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            16w4791: parse_bth; 
            default: accept;
        }
    }

    state parse_bth {
        packet.extract(hdr.bth);
        transition select(hdr.bth.opcode) {
            8w10: parse_reth; 
            8w11: parse_reth; 
            default: accept;
        }
    }

    state parse_reth {
        packet.extract(hdr.reth);
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
control MyIngressDeparser(packet_out packet,
    inout headers hdr,
    in metadata meta,
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.countFlag);
        packet.emit(hdr.myTunnel);
        packet.emit(hdr.regMig);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.bth);
        packet.emit(hdr.reth); 
    }
}

parser MyEgressParser(
        packet_in packet,
        out headers hdr,
        out metadata meta,
        out egress_intrinsic_metadata_t eg_intr_md) {  

    state start {
        packet.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_COUNTFLAG: parse_countFlag;  
            TYPE_MYTUNNEL: parse_myTunnel;
            TYPE_IPV4: parse_ipv4;
            TYPE_REGMIG: parse_regMig;
            default: accept;
        }
    }

    state parse_countFlag {
        packet.extract(hdr.countFlag);
        transition select(packet.lookahead<bit<16>>()) {
            TYPE_MYTUNNEL: parse_myTunnel;
            default: parse_ipv4;
        }
    }

    state parse_myTunnel {
        packet.extract(hdr.myTunnel);
        transition select(hdr.myTunnel.proto_id) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_regMig {
        packet.extract(hdr.regMig);
        transition parse_ipv4; 
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6  : parse_tcp;
            17 : parse_udp; 
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            16w4791: parse_bth;
            default: accept;
        }
    }

    state parse_bth {
        packet.extract(hdr.bth);
        transition select(hdr.bth.opcode) {
            8w10: parse_reth;
            8w11: parse_reth;
            default: accept;
        }
    }

    state parse_reth {
        packet.extract(hdr.reth);
        transition accept;
    }
}

control MyEgressDeparser(
        packet_out packet,
        inout headers hdr,
        in metadata meta,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    apply {
        packet.emit(hdr.ethernet);
        // packet.emit(hdr.countFlag);  
        // packet.emit(hdr.myTunnel);
        packet.emit(hdr.regMig);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp); 
        packet.emit(hdr.bth); 
        packet.emit(hdr.reth); 
    }
}