#include <core.p4>
#include <tna.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 128
#define SKETCH_CELL_BIT_WIDTH 32

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control MyIngress(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    #define BLOOM_FILTER_REGISTER(num) \
        Register<bit<SKETCH_CELL_BIT_WIDTH>, bit<32>>(SKETCH_BUCKET_LENGTH) bloomfilter##num;\
        RegisterAction<bit<32>, bit<32>, bit<32>>(bloomfilter##num) \
            action_bloomfilter##num = {\
                void apply(inout bit<32> value, out bit<32> read_val) {\
                    read_val = value;\
                    value = 1;\
                }};\
        RegisterAction<bit<32>, bit<32>, bit<32>>(bloomfilter##num) \
            migration_read_bloomfilter##num = {\
                void apply(inout bit<32> reg_val, out bit<32> result) {\
                    result = reg_val;\
                    reg_val = 0;\
                }};

    BLOOM_FILTER_REGISTER(0)
    BLOOM_FILTER_REGISTER(1)
    BLOOM_FILTER_REGISTER(2)

    CRCPolynomial<bit<32>>(32w0x04C11DB7, true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly0;
    CRCPolynomial<bit<32>>(32w0xEDB88320, true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly1;
    CRCPolynomial<bit<32>>(32w0xDB710641, true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly2;

    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly0) myhash0;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly1) myhash1;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly2) myhash2;

    // hash verification: CRC over index + three register values
    CRCPolynomial<bit<32>>(32w0x82608EDB, true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly_verify;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly_verify) hash_verify;

    action check_bloomfilter0() {
        meta.index_sketch0 = (myhash0.get({ hdr.ipv4.dstAddr })) & 0x003f;
    }
    action check_bloomfilter1() {
        meta.index_sketch1 = (myhash1.get({ hdr.ipv4.dstAddr })) & 0x003f;
    }
    action check_bloomfilter2() {
        meta.index_sketch2 = (myhash2.get({ hdr.ipv4.dstAddr })) & 0x003f;
    }

    table tbl_bloomfilter0 { actions = {check_bloomfilter0;} size = 64; const default_action = check_bloomfilter0(); }
    table tbl_bloomfilter1 { actions = {check_bloomfilter1;} size = 64; const default_action = check_bloomfilter1(); }
    table tbl_bloomfilter2 { actions = {check_bloomfilter2;} size = 64; const default_action = check_bloomfilter2(); }

    action mark_packet_counted() { hdr.countFlag.is_counted = 1; }

    action add_count_flag() {
        hdr.countFlag.setValid();
        hdr.countFlag.is_counted = 1;
    }

    action update_migration_info(bit<32> val0, bit<32> val1, bit<32> val2) {
        hdr.regMig.value0 = val0;
        hdr.regMig.value1 = val1;
        hdr.regMig.value2 = val2;
    }

    action set_finish_flag_true()  { hdr.regMig.if_finish = 1; }
    action set_finish_flag_false() { hdr.regMig.if_finish = 0; }

    action add_header(){
        hdr.myTunnel.setValid();
        hdr.myTunnel.proto_id = TYPE_IPV4;
        hdr.ethernet.etherType = TYPE_COUNTFLAG;
    }

    action drop(){ ig_dprsr_md.drop_ctl = 0x1; }

    action set_egress_port(bit<9> egress_port){
        ig_tm_md.ucast_egress_port = egress_port;
    }

    // NOTE: entries are installed at runtime from the control plane (BFRT);
    // the default action drops any packet without a matching entry.
    table forwarding {
        key = {ig_intr_md.ingress_port: exact;}
        actions = {set_egress_port; drop; NoAction;}
        size = 64;
        default_action = drop;
    }

    apply {
        bit<48> ingress_start_time = ig_prsr_md.global_tstamp;

        if (hdr.regMig.isValid()) {
            hdr.regMig.ingress_tstamp = ingress_start_time;

            bit<32> val0 = migration_read_bloomfilter0.execute(hdr.regMig.index);
            bit<32> val1 = migration_read_bloomfilter1.execute(hdr.regMig.index);
            bit<32> val2 = migration_read_bloomfilter2.execute(hdr.regMig.index);

            update_migration_info(val0, val1, val2);

            hdr.regMig.hash_check = hash_verify.get({
                hdr.regMig.index,
                hdr.regMig.value0,
                hdr.regMig.value1,
                hdr.regMig.value2
            });
            hdr.ethernet.etherType = TYPE_REGMIG;

            if (hdr.regMig.index == (SKETCH_BUCKET_LENGTH - 1)) {
                set_finish_flag_true();
            } else {
                set_finish_flag_false();
            }

            ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        }
        else if (hdr.ipv4.isValid()) {
            bit<1> do_sketch = 1;

            if (hdr.countFlag.isValid()) {
                if (hdr.countFlag.is_counted == 1) {
                    do_sketch = 0;
                } else {
                    mark_packet_counted();
                }
            } else {
                add_count_flag();
            }

            if (do_sketch == 1) {
                tbl_bloomfilter0.apply();
                tbl_bloomfilter1.apply();
                tbl_bloomfilter2.apply();

                action_bloomfilter0.execute(meta.index_sketch0);
                action_bloomfilter1.execute(meta.index_sketch1);
                action_bloomfilter2.execute(meta.index_sketch2);
            }

            add_header();
            hdr.myTunnel.ig_tstamp = ingress_start_time;
            forwarding.apply();
        }
        else {
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/
control MyEgress(
    inout headers hdr,
    inout metadata meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md){

    apply{
        // Edge switch: strip all custom headers, only clean Ethernet + IPv4 leaves
        if (hdr.myTunnel.isValid()) {
            hdr.myTunnel.setInvalid();
            hdr.ethernet.etherType = TYPE_IPV4;
        }

        if (hdr.regMig.isValid()) {
            hdr.regMig.setInvalid();
            hdr.ethernet.etherType = TYPE_IPV4;
        }

        if (hdr.countFlag.isValid()) {
            hdr.countFlag.setInvalid();
            hdr.ethernet.etherType = TYPE_IPV4;
        }
    }
}

/*************************************************************************
***********************  S W I T C H  ************************************
*************************************************************************/
Pipeline(MyIngressParser(),
         MyIngress(),
         MyIngressDeparser(),
         MyEgressParser(),
         MyEgress(),
         MyEgressDeparser()) pipe;
Switch(pipe) main;
