#include <core.p4>
#include <tna.p4>

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 128
#define SKETCH_CELL_BIT_WIDTH 32

#include "include/headers.p4"
#include "include/parsers.p4"

/*************************************************************************
*******  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyIngress(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    #define SKETCH_LEARN_REGISTER(num) \
        Register<bit<SKETCH_CELL_BIT_WIDTH>, bit<32>>(SKETCH_BUCKET_LENGTH) sketch_learn##num;\
        RegisterAction<bit<32>, bit<32>, bit<32>>(sketch_learn##num) reg_sketch_learn##num = {\
            void apply(inout bit<32> value) {\
                bit<32> in_value = value; \
                value = in_value + 1;\
            }};\
        RegisterAction<bit<32>, bit<32>, bit<32>>(sketch_learn##num) reg_read_reset##num = {\
            void apply(inout bit<32> value, out bit<32> read_val) {\
                read_val = value; \
                value = 0;\
            }};\
        action set_sketch##num() {reg_sketch_learn##num.execute(meta.index);}\
        table tbl_set_sketch##num {\
            actions = {set_sketch##num;}  size = 64;\
            const default_action = set_sketch##num();\
        }

    SKETCH_LEARN_REGISTER(0)
    SKETCH_LEARN_REGISTER(1)
    SKETCH_LEARN_REGISTER(2)

    CRCPolynomial<bit<32>>(32w0x04C11DB7, true,  false,  true,  32w0xFFFFFFFF, 32w0xFFFFFFFF) poly0;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly0) myhash;

    CRCPolynomial<bit<32>>(32w0x82608EDB, true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly_verify;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly_verify) hash_verify;

    action compute_hash_in_meta() {
        meta.computed_hash = hash_verify.get({
            hdr.regMig.index,
            hdr.regMig.value0,
            hdr.regMig.value1,
            hdr.regMig.value2
        });
    }

    action execute_hash() {
        meta.index = (myhash.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr })) & 0x003f;
    }

    action modify_flag_1() {
        meta.flag1 = (bit<1>)(hdr.ipv4.srcAddr >> 1)&0x0001;
        meta.flag2 = (bit<1>)(hdr.ipv4.srcAddr >> 2)&0x0001;
    }

    table tbl_execute_hash {actions = {execute_hash;}  size = 32; const default_action = execute_hash();}
    table modify_flag1 {actions = {modify_flag_1;}  size = 1; const default_action = modify_flag_1();}

    action mark_packet_counted() {
        hdr.countFlag.is_counted = 1;
    }

    action add_count_flag() {
        hdr.countFlag.setValid();
        hdr.countFlag.is_counted = 1;
    }

    action update_migration_info(bit<32> val0, bit<32> val1, bit<32> val2) {
        hdr.regMig.value0 = val0;
        hdr.regMig.value1 = val1;
        hdr.regMig.value2 = val2;
    }

    action set_finish_flag_true() { hdr.regMig.if_finish = 1; }
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
        if (hdr.regMig.isValid()) {
            hdr.regMig.ingress_tstamp = ig_prsr_md.global_tstamp;

            bit<32> val0;
            bit<32> val1;
            bit<32> val2;

            val0 = reg_read_reset0.execute(hdr.regMig.index);
            val1 = reg_read_reset1.execute(hdr.regMig.index);
            val2 = reg_read_reset2.execute(hdr.regMig.index);

            update_migration_info(val0, val1, val2);
            compute_hash_in_meta();
            hdr.regMig.hash_check = meta.computed_hash;
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
                tbl_execute_hash.apply();
                tbl_set_sketch0.apply();

                modify_flag1.apply();
                if (meta.flag1 == 1)  tbl_set_sketch1.apply();
                if (meta.flag2 == 1)  tbl_set_sketch2.apply();

                add_header();
                hdr.myTunnel.ig_tstamp = ig_prsr_md.global_tstamp;
            }

            forwarding.apply();
        }
        else {
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyEgress(inout headers hdr,
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
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(MyIngressParser(),
         MyIngress(),
         MyIngressDeparser(),
         MyEgressParser(),
         MyEgress(),
         MyEgressDeparser()) pipe;
Switch(pipe) main;
