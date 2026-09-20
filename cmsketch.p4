#include <core.p4>
#include <tna.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 128
#define SKETCH_CELL_BIT_WIDTH 32

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyIngress(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    #define CM_SKETCH_REGISTER(num) Register<bit<SKETCH_CELL_BIT_WIDTH>, bit<32>>(SKETCH_BUCKET_LENGTH) sketch##num;\
    RegisterAction<bit<32>, bit<32>, bit<32>>(sketch##num) \
        action_increment_sketch##num = {\
            void apply(inout bit<32> val, out bit<32> read_val) {\
                val = val + 1;\
                read_val = val;\
            }};

    CM_SKETCH_REGISTER(0)
    CM_SKETCH_REGISTER(1)
    CM_SKETCH_REGISTER(2)

    RegisterAction<bit<32>, bit<32>, bit<32>>(sketch0) migration_read_sketch0 = { void apply(inout bit<32> reg_val, out bit<32> result) { result = reg_val; reg_val = 0; }};
    RegisterAction<bit<32>, bit<32>, bit<32>>(sketch1) migration_read_sketch1 = { void apply(inout bit<32> reg_val, out bit<32> result) { result = reg_val; reg_val = 0; }};
    RegisterAction<bit<32>, bit<32>, bit<32>>(sketch2) migration_read_sketch2 = { void apply(inout bit<32> reg_val, out bit<32> result) { result = reg_val; reg_val = 0; }};

    CRCPolynomial<bit<32>>(32w0x04C11DB7, true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly0;
    CRCPolynomial<bit<32>>(32w0xEDB88320, true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly1;
    CRCPolynomial<bit<32>>(32w0xDB710641, true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly2;
    CRCPolynomial<bit<32>>(32w0x82608EDB, true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly_verify;

    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly0) myhash0;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly1) myhash1;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly2) myhash2;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly_verify) hash_verify;

    action check_bloomfilter0() { meta.index_sketch0 = (myhash0.get({ hdr.ipv4.dstAddr })) & 0x003f; } // Mask 0x003f for 128 buckets
    action check_bloomfilter1() { meta.index_sketch1 = (myhash1.get({ hdr.ipv4.dstAddr })) & 0x003f; }
    action check_bloomfilter2() { meta.index_sketch2 = (myhash2.get({ hdr.ipv4.dstAddr })) & 0x003f; }

    table tbl_bloomfilter0 { actions = {check_bloomfilter0;} size = 64; const default_action = check_bloomfilter0(); }
    table tbl_bloomfilter1 { actions = {check_bloomfilter1;} size = 64; const default_action = check_bloomfilter1(); }
    table tbl_bloomfilter2 { actions = {check_bloomfilter2;} size = 64; const default_action = check_bloomfilter2(); }

    action drop(){ ig_dprsr_md.drop_ctl = 0x1; }
    action set_egress_port(bit<9> egress_port){ ig_tm_md.ucast_egress_port = egress_port; }

    // NOTE: entries are installed at runtime from the control plane (BFRT);
    // the default action drops any packet without a matching entry.
    table forwarding {
        key = {ig_intr_md.ingress_port: exact;}
        actions = {set_egress_port; drop; NoAction;}
        size = 64;
        default_action = drop;
    }

    action compute_hash_in_meta() {
        meta.computed_hash = hash_verify.get({
            hdr.regMig.index,
            hdr.regMig.value0,
            hdr.regMig.value1,
            hdr.regMig.value2
        });
    }

    apply {
        if (hdr.regMig.isValid()) {
            hdr.regMig.ingress_tstamp = ig_prsr_md.global_tstamp;

            hdr.regMig.value0 = migration_read_sketch0.execute(hdr.regMig.index);
            hdr.regMig.value1 = migration_read_sketch1.execute(hdr.regMig.index);
            hdr.regMig.value2 = migration_read_sketch2.execute(hdr.regMig.index);

            compute_hash_in_meta();
            hdr.regMig.hash_check = meta.computed_hash;

            if (hdr.regMig.index == (SKETCH_BUCKET_LENGTH - 1)) {
                hdr.regMig.if_finish = 1;
            } else {
                hdr.regMig.if_finish = 0;
            }
            ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        }
        else if (hdr.ipv4.isValid()) {
            tbl_bloomfilter0.apply();
            tbl_bloomfilter1.apply();
            tbl_bloomfilter2.apply();

            if (hdr.countFlag.isValid()) {
                if (hdr.countFlag.is_counted == 0) {
                    action_increment_sketch0.execute(meta.index_sketch0);
                    action_increment_sketch1.execute(meta.index_sketch1);
                    action_increment_sketch2.execute(meta.index_sketch2);
                    hdr.countFlag.is_counted = 1;
                }
            } else {
                action_increment_sketch0.execute(meta.index_sketch0);
                action_increment_sketch1.execute(meta.index_sketch1);
                action_increment_sketch2.execute(meta.index_sketch2);
                // attach countFlag for downstream switches (dedup)
                hdr.countFlag.setValid();
                hdr.countFlag.is_counted = 1;
                hdr.ethernet.etherType = TYPE_COUNTFLAG;
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
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(MyIngressParser(),
         MyIngress(),
         MyIngressDeparser(),
         MyEgressParser(),
         MyEgress(),
         MyEgressDeparser()) pipe;
Switch(pipe) main;
