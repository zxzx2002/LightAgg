/*************************************************************************
 * MVSketch with Migration Support
 * 
 * 功能说明：
 * 1. MVSketch (Majority Voter Sketch): 用于识别网络流量中的主要流
 * 2. Migration Support: 支持寄存器状态的迁移，用于网络设备状态同步
 * 
 * 主要组件：
 * - MVSketch 寄存器：存储流量统计信息（total, vote, subkey）
 * - Migration 机制：通过特殊数据包读取/写入寄存器状态
 *************************************************************************/

#include <core.p4>
#include <tna.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS - Sketch 参数配置 */
#define SKETCH_BUCKET_LENGTH 64    // Sketch 桶的数量（索引范围 0-63）

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

    /* ================= 寄存器定义 ================= */
    /* MVSketch 使用的寄存器阵列：
     * 
     * total: 统计桶内所有流量的总字节数
     * vote:  当前主导流的投票数（票数）
     * 
     * subkey1_hi/lo: 第一个子键 (dstAddr/srcAddr)
     * subkey2_hi/lo: 第二个子键 (protocol/dstPort)
     * 
     * 组合起来形成完整的流标识：
     * (dstAddr, srcAddr, protocol, dstPort)
     */
    Register<bit<32>, bit<32>>(SKETCH_BUCKET_LENGTH) mvsketch_total;
    Register<bit<32>, bit<32>>(SKETCH_BUCKET_LENGTH) mvsketch_vote;
    Register<bit<32>, bit<32>>(SKETCH_BUCKET_LENGTH) mvsketch_subkey;

    /* ================= Register Actions (逻辑核心) ================= */
    /* 这些 RegisterAction 定义了对寄存器的原子操作
     * 保证在高速数据平面中的一致性
     */

    /* ================= Migration RegisterActions ================= */

    RegisterAction<bit<32>, bit<32>, bit<32>>(mvsketch_total) action_read_total = {
        void apply(inout bit<32> value_total, out bit<32> result) {
            result = value_total;
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(mvsketch_vote) action_read_vote = {
        void apply(inout bit<32> value_vote, out bit<32> result) {
            result = value_vote;
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(mvsketch_subkey) action_read_subkey = {
        void apply(inout bit<32> value_subkey, out bit<32> result) {
            result = value_subkey;
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(mvsketch_total) action_update_total = {
        void apply(inout bit<32> value_total, out bit<32> ignored) {
            value_total = value_total + 1;
            ignored = 0;
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(mvsketch_vote) action_update_vote = {
        void apply(inout bit<32> value_vote, out bit<32> ignored) {
            value_vote = value_vote + 1;
            ignored = 0;
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(mvsketch_subkey) action_update_subkey = {
        void apply(inout bit<32> value_subkey, out bit<32> ignored) {
            value_subkey = hdr.ipv4.srcAddr;
            ignored = 0;
        }
    };

    CRCPolynomial<bit<32>>(32w0x04C11DB7, true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly_verify;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly_verify) hash_verify;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly_verify) hash_sketch_index;

    action load_sketch_data() {
        bit<32> value0_total = action_read_total.execute(hdr.migration.index);

        hdr.migration.total = value0_total;
        hdr.migration.vote = 0;
        hdr.migration.subkey_hi = 0;
        hdr.migration.subkey_lo = 0;
    }

    action load_vote_data() {
        bit<32> value0_vote = action_read_vote.execute(hdr.migration.index);
        hdr.migration.vote = value0_vote;
    }

    action load_subkey_data() {
        bit<32> value0_subkey = action_read_subkey.execute(hdr.migration.index);
        hdr.migration.subkey_lo = value0_subkey;
    }

    action compute_hash_in_meta() {
        meta.computed_hash = hash_verify.get({ hdr.migration.index, hdr.migration.vote, hdr.migration.total });
        hdr.migration.subkey_hi = meta.computed_hash;
    }

    action do_update_total() {
        action_update_total.execute(meta.index_mvsketch);
    }

    action do_update_vote() {
        action_update_vote.execute(meta.index_mvsketch);
    }

    action do_update_subkey() {
        action_update_subkey.execute(meta.index_mvsketch);
    }

    action compute_mv_index() {
        meta.index_mvsketch = hash_sketch_index.get({
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            hdr.ipv4.protocol,
            hdr.tcp.srcPort,
            hdr.tcp.dstPort
        }) % (bit<32>)SKETCH_BUCKET_LENGTH;
    }

    /**
     * 丢弃数据包
     */
    action drop(){
        ig_dprsr_md.drop_ctl = 0x1;
    }

    /**
     * 设置出端口
     */
    action set_egress_port(bit<9> egress_port){
        ig_tm_md.ucast_egress_port = egress_port;
    }

    // ===== 表定义 =====
    // 根据入端口匹配，决定转发动作
    
    table forwarding {
        key = {ig_intr_md.ingress_port: exact;}
        actions = {set_egress_port; drop; NoAction;}
        size = 64;
        default_action = drop();
    }

    /* ================= Apply Block (执行流程) ================= */
    /**
     * 主处理逻辑：分为两条路径
     * 
     * 路径1: 迁移数据包处理 (hdr.migration.isValid())
     *   - 处理状态迁移请求，读取或写入寄存器
     * 
     * 路径2: 正常流量处理 (hdr.ipv4.isValid())
     *   - 实现 MVSketch 算法，识别主要流
     */
    apply {
        if (hdr.migration.isValid()) {
            hdr.migration.ig_tstamp = ig_prsr_md.global_tstamp;
            hdr.migration.eg_tstamp = 0;
            load_sketch_data();
            load_vote_data();
            load_subkey_data();
            if (hdr.migration.index == (bit<32>)(SKETCH_BUCKET_LENGTH - 1)) {
                hdr.migration.if_finish = 1;
            } else {
                hdr.migration.if_finish = 0;
            }
            compute_hash_in_meta();
            forwarding.apply();
        }
        else if (hdr.ipv4.isValid()) {
            compute_mv_index();
            do_update_total();
            do_update_vote();
            do_update_subkey();
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
/**
 * Egress 处理逻辑
 * 功能：为出端口的数据包添加出端口时间戳
 */
control MyEgress(inout headers hdr,
    inout metadata meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md){

    /*
     * Remove the private tunnel header at the edge switch.  proto_id holds
     * the EtherType of the original payload, so restoring it before marking
     * myTunnel invalid makes the deparser emit a normal Ethernet frame.
     */
    action decapsulate_myTunnel() {
        hdr.ethernet.etherType = hdr.myTunnel.proto_id;
        hdr.myTunnel.setInvalid();
    }

    apply{
        if (hdr.migration.isValid()) {
            hdr.migration.eg_tstamp = eg_intr_md_from_prsr.global_tstamp;
        }

        if (hdr.myTunnel.isValid()) {
            decapsulate_myTunnel();
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
