/* -*- P4_16 -*- */

/* -* 
 * This file is part of the P4 Registers (https://github.com/NETSERV-UAH/P4-Registers).
 * Copyright (c) 2020.
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
-*- */

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x806;
const bit<32> NUM_ELEM_TABLE = 327680;
const bit<4> NUM_PORT = 3;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<48> BROADCAST_MAC = 281474976710655;
const bit<48> BTIME = 10000000; // 10 second
const bit<48> UTIME = 20000000; // 20 second

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9>  PortId_t;
typedef bit<48> time_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header arp_t {
	bit<16> hwType;
    bit<16> protoType;
	bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    macAddr_t hwSrcAddr;
    ip4Addr_t protoSrcAddr;
    macAddr_t hwDstAddr;
    ip4Addr_t protoDstAddr;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
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

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    arp_t 	 arp;
}

/*************************************************************************
*********************** R E G I S T E R **********************************
************************************************************************/
register <PortId_t> (NUM_ELEM_TABLE) bcast_register_port; //BT Port
register <time_t> (NUM_ELEM_TABLE) bcast_register_time; //BT time
register <PortId_t> (NUM_ELEM_TABLE) ucast_register_port; //LT
register <time_t> (NUM_ELEM_TABLE) ucast_register_time; //BT time

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        /* start tu parse the packet, and of course we
        start with the ethernet header */
        transition parse_ethernet;
    }

    state parse_ethernet{
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            /** If we have arp packet we extract it */
            TYPE_ARP:parse_arp;
            /** If we have ip packet we extract it */
            /* in this case we forgot the ip header */
            TYPE_IPV4:parse_ipv4;
            /* for the rest type of header */
            default: accept;
        }
    }

    state parse_arp{
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    /* ARP-PATH protocol logic*/
    apply {
        /* aux variables */
        PortId_t table_port = 0;
        time_t timestamp = 0;
        /*varibale for hash*/
        bit<32> hash_srcmac;
        bit<32> hash_dstmac;

        if (hdr.ethernet.etherType == TYPE_IPV6){
            mark_to_drop(standard_metadata);
        }
        else{
            /*read ports in table */
            hash(hash_srcmac, HashAlgorithm.identity, (bit<48>) 0, { hdr.ethernet.srcAddr }, (bit<48>) NUM_ELEM_TABLE);
            hash(hash_dstmac, HashAlgorithm.identity, (bit<48>) 0, { hdr.ethernet.dstAddr }, (bit<48>) NUM_ELEM_TABLE);

            if (hdr.arp.isValid()){
                /* Start with request */
                if (hdr.arp.opcode == 2){
                    /*Operation on BTable*/
                    /* look for the port dst */
                    bcast_register_port.read(table_port, hash_dstmac);
                    /*Operation on LTable*/
                    /* create/udapte DST*/
                    ucast_register_port.write(hash_dstmac, table_port);
                    ucast_register_time.write(hash_dstmac, UTIME + standard_metadata.ingress_global_timestamp);
                }
            }
            //forwarding part
            if (hdr.ethernet.dstAddr == BROADCAST_MAC){
                bcast_register_port.read(table_port, hash_srcmac);
                bcast_register_time.read(timestamp, hash_srcmac);
                if (table_port != 0 && (BTIME + timestamp) < standard_metadata.ingress_global_timestamp){
                    table_port = 0; //nos cargamos el puerto de salida
                    bcast_register_port.write(hash_srcmac, table_port);
                    bcast_register_time.write(hash_srcmac, standard_metadata.ingress_global_timestamp);
                }
                /* if not exist port in table */
                if (table_port == 0 || table_port == standard_metadata.ingress_port){
                    bcast_register_port.write(hash_srcmac, standard_metadata.ingress_port);
                    bcast_register_time.write(hash_srcmac, standard_metadata.ingress_global_timestamp);
                    //send_to_multicast_group(standard_metadata.mcast_grp);
                    /* Send broadcast packet */
                    standard_metadata.mcast_grp = 1;
                }
                else{
                    /* drop packet */
                    mark_to_drop(standard_metadata);
                }
            }
            else{
                ucast_register_port.read(table_port, hash_dstmac);
                ucast_register_time.read(timestamp, hash_dstmac);
                if (table_port != 0 && (UTIME + timestamp) < standard_metadata.ingress_global_timestamp){
                    table_port = 0; //nos cargamos el puerto de salida
                    ucast_register_port.write(hash_dstmac, table_port);
                    ucast_register_time.write(hash_dstmac, standard_metadata.ingress_global_timestamp);
                }
                /* Send the packet if we have out port */
                if (table_port != 0){
                    /* create/udapte SRC*/
                    ucast_register_port.write(hash_srcmac, standard_metadata.ingress_port);
                    ucast_register_time.write(hash_srcmac, standard_metadata.ingress_global_timestamp);
                    /* Send packet */
                    standard_metadata.egress_spec = table_port;
                }
                else{
                    /* Drop the packet because we haven't out port */
                    mark_to_drop(standard_metadata);
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* We insert the header in the packets */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
