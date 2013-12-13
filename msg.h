/*
 * Copyright (c) 2010  Axel Neumann
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/if.h>



#define DEF_DROP_ALL_FRAMES 0
#define MIN_DROP_ALL_FRAMES 0
#define MAX_DROP_ALL_FRAMES 1
#define ARG_DROP_ALL_FRAMES "dropAllFrames"

#define DEF_DROP_ALL_PACKETS 0
#define MIN_DROP_ALL_PACKETS 0
#define MAX_DROP_ALL_PACKETS 1
#define ARG_DROP_ALL_PACKETS "dropAllPackets"


#define ARG_UDPD_SIZE "prefUdpSize"
#define HLP_UDPD_SIZE "set preferred udp-data size for send packets"
#define MIN_UDPD_SIZE 128 //(6+4+(22+8)+32)+184=72+56=128
#define BIG_UDPD_SIZE (1280 /*min IPv6 MTU*/ - sizeof(struct ip6_hdr) - sizeof(struct udphdr))
#define DEF_UDPD_SIZE (BIG_UDPD_SIZE / 2)
#define MAX_UDPD_SIZE 1400

#define     PKT_FRAMES_SIZE_OUT     (pref_udpd_size - sizeof(struct packet_header))
#define     PKT_FRAMES_SIZE_MAX     ( MAX_UDPD_SIZE - sizeof(struct packet_header))

#define ARG_DESC_FRAME_SIZE         "descSizeOut"
#define HLP_DESC_FRAME_SIZE         "set maximum size for own description and reference frames"
#define MIN_DESC_FRAME_SIZE         (MIN_UDPD_SIZE - sizeof(struct packet_header))
#define MAX_DESC_FRAME_SIZE         (MAX_UDPD_SIZE - sizeof(struct packet_header))
#define DEF_DESC_FRAME_SIZE         (BIG_UDPD_SIZE - sizeof(struct packet_header))
#define     REF_FRAME_BODY_SIZE_OUT (desc_frame_size_out - sizeof(struct tlv_hdr) - sizeof(struct frame_hdr_rhash_adv))
#define     REF_FRAME_BODY_SIZE_MAX (MAX_DESC_FRAME_SIZE - sizeof(struct tlv_hdr) - sizeof(struct frame_hdr_rhash_adv))
#define     DESC_FRAMES_SIZE_OUT    (desc_frame_size_out - sizeof(struct tlv_hdr) - sizeof (struct msg_description_adv))
#define     DESC_FRAMES_SIZE_MAX    (MAX_DESC_FRAME_SIZE - sizeof(struct tlv_hdr) - sizeof (struct msg_description_adv))

#define ARG_VRT_DESC_SIZE_OUT  "descVirtSizeOut"
#define HLP_VRT_DESC_SIZE_OUT  "set maximum virtual size for own description"
#define ARG_VRT_DESC_SIZE_IN   "descVirtSizeIn"
#define HLP_VRT_DESC_SIZE_IN   "set maximum virtual size for other node descriptions"
#define MIN_VRT_DESC_SIZE      (MIN_DESC_FRAME_SIZE)
#define DEF_VRT_DESC_SIZE      (16384) //any value less-equal then MAX_VRT_DESC_SIZE
//#define MAX_VRT_DESC_SIZE      (INT32_MAX)
// this should be the max possible with a reference depth of 1 :
#define MAX_VRT_DESC_SIZE      ((DESC_FRAMES_SIZE_MAX - (5 * (sizeof(struct tlv_hdr) + sizeof(struct desc_hdr_rhash_adv)) )) / \
			       sizeof(struct desc_msg_rhash_adv)) \
			       * \
			       (DEF_DESC_FRAME_SIZE - sizeof(struct tlv_hdr) - sizeof(struct frame_hdr_rhash_adv))
#define     VRT_DESC_SIZE_OUT  (vrt_desc_size_out)
#define     VRT_DESC_SIZE_IN   (vrt_desc_size_in)


#define ARG_VRT_FRAME_DATA_SIZE_OUT  "descVirtFrameSizeOut"
#define HLP_VRT_FRAME_DATA_SIZE_OUT  "set maximum virtual size for own description frames"
#define ARG_VRT_FRAME_DATA_SIZE_IN   "descVirtFrameSizeIn"
#define HLP_VRT_FRAME_DATA_SIZE_IN   "set maximum virtual size for other description frames"
#define MIN_VRT_FRAME_DATA_SIZE      (MIN_DESC_FRAME_SIZE - sizeof (struct tlv_hdr))
#define DEF_VRT_FRAME_DATA_SIZE      (8192) //any value less then MAX_VRT_FRAME_DATA_SIZE
#define MAX_VRT_FRAME_DATA_SIZE      (MAX_VRT_DESC_SIZE - sizeof(struct tlv_hdr_virtual))
#define     VRT_FRAME_DATA_SIZE_OUT  (vrt_frame_data_size_out)
#define     VRT_FRAME_DATA_SIZE_MAX  XMAX(vrt_frame_data_size_in, vrt_frame_data_size_out)



#define ARG_FZIP     "descCompression"
#define MIN_FZIP      0
#define TYP_FZIP_DFLT 0
#define TYP_FZIP_DONT 1
#define TYP_FZIP_DO   2
#define MAX_FZIP      2
#define DEF_FZIP      TYP_FZIP_DONT
#define HLP_FZIP      "use compressed description 0:dflt, 1:disabled, 2:gzip"

#define ARG_FREF      "descReferencing"
#define MIN_FREF      0
#define TYP_FREF_DFLT 0
#define TYP_FREF_DONT 1
#define TYP_FREF_DO   2
#define MAX_FREF      2
#define DEF_FREF      TYP_FREF_DONT
#define HLP_FREF      "use referenced description 0:dflt, 1:disabled, 2:reference"




#define DEF_TX_TS_TREE_SIZE 150
#define DEF_TX_TS_TREE_PURGE_FK 3

#define DEF_DESC0_CACHE_SIZE 100
#define DEF_DESC0_CACHE_TO   100000




#define MIN_DEV_ADVS_TX_ITERS 1
#define MAX_DEV_ADVS_TX_ITERS 100
#define DEF_DEV_ADVS_TX_ITERS 1
#define ARG_DEV_ADVS_TX_ITERS "devAdvSends"

#define MIN_DEV_ADVS_UNSOLICITED 0
#define MAX_DEV_ADVS_UNSOLICITED 1
#define DEF_DEV_ADV_UNSOLICITED 3
#define ARG_DEV_ADVS_UNSOLICITED "devUnsolicitedSends"

#define MIN_DEV_REQS_TX_ITERS 1
#define MAX_DEV_REQS_TX_ITERS 100
#define DEF_DEV_REQS_TX_ITERS 4
#define ARG_DEV_REQS_TX_ITERS "devReqSends"




#define MIN_LINK_ADVS_TX_ITERS 1
#define MAX_LINK_ADVS_TX_ITERS 100
#define DEF_LINK_ADVS_TX_ITERS 1
#define ARG_LINK_ADVS_TX_ITERS "linkAdvSends"

#define MIN_LINK_ADVS_UNSOLICITED 0
#define MAX_LINK_ADVS_UNSOLICITED 1
#define DEF_LINK_ADV_UNSOLICITED  1
#define ARG_LINK_ADVS_UNSOLICITED "linkUnsolicitedSends"

#define MIN_LINK_REQS_TX_ITERS 1
#define MAX_LINK_REQS_TX_ITERS 100
#define DEF_LINK_REQS_TX_ITERS 4
#define ARG_LINK_REQS_TX_ITERS "linkReqSends"




#define MIN_DSC0_ADVS_TX_ITERS 1
#define MAX_DSC0_ADVS_TX_ITERS 20
#define DEF_DESC_ADV_TX_ITERS 1
#define ARG_DSC0_ADVS_TX_ITERS "descAdvSends"

#define MIN_UNSOLICITED_DESC_ADVS 0
#define MAX_UNSOLICITED_DESC_ADVS 1
#define DEF_DESC_ADV_UNSOLICITED 1
#define ARG_UNSOLICITED_DESC_ADVS "unsolicitedDescAdvs"

#define MIN_DREF_ADV_UNSOLICITED 0
#define MAX_DREF_ADV_UNSOLICITED 1
#define DEF_DREF_ADV_UNSOLICITED 1
#define ARG_DREF_ADV_UNSOLICITED "unsolicitedDRefAdvs"

#define MIN_DSC0_REQS_TX_ITERS 1
#define MAX_DSC0_REQS_TX_ITERS 100
#define DEF_DESC_REQ_TX_ITERS 10 //TODO: will blow lndev->tx_task_list[] if new local_ids appeare just for a moment
#define ARG_DSC0_REQS_TX_ITERS "descReqSends"


#define MIN_DHS0_ADVS_TX_ITERS 1
#define MAX_DHS0_ADVS_TX_ITERS 100
#define DEF_DHASH_ADV_TX_ITERS 1
#define ARG_DHS0_ADVS_TX_ITERS "descShaAdvSends"

#define MIN_DHS0_REQS_TX_ITERS 1
#define MAX_DHS0_REQS_TX_ITERS 100
#define DEF_DHASH_REQ_TX_ITERS 10 //TODO: will blow lndev->tx_task_list[] if new local_ids appeare just for a moment
#define ARG_DHS0_REQS_TX_ITERS "descShaReqSends"

#define _DEF_OGM_SQN_DIV   5
#define _MIN_OGM_SQN_RANGE 32
#define _MAX_OGM_SQN_RANGE 8192 // changing this will cause compatibility trouble


#define MIN_OGM_SQN_RANGE _MIN_OGM_SQN_RANGE + (_MIN_OGM_SQN_RANGE/(2*_DEF_OGM_SQN_DIV))
#define MAX_OGM_SQN_RANGE _MAX_OGM_SQN_RANGE - (_MAX_OGM_SQN_RANGE/(2*_DEF_OGM_SQN_DIV))
#define DEF_OGM_SQN_RANGE MAX_OGM_SQN_RANGE
#define ARG_OGM_SQN_RANGE "ogmSqnRange"

#define MIN_OGM_TX_ITERS 0
#define MAX_OGM_TX_ITERS 30
#define DEF_OGM_TX_ITERS 10
#define ARG_OGM_TX_ITERS "ogmAdvSends"

#define DEF_OGM_ACK_TX_ITERS 1
#define MIN_OGM_ACK_TX_ITERS 0
#define MAX_OGM_ACK_TX_ITERS 4
#define ARG_OGM_ACK_TX_ITERS "ogmAckSends"

#define CONTENT_MIN_TX_INTERVAL_MIN 0
#define CONTENT_MIN_TX_INTERVAL__CHECK_FOR_REDUNDANCY 1
#define CONTENT_MIN_TX_INTERVAL_MAX 50000

//TODO: set REQ_TO to 1 (in a non-packet-loss testenvironment this may be set to 1000 for testing)
#define DEF_TX_REF_REQ_TO    ((DEF_TX_INTERVAL*3)/2)
#define DEF_TX_DREF_ADV_TO    200
#define DEF_TX_DESC0_REQ_TO  ((DEF_TX_INTERVAL*3)/2)
#define DEF_TX_DESC0_ADV_TO  200
#define DEF_TX_DHASH0_REQ_TO ((DEF_TX_INTERVAL*3)/2)
#define DEF_TX_DHASH0_ADV_TO 200

#define MIN_DESC0_REFERRED_TO 10000
#define MAX_DESC0_REFERRED_TO 100000
#define DEF_DESC0_REFERRED_TO 10000

#define DEF_DESC0_REQ_STONE_OLD_TO 40000


#define FRAME_TYPE_RSVD0        0

#define FRAME_TYPE_PROBLEM_ADV  2  // yet only used to indicate local/link_id collisions

#define FRAME_TYPE_TEST_ADV     3  // just for testing zero-message rx/tx_frame_iterator()

#define FRAME_TYPE_HELLO_ADV    4 // most-simple BMX-NG hello (nb-discovery) advertisements

#define FRAME_TYPE_DEV_REQ      6
#define FRAME_TYPE_DEV_ADV      7
#define FRAME_TYPE_LINK_REQ_ADV 8
#define FRAME_TYPE_LINK_ADV     9

#define FRAME_TYPE_RP_ADV      11

#define FRAME_TYPE_REF_REQ     12
#define FRAME_TYPE_REF_ADV     13

#define FRAME_TYPE_DESC_REQ    14
#define FRAME_TYPE_DESC_ADV    15


#define FRAME_TYPE_HASH_REQ    18  // Hash-for-description-of-OG-ID requests
#define FRAME_TYPE_HASH_ADV    19  // Hash-for-description-of-OG-ID advertisements

//#define FRAME_TYPE_HELLO_REPS  21  // most-simple BMX-NG hello (nb-discovery) replies

#define FRAME_TYPE_OGM_ADV     22 // most simple BMX-NG (type 0) OGM advertisements
#define FRAME_TYPE_OGM_ACK     23 // most simple BMX-NG (type 0) OGM advertisements

#define FRAME_TYPE_NOP         24
#define FRAME_TYPE_MAX_KNOWN    24
#define FRAME_TYPE_MAX         (FRAME_TYPE_ARRSZ-1)


#define FRAME_TYPE_PROCESS_ALL    (255)
#define FRAME_TYPE_PROCESS_NONE   (254)

#define FRAME_COMPRESSION_NONE  0
#define FRAME_COMPRESSION_GZIP  1

#define ARG_DESCRIPTIONS        "descriptions"
#define HLP_DESCRIPTIONS        "show node descriptions\n"

#define ARG_DESCRIPTION_NAME    "name"

#define ARG_DESCRIPTION_TYPE    "type"
#define DEF_DESCRIPTION_TYPE     FRAME_TYPE_PROCESS_ALL
#define MIN_DESCRIPTION_TYPE     0
#define MAX_DESCRIPTION_TYPE     FRAME_TYPE_PROCESS_ALL
#define HLP_DESCRIPTION_TYPE     "show description extension(s) of given type (0..253=type 254=none 255=all) \n"

#define ARG_REFERENCES          "references"
#define HLP_REFERENCES          "show cached reference frames\n"

#ifdef COMMENT


FSV : fixed-sized array of fixed-sized values (implicit types)

ILV : single implicit-length value (implicit type)

TLV : type length value (variable type and length, implicit dataHdrRelevance and dataBdyRelevance)
- dataHdrFormat := { nil | FSV | TLV }
- dataBdyFormat := { nil | ILV | {+|*}{ FSV | TLV } }

data[ context=packet[ dataHdrFormat=nil dataBdyFormat=+TLV ], length= ]={
    dataBdy={
	TLV={
	    type=cv16, length=,
	    data[ context=packet.cv16[ dataHdrFormat=FSV dataBdyFormat=+TLV ], length= ]={
		dataHdr={ FSV={transmitterIID, linkID, devID, ...} }
		dataBdy={
		    TLV={
			type=hello, length=,
			data[ context=packet.cv16.hello[ dataHdrFormat=FSV ], length= ]={
			    dataHdr={ FSV={helloSqn} }
			}
		    }
		    TLV={
			type=descriptions, length=,
			data[ context=packet.cv16.description[ dataBdyFormat=+TLV ], length= ]={
			    dataBdy={
				TLV={
				    type=0, length=,
				    data[ context=packet.cv16.description.1[ dataHdrFormat=FSV, dataBdyFormat=*TLV ], length= ]={
					dataHdr={ FSV={name, descSqn, ...} }
					dataBdy={
					    TLV={
						type=metric, length=,
						data[ context=packet.cv16.description.1.metric[ dataHdrFormat=FSV ], length= ]={
						    dataHdr={ FSV={algo, ...} }
						}
					    }
					    TLV={
						type=hna, length=,
						data[ context=packet.cv16.description.1.hna[ dataBdyFormat=+FSV ], length= ]={
						    dataBdy={
							FSV={net,prefix}
							FSV={net,prefix}
							...
						    }
						}
					    }
					    TLV={
						type=sms, length=,
						data[ context=packet.cv16.description.1.sms[ dataBdyFormat=+TLV ], length= ]={
						    dataBdy={
							TLV={
							    type=0, length=,
							    data[ context=packet.cv16.description.1.sms.1[ dataHdrFormat=FSV, dataBdyFormat=ILV ], length= ]={
								dataHdr={ FSV={name} }
								dataBdy={ ILV={data} }
							    }
							}
							TLV={
							    type=0, length=,
							    data[ context=packet.cv16.description.1.sms.2[ dataHdrFormat=FSV, dataBdyFormat=ILV ], length= ]={
								dataHdr={ FSV={name} }
								dataBdy={ ILV={data} }
							    }
							}
						    }
						}
					    }
					}
				    }
				}
				TLV={
				    type=0, length=,
				    data[ context=packet.cv16.description.2[ dataHdrFormat=FSV, dataMsgsFormat=*TLV ], length= ]={}
				}
				TLV
			    }
			}			
		    }
		}
	    }
	}
    }
}

#endif



#if MIN_COMPATIBILITY <= CV17

struct packet_header // 17 bytes
{
	uint8_t    comp_version;     //  8
	uint8_t    capabilities;     //  8  reserved
	uint16_t   pkt_length; 	     // 16 the relevant data size in bytes (including the bmx_header)

	IID_T      transmitterIID;   // 16 IID of transmitter node

	LINKADV_SQN_T link_adv_sqn;  // 16 used for processing: link_adv, lq_adv, rp_adv, ogm_adv, ogm_ack

	//TODOCV17: merge pkt_sqn and local_id into single uint64_t local_id
	PKT_SQN_T  pkt_sqn;          // 32
	LOCAL_ID_T local_id;         // 32

	DEVADV_IDX_T   dev_idx;      //  8

//	uint8_t    reserved_for_2byte_alignement;  //  8

} __attribute__((packed,__may_alias__));
#endif

#if MAX_COMPATIBILITY >= CV16
// understand tlv_header as well
#endif



struct tlv_hdr_virtual { // 6 bytes
    uint8_t type;
    uint8_t mbz;
    uint32_t length;  // lenght of (always uncompressed and resolved) frame in 1-Byte steps, including frame_header and variable data field
//	uint8_t  data[];  // frame-type specific data consisting of 0-1 data headers and 1-n data messages
} __attribute__((packed));



struct tlv_hdr { // 2 bytes
    union {
        struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
            unsigned int length :    11;
            unsigned int type :       5;
#elif __BYTE_ORDER == __BIG_ENDIAN
            unsigned int type :       5;
            unsigned int length :    11;
#else
# error "Please fix <bits/endian.h>"
#endif
        } __attribute__((packed)) tlv;
        uint16_t u16;
    } u;
//	uint8_t  data[];  // frame-type specific data consisting of 0-1 data headers and 1-n data messages
} __attribute__((packed));


// Future generic ILV header:
struct ilv_hdr { // 1 bytes
    uint8_t type;
} __attribute__((packed));


// for BMX_DSC_TLV_RHASH_ADV:
struct desc_msg_rhash_adv {
    SHA1_T rframe_hash;       // hash over full frame (including frame-header and data) as transmitted
} __attribute__((packed));


struct desc_hdr_rhash_adv {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int reserved :      1;
	unsigned int compression :   2; // 0:= NO compresson, 1:= gzip compression, 2-7:=reserved; only data field is compressed
	                                // all resolved and aggregated data fields are compressed (NOT the hashes)
	unsigned int expanded_type : 5;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int expanded_type : 5;
	unsigned int compression :   2;
	unsigned int reserved :      1;
#else
# error "Please fix <bits/endian.h>"
#endif
    struct   desc_msg_rhash_adv msg[];
} __attribute__((packed));


// for FRAME_TYPE_REF_ADV:
struct frame_msg_rhash_adv {
    SHA1_T rframe_hash;       // hash over full frame (including frame-header and data) as transmitted
} __attribute__((packed));

struct frame_hdr_rhash_adv {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int nested :      1;
	unsigned int compression : 2; // 0:= NO compresson, 1:= gzip compression, 2-7:=reserved; only data field is compressed
	                              // all resolved and aggregated data fields are compressed (NOT the hashes)
	unsigned int reserved    : 5;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int reserved    : 5;
	unsigned int compression : 2;
	unsigned int nested :      1;
#else
# error "Please fix <bits/endian.h>"
#endif
    struct   desc_msg_rhash_adv msg[];
} __attribute__((packed));



#define MSG_RHASH_ADV_FORMAT { \
{FIELD_TYPE_STRING_BINARY, -1, 160, 1, FIELD_RELEVANCE_LOW,  "rframe_hash"},  \
	FIELD_FORMAT_END }




// iterator return codes:
#define TLV_RX_DATA_BLOCKED    (-6) // blocked due to DAD

#define TLV_TX_DATA_FULL       (-5) // nothing done! Frame finished or not enough remining data area to write
                                 // only returns from tx-iterations, rx- will return FAILURE
#define TLV_RX_DATA_FAILURE    (-4) // syntax error: exit or blacklist
#define TLV_TX_DATA_FAILURE    (-4) // syntax error: will fail assertion()

#define TLV_RX_DATA_DONE        (-3) // done, nothing more to do
#define TLV_TX_DATA_DONE        (-3) // done, nothing more to do

#define TLV_RX_DATA_UNRESOLVED  (-2) // TBD: remove !!?? (unknown, filtered, nothing to send, or ignored due to bad link...)

#define TLV_RX_DATA_IGNORED     (-1) // unknown, filtered, nothing to send, or ignored due to bad link...
#define TLV_TX_DATA_IGNORED     (-1) // unknown, filtered, nothing to send, or ignored due to bad link...

#define TLV_RX_DATA_PROCESSED   (0) // >= means succesfully processed returned amount of data
#define TLV_TX_DATA_PROCESSED   (0) // >= means succesfully processed returned amount of data



// rx_frame_iterator operation codes:
enum {
	TLV_OP_DEL = 0,
	TLV_OP_TEST = 1,
//	TLV_OP_ADD = 2,
	TLV_OP_NEW = 2,
	TLV_OP_DEBUG = 3,

	TLV_OP_CUSTOM_MIN = 20,
        TLV_OP_CUSTOM_MAX = 99,
        TLV_OP_PLUGIN_MIN = 100,
        TLV_OP_PLUGIN_MAX = 199
};

char *tlv_op_str(uint8_t op);


struct tlv_hdr tlv_set_net(int16_t type, int16_t length);

struct problem_type {
    LOCAL_ID_T local_id;
    uint16_t problem_code;
};

#define FRAME_TYPE_PROBLEM_CODE_MIN          0x01
#define FRAME_TYPE_PROBLEM_CODE_DUP_LINK_ID  0x01
#define FRAME_TYPE_PROBLEM_CODE_MAX          0x01

//struct msg_test_adv { // 1 byte
//	uint8_t adv_test;
//} __attribute__((packed));
//
//struct hdr_test_adv { // 1 byte
//	uint8_t hdr_test;
//	struct msg_test_adv msg[];
//} __attribute__((packed));




struct msg_problem_adv { // 4 bytes
	uint8_t code;
	uint8_t reserved;
	LOCAL_ID_T local_id;
} __attribute__((packed));






struct msg_hello_adv { // 2 bytes
	HELLO_SQN_T hello_sqn;
//	uint8_t reserved; !!!!!!!!!!!!!!!!!!!!!!!!!!
} __attribute__((packed));



#define DEVADV_MSG_IGNORED -1


struct msg_dev_adv { // 26 byte

	DEVADV_IDX_T dev_idx;        // 1 byte
	uint8_t channel;             // 1 byte
	FMETRIC_U8_T tx_bitrate_min; // 1 byte
	FMETRIC_U8_T tx_bitrate_max; // 1 byte

	IPX_T llip;                  // 16 byte
	MAC_T mac;                   // 6 byte
} __attribute__((packed));

struct hdr_dev_adv { // 2 byte
	DEVADV_SQN_T dev_sqn;
	struct msg_dev_adv msg[];
} __attribute__((packed));

struct msg_dev_req { // 4 byte
	LOCAL_ID_T destination_local_id;
} __attribute__((packed));




// directives indicating the importance for recalculating the link_adv msg array
#define LINKADV_CHANGES_NONE     0
#define LINKADV_CHANGES_REMOVED  1        // recalculate, but at most once each LINKADV_INTERVAL_REMOVED ms
#define LINKADV_CHANGES_NEW      1000     // recalculate, but at most once each LINKADV_INTERVAL_NEW ms
#define LINKADV_CHANGES_CRITICAL 1000000  // recalculate now!

#define LINKADV_INTERVAL_REMOVED 10000
#define LINKADV_INTERVAL_NEW     2000

#define LINKADV_MSG_IGNORED -1 // used to identify links that are currently not announed via link_adv msgs

// used to calculate the relevance of a link compared to the best current link:
#define LINKADV_ADD_RP_4DIF 4
#define LINKADV_ADD_RP_4MIN 2
#define LINKADV_ADD_RP_4MAX 3

struct msg_link_adv { // 6 byte
	DEVADV_IDX_T transmitter_dev_idx; // to be combined with dev_id from packet header to resolve transmitters dev_id of reported link
	DEVADV_IDX_T peer_dev_idx;
	LOCAL_ID_T peer_local_id;
} __attribute__((packed));

struct hdr_link_adv { // 2 byte
	//LINK_SQN_T link_sqn; as given in packet_header
	DEVADV_SQN_T dev_sqn_ref;
	struct msg_link_adv msg[];
} __attribute__((packed));

struct msg_link_req { // 4 byte
	LOCAL_ID_T destination_local_id;
} __attribute__((packed));




struct msg_rp_adv { // 1 byte
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int rp_127range : 7;
	unsigned int ogm_request : 1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int ogm_request : 1;
	unsigned int rp_127range : 7;
#else
# error "Please fix <bits/endian.h>"
#endif

//	uint8_t rp_255range;
} __attribute__((packed));




/* Why knowledge about prev-hop (z) bandwidth is important:
 * x,y,z transmit time via link x,y,z
 *
 *  ->-x=3--              x: MAX(x,z) <  y+z
 * A        B        C
 *  ---y=2-- ---z=2--
 *
 *
 *  ---x=3--
 * A        B        C
 *  ->-y=2-- ---z=1--     y: MAX(x,z) >= y+z
 *
 *  */


/* 
 * Why 2-hops channel knowledge is important for directional links:
 *
 *  (------)--..  ..--(-------)--..
 * A        B        C         D
 *       ..--(------)--..
 *
 * Why 3-hops channel knowledge is important for omnidirectional links:
 *
 * *||||||||*)))))))) (((((((((*||||||||*))))))))))
 * A        B                           E
 *  ((((((((*||||||||*)))))))))
 *                   C         D
 *           ((((((((*|||||||||*)))))))))
 *  */





struct msg_dhash_request { // 2 bytes
	IID_T receiverIID4x;
} __attribute__((packed));

struct hdr_dhash_request { // 4 bytes
	LOCAL_ID_T destination_local_id;
	struct msg_dhash_request msg[];
} __attribute__((packed));


struct msg_dhash_adv { // 2 + X bytes
	IID_T transmitterIID4x;
	DHASH_T dhash;
} __attribute__((packed));




// for FRAME_TYPE_REF_REQ:
struct msg_ref_req {
    SHA1_T rframe_hash;
} __attribute__((packed));





#define BMX_DSC_TLV_METRIC      0x00

#define BMX_DSC_TLV_UHNA6       0x02

#define BMX_DSC_TLV_TUN6_MIN            0x04
#define BMX_DSC_TLV_TUN6_ADV            0x04
#define BMX_DSC_TLV_TUN4IN6_INGRESS_ADV 0x05
#define BMX_DSC_TLV_TUN6IN6_INGRESS_ADV 0x06
#define BMX_DSC_TLV_TUN4IN6_SRC_ADV     0x07
#define BMX_DSC_TLV_TUN6IN6_SRC_ADV     0x08
#define BMX_DSC_TLV_TUN4IN6_NET_ADV     0x09
#define BMX_DSC_TLV_TUN6IN6_NET_ADV     0x0A
#define BMX_DSC_TLV_TUN6_MAX            0x0A

#define BMX_DSC_TLV_SMS                 0x10

#define BMX_DSC_TLV_PUBKEY      (FRAME_TYPE_ARRSZ-4) //TODO: move to struct description
#define BMX_DSC_TLV_SHA         (FRAME_TYPE_ARRSZ-3)
#define BMX_DSC_TLV_SIGNATURE   (FRAME_TYPE_ARRSZ-2)

#define BMX_DSC_TLV_RHASH_ADV   (FRAME_TYPE_ARRSZ-1)



#define msg_description_request msg_dhash_request
#define hdr_description_request hdr_dhash_request


struct description { // 68 bytes
	GLOBAL_ID_T globalId; // 32 bytes name + 20 bytes pkid

	uint16_t revision;     // 2 bytes

        DESC_SQN_T descSqn;    // 4 bytes

	OGM_SQN_T ogmSqnMin;   // 2 bytes
	OGM_SQN_T ogmSqnRange; // 2 bytes

	uint16_t capabilities; // 2 bytes //was tx_interval, TODOCV18: dont use before!

	uint8_t comp_version;  // 1 bytes
	uint8_t reserved;
        uint16_t reserved2;
//      uint16_t extensionLen;// 2 bytes
//	uint8_t extensionData[];
} __attribute__((packed));



struct description2 {

	SHA1_T globalId;       // 20 bytes, hash of pubKey

        DESC_SQN_T descSqn;    // 4 bytes
	OGM_SQN_T ogmSqnMin;   // 2 bytes
	OGM_SQN_T ogmSqnRange; // 2 bytes

//	uint8_t extensionData[];
	
// Additional TLV types needed for:
// - hostname, email, revision, capabilities,
// - expanded uint32_t rframes_data_len and SHA1_T rframes_data_hash

} __attribute__((packed));



struct msg_description_adv { // IPv6: >= 92 bytes
	
	// the hashed pard:
	struct description desc;   // 68 bytes + extension frames (>= (metric-algo:2+16 bytes + hna6: 2+(x*22) bytes  ))

} __attribute__((packed));

#define DESCRIPTION_MSG_FORMAT { \
{FIELD_TYPE_GLOBAL_ID,        -1, (8*sizeof(GLOBAL_ID_T)), 1, FIELD_RELEVANCE_HIGH, "globalId"},  \
{FIELD_TYPE_HEX,              -1, 16,                      0, FIELD_RELEVANCE_MEDI, "revision" }, \
{FIELD_TYPE_UINT,             -1, 32,                      0, FIELD_RELEVANCE_MEDI, "descSqn" }, \
{FIELD_TYPE_UINT,             -1, (8*sizeof(OGM_SQN_T)),   0, FIELD_RELEVANCE_MEDI, "ogmSqnMin" }, \
{FIELD_TYPE_UINT,             -1, (8*sizeof(OGM_SQN_T)),   0, FIELD_RELEVANCE_MEDI, ARG_OGM_SQN_RANGE }, \
{FIELD_TYPE_HEX,              -1, 16,                      0, FIELD_RELEVANCE_MEDI, "capabilities" }, \
{FIELD_TYPE_UINT,             -1, 8,                       1, FIELD_RELEVANCE_LOW,  "comp_version" }, \
{FIELD_TYPE_UINT,             -1, 8,                       1, FIELD_RELEVANCE_LOW,  "reserved" }, \
{FIELD_TYPE_STRING_SIZE,      -1, 16,                      0, FIELD_RELEVANCE_LOW,  "reserved2" }, \
{FIELD_TYPE_STRING_BINARY,    -1, 0,                       1, FIELD_RELEVANCE_LOW,  "extensionData" }, \
FIELD_FORMAT_END}


#define OGM_JUMPS_PER_AGGREGATION 10

#define OGMS_PER_AGGREG_MAX  (PKT_FRAMES_SIZE_OUT - \
                              (sizeof(struct tlv_hdr) + sizeof(struct hdr_ogm_adv) + \
                               (OGM_JUMPS_PER_AGGREGATION * sizeof(struct msg_ogm_adv)))) \
			      / sizeof(struct msg_ogm_adv)

#define OGMS_PER_AGGREG_PREF ( OGMS_PER_AGGREG_MAX  / 2 )




#define OGM_IID_RSVD_JUMP  (OGM_IIDOFFST_MASK) // 63 //255 // resulting from ((2^transmitterIIDoffset_bit_range)-1)



struct msg_ogm_adv // 4 bytes
{
	OGM_MIX_T mix; //uint16_t mix of transmitterIIDoffset, metric_mant, metric_exp

	union {
		OGM_SQN_T ogm_sqn;
		IID_T transmitterIIDabsolute;
	} u;

} __attribute__((packed));



struct hdr_ogm_adv { // 2 bytes
	AGGREG_SQN_T aggregation_sqn;
	uint8_t ogm_dst_field_size;

	struct msg_ogm_adv msg[];
} __attribute__((packed));

/*
 * reception triggers:
 * - (if link <-> neigh <-... is known and orig_sid is NOT known) msg_dhash0_request[ ... orig_did = orig_sid ]
 * - else update_orig(orig_sid, orig_sqn)
 */

struct msg_ogm_ack {
//	IID_T transmitterIID4x;
	OGM_DEST_T ogm_destination;   // 1 byte
	AGGREG_SQN_T aggregation_sqn; // 1 byte
} __attribute__((packed));
/*
 * reception triggers:
 * - (if link <-> neigh <-... is known and orig_sid is NOT known) msg_dhash0_request[ ... orig_did = orig_sid ]
 * - else update_orig(orig_sid, orig_sqn)
 */



struct ogm_aggreg_node {

	struct list_node list;

	struct msg_ogm_adv *ogm_advs;

	uint8_t ogm_dest_field[(OGM_DEST_ARRAY_BIT_SIZE / 8)];
//	int16_t ogm_dest_bit_max;
	int16_t ogm_dest_bytes;

	uint16_t aggregated_msgs;

	AGGREG_SQN_T    sqn;
	uint8_t  tx_attempt;
};

struct description_cache_node {
	DHASH_T dhash;
        TIME_T timestamp;
        uint16_t desc_len;
        struct description *desc;
};


/*
 * this iterator is given the beginning of a frame area (e.g. the end of the packet_header)
 * then it iterates over the frames in that area */
struct rx_frame_iterator {
        // MUST be initialized:
        // remains unchanged:
        const char *caller;
        struct packet_buff *pb;
        struct orig_node *on;
        struct ctrl_node *cn;
        struct description *desc; //as received on wire
        uint16_t desc_len;
        uint8_t *frames_in;
        struct frame_handl *handls;
        struct frame_handl *handl;
        uint8_t op;
        uint8_t process_filter;
        uint8_t handl_max;
        uint8_t is_virtual_header;
        int32_t frames_length;

        // MUST be initialized, updated by rx..iterate(), and consumed by handl[].rx_tlv_handler
        int32_t frames_pos;
        int8_t frame_type; //init to -1 !!
        int8_t frame_type_expanded; //init to -1 !!

        // set by rx..iterate(), and consumed by handl[].rx_tlv_handler
        int32_t frame_data_length;
        int32_t frame_length;
        int32_t frame_msgs_length;
        int32_t frame_msgs_fixed;
	struct tlv_hdr *frame_hdr;
        uint8_t *frame_data;
        uint8_t *msg;

        // allocated by handl[].rx_tlv_handler and freed by calling function of rx_frame_iterate() (e.g. process_description_tlvs())

        // allocated and freed by function calling process_description_tlvs(), eg. process_description(), bmx(), plugins,...
        void *custom_data;
};


/*
 * this iterator is given a fr_type and a set of handlers,
 * then the handlers are supposed to figure out what needs to be done.
 * finally the iterator writes ready-to-send frame_header and frame data to *fs_data */
struct tx_frame_iterator {
	// MUST be initialized:
	// remains unchanged:
	const char          *caller;
	struct list_head    *tx_task_list;
	struct tx_task_node *ttn;
	struct desc_extension *dext;

	uint8_t             *frame_cache_array;
	uint8_t             *frames_out_ptr;
	struct frame_handl  *handls;
	uint8_t              handl_max;
	int32_t              frames_out_pref;
	int32_t              frames_out_max;
	int32_t              frame_cache_size;
        // updated by fs_caller():
	uint8_t              frame_type;

	// updated by tx..iterate():
	int32_t              frames_out_pos;
	int32_t              frames_out_num;
	int32_t              frame_cache_msgs_size;


//#define tx_iterator_cache_data_space( it ) (((it)->frames_out_max) - ((it)->frames_out_pos + (it)->cache_msg_pos + ((int)(sizeof (struct frame_header_long)))))
//#define tx_iterator_cache_hdr_ptr( it ) ((it)->cache_data_array)
//#define tx_iterator_cache_msg_ptr( it ) ((it)->cache_data_array + (it)->cache_msg_pos)
};


struct frame_handl {
        uint8_t is_advertisement;              // NO link information required for tx_frame_...(), dev is enough
	uint8_t is_destination_specific_frame; // particularly: is NO advertisement AND individual frames are created for each destination
	int32_t *dextCompression;
	int32_t *dextReferencing;
	uint8_t rx_requires_described_neigh;
        uint16_t data_header_size;
        uint16_t min_msg_size;
        uint16_t fixed_msg_size;
        uint16_t tx_task_interval_min;
        int32_t *tx_iterations;
        UMETRIC_T *tx_tp_min;
        UMETRIC_T *tx_rp_min;
        UMETRIC_T *rx_tp_min;
        UMETRIC_T *rx_rp_min;
        char *name;

	int32_t (*rx_frame_handler) (struct rx_frame_iterator *); // returns: TLV_RX_DATA_code or rcvd frame_msgs_len (without data_header_size)
	int32_t (*rx_msg_handler)   (struct rx_frame_iterator *); // returns: TLV_RX_DATA_code or rcvd frame_msg_len  (without data_header_size)
	int32_t (*tx_frame_handler) (struct tx_frame_iterator *); // returns: TLV_TX_DATA_code or send frame_msgs_len (without data_header_size)
	int32_t (*tx_msg_handler)   (struct tx_frame_iterator *); // returns: TLV_TX_DATA_code or send frame_msg_len  (without data_header_size)

	const struct field_format *msg_format;
};


static inline uint8_t * tx_iterator_cache_hdr_ptr(struct tx_frame_iterator *it)
{
	return it->frame_cache_array;
}

static inline uint8_t * tx_iterator_cache_msg_ptr(struct tx_frame_iterator *it)
{
	return it->frame_cache_array + it->handls[it->frame_type].data_header_size + it->frame_cache_msgs_size;
}

int32_t _tx_iterator_cache_data_space(struct tx_frame_iterator *it, IDM_T max);

#define tx_iterator_cache_data_space_max( it )  _tx_iterator_cache_data_space(it, 1)
#define tx_iterator_cache_data_space_pref( it ) _tx_iterator_cache_data_space(it, 0)

static inline int32_t tx_iterator_cache_data_space_sched(struct tx_frame_iterator *it)
{
    return (!it->frames_out_pos && !it->frame_cache_msgs_size) ?
	tx_iterator_cache_data_space_max(it) : tx_iterator_cache_data_space_pref(it);
}

static inline int32_t tx_iterator_cache_msg_space_pref(struct tx_frame_iterator *it)
{
        if (it->handls[it->frame_type].min_msg_size && it->handls[it->frame_type].fixed_msg_size)
                return tx_iterator_cache_data_space_pref(it) / it->handls[it->frame_type].min_msg_size;
        else
                return 0;
}



extern const int32_t always_fref;


extern uint32_t ogm_aggreg_pending;
extern IID_T myIID4me;
extern TIME_T myIID4me_timestamp;

//extern IDM_T my_dev_adv_changed;


extern struct frame_handl packet_frame_handler[FRAME_TYPE_ARRSZ];
extern struct frame_handl description_tlv_handl[BMX_DSC_TLV_ARRSZ];


/***********************************************************
  The core frame/message structures and handlers
************************************************************/


OGM_SQN_T set_ogmSqn_toBeSend_and_aggregated(struct orig_node *on, UMETRIC_T um, OGM_SQN_T to_be_send, OGM_SQN_T aggregated);
void update_my_description_adv( void );
void update_my_dev_adv(void);
void update_my_link_adv(uint32_t changes);

void free_desc_extensions(struct desc_extension **dext);
struct dhash_node * process_description(struct packet_buff *pb, struct description_cache_node *desc, DHASH_T *dhash);
IDM_T process_description_tlvs(struct packet_buff *pb, struct orig_node *on, struct description *desc, uint16_t desc_len, 
        struct desc_extension *dext, uint8_t op, uint8_t filter, void *custom, struct ctrl_node *cn);
int32_t get_desc_frame_data(uint8_t **frame_data, uint8_t *desc_ext_data, int32_t desc_ext_len, uint8_t virtual_data, uint8_t frame_type);
IDM_T desc_frame_changed(  struct rx_frame_iterator *it, uint8_t f_type );
void purge_tx_task_list(struct list_head *tx_tasks_list, struct link_node *only_link, struct dev_node *only_dev);
SHA1_T *ref_node_key(uint8_t *f_body, uint32_t f_body_len, uint8_t compression, uint8_t nested, uint8_t reserved);
void ref_node_purge (IDM_T all_unused);

void tx_packets( void *unused );
IDM_T rx_frames(struct packet_buff *pb);
int32_t rx_frame_iterate(struct rx_frame_iterator* it);

void rx_packet( struct packet_buff *pb );

#define SCHEDULE_UNKNOWN_MSGS_SIZE 0
#define SCHEDULE_MIN_MSG_SIZE -1

void schedule_tx_task(struct link_dev_node *dest_lndev, uint16_t frame_type, int16_t frame_msgs_len,
        void *data, uint32_t dlen, IID_T myIID4x, IID_T neighIID4x);

void register_frame_handler(struct frame_handl *array, int pos, struct frame_handl *handl);

struct plugin *msg_get_plugin( void );

uint8_t use_compression(struct frame_handl *handl);
uint8_t use_referencing(struct frame_handl *handl);

