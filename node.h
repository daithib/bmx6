/*
 * Copyright (c) 2010  BMX protocol contributor(s):
 * Axel Neumann  <neumann at cgws dot de>
 *
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
#include <linux/rtnetlink.h>

/*
 * from iid.h:
 */
typedef uint16_t IID_T;
typedef struct neigh_node IID_NEIGH_T;
typedef struct dhash_node IID_NODE_T;


#define IID_REPOS_SIZE_BLOCK 32

#define IID_REPOS_SIZE_MAX  ((IID_T)(-1))
#define IID_REPOS_SIZE_WARN 1024

#define IID_RSVD_UNUSED 0
#define IID_RSVD_MAX    0
#define IID_MIN_USED    1

#define IID_SPREAD_FK   1  /*default=2 , 1 means no spreading    #define IID_REPOS_USAGE_WARNING 10 */


struct iid_ref {
	IID_T myIID4x;
	uint16_t referred_by_neigh_timestamp_sec;
};

struct iid_repos {
	IID_T arr_size; // the number of allocated array fields
	IID_T min_free; // the first unused array field from the beginning of the array (might be outside of allocated space)
	IID_T max_free; // the first unused array field after the last used field in the array (might be outside of allocated space)
	IID_T tot_used; // the total number of used fields in the array
	union {
		uint8_t *u8;
		IID_NODE_T **node;
		struct iid_ref *ref;
	} arr;
};



#define DEF_LINK_PURGE_TO  100000
#define MIN_LINK_PURGE_TO  (MAX_TX_INTERVAL*2)
#define MAX_LINK_PURGE_TO  864000000 /*10 days*/
#define ARG_LINK_PURGE_TO  "linkPurgeTimeout"

#define MIN_OGM_PURGE_TO  (MAX_OGM_INTERVAL + MAX_TX_INTERVAL)
#define MAX_OGM_PURGE_TO  864000000 /*10 days*/
#define DEF_OGM_PURGE_TO  100000
#define ARG_OGM_PURGE_TO  "purgeTimeout"


#if MIN_COMPATIBILITY <= CV16




typedef CRYPTSHA1_T SHA1_T;
typedef CRYPTSHA1_T DHASH_T;
typedef CRYPTSHA1_T RHASH_T;


struct local_node {

	LOCAL_ID_T local_id;
	struct avl_tree link_tree;
	struct link_dev_node *best_rp_lndev;
	struct link_dev_node *best_tp_lndev;
	struct link_dev_node *best_lndev;
	struct neigh_node *neigh; // to be set when confirmed, use carefully

	TIME_T packet_time;
	LINKADV_SQN_T packet_link_sqn_ref; //indicating the maximum existing link_adv_sqn

	// the latest received link_adv:
	LINKADV_SQN_T link_adv_sqn;
	TIME_T link_adv_time;
	uint16_t link_adv_msgs;
	int16_t link_adv_msg_for_me;
	int16_t link_adv_msg_for_him;
	struct msg_link_adv *link_adv;
	DEVADV_SQN_T link_adv_dev_sqn_ref;

	// the latest received dev_adv:
	DEVADV_SQN_T dev_adv_sqn;
	uint16_t dev_adv_msgs;
	struct msg_dev_adv *dev_adv;

	// the latest received rp_adv:
	TIME_T rp_adv_time;
	IDM_T rp_ogm_request_rcvd;
	int32_t orig_routes;
} __attribute__((packed));



struct link_node_key {
	DEVADV_IDX_T dev_idx;
	LOCAL_ID_T local_id;
} __attribute__((packed));

struct link_node {

	struct link_node_key key;

	IPX_T link_ip;

	TIME_T pkt_time_max;
	TIME_T hello_time_max;

	HELLO_SQN_T hello_sqn_max;

	struct local_node *local; // set immediately

	struct list_head lndev_list; // list with one link_node_dev element per link
};


struct link_dev_key {
	struct link_node *link;
	struct dev_node *dev;
} __attribute__((packed));

struct router_node {

//	struct link_dev_key key_2BRemoved;

	struct local_node *local_key;

	struct metric_record mr;
	OGM_SQN_T ogm_sqn_last;
	UMETRIC_T ogm_umetric_last;

	UMETRIC_T path_metric_best; //TODO removed
	struct link_dev_node *path_lndev_best;
};



struct link_dev_node {
	struct list_node list;
	struct link_dev_key key;

	UMETRIC_T tx_probe_umetric;
	UMETRIC_T timeaware_tx_probe;
	struct lndev_probe_record rx_probe_record;
	UMETRIC_T timeaware_rx_probe;

	struct list_head tx_task_lists[FRAME_TYPE_ARRSZ]; // scheduled frames and messages
	int16_t link_adv_msg;
	TIME_T pkt_time_max;
};




struct neigh_node {

	struct neigh_node *nnkey;
	struct dhash_node *dhn; // confirmed dhash

	struct local_node *local; // to be set when confirmed, use carefully

	// filled in by ???:

	IID_T neighIID4me;

	struct iid_repos neighIID4x_repos;

//	AGGREG_SQN_T ogm_aggregation_rcvd_set;
        TIME_T ogm_new_aggregation_rcvd;
	AGGREG_SQN_T ogm_aggregation_cleard_max;
	uint8_t ogm_aggregations_not_acked[AGGREG_ARRAY_BYTE_SIZE];
	uint8_t ogm_aggregations_rcvd[AGGREG_ARRAY_BYTE_SIZE];
};




struct dext_tree_key {
    struct desc_extension *dext;
} __attribute__((packed));

struct dext_tree_node {
    struct dext_tree_key dext_key;
    uint8_t rf_types[(BMX_DSC_TLV_ARRSZ/8) + (BMX_DSC_TLV_ARRSZ%8)];
};

#define MAX_DESC_LEN (INT32_MAX-1)
#define MAX_REF_NESTING 2

struct ref_node {
        SHA1_T rhash;
        //struct frame_header_long *frame_hdr;
	uint8_t f_long;
	uint8_t *f_data;
        uint32_t f_data_len; // NOT including frame header!!
        uint32_t last_usage;
        uint32_t usage_counter;
	struct avl_tree dext_tree;
};



struct refnl_node {
    	struct list_node list;
	struct ref_node *refn;
};

struct desc_extension {
	struct list_head refnl_list;
	struct orig_node *on;
        uint8_t max_nesting;
        uint8_t *data;
        uint32_t dlen;
};

struct orig_node {
	// filled in by validate_new_link_desc0():

	GLOBAL_ID_T global_id;

	struct dhash_node *dhn;
	struct description *desc;
	struct desc_extension *dext;


	TIME_T updated_timestamp; // last time this on's desc was succesfully updated

	DESC_SQN_T descSqn;

	OGM_SQN_T ogmSqn_rangeMin;
	OGM_SQN_T ogmSqn_rangeSize;



	// filled in by process_desc0_tlvs()->
	IPX_T primary_ip;
	char primary_ip_str[IPX_STR_LEN];
	uint8_t blocked; // blocked description
        uint8_t added;   // added description


	struct host_metricalgo *path_metricalgo;

	// calculated by update_path_metric()

	OGM_SQN_T ogmSqn_maxRcvd;

	OGM_SQN_T ogmSqn_next;
	UMETRIC_T ogmMetric_next;

	OGM_SQN_T ogmSqn_send;
//	UMETRIC_T ogmMetric_send;

	UMETRIC_T *metricSqnMaxArr;          // TODO: remove

	struct avl_tree rt_tree;

	struct router_node * best_rt_local;  // TODO: remove
	struct router_node *curr_rt_local;   // the currently used local neighbor for routing
	struct link_dev_node *curr_rt_lndev; // the configured route in the kernel!

	//size of plugin data is defined during intialization and depends on registered PLUGIN_DATA_ORIG hooks
	void *plugin_data[];

};



struct dhash_node {

	DHASH_T dhash;

	TIME_T referred_by_me_timestamp; // last time this dhn was referred

	struct neigh_node *neigh;

	IID_T myIID4orig;


	struct orig_node *on;
};



struct black_node {

	DHASH_T dhash;
};




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

} __attribute__((packed));
#else
// use generic tlv_header instead...
#endif

struct packet_buff {

	struct packet_buff_info {
		//filled by wait4Event()
		struct sockaddr_storage addr;
		struct timeval tv_stamp;
		struct dev_node *iif;
		int total_length;
		uint8_t unicast;

		//filled in by rx_packet()
		uint32_t rx_counter;
		IID_T transmittersIID;
		LINKADV_SQN_T link_sqn;

		struct link_node_key link_key;

		IPX_T llip;
		char llip_str[INET6_ADDRSTRLEN];
		struct dev_node *oif;
		struct link_dev_node *lndev;
		struct link_node *link;

//		struct neigh_node *described_neigh; // might be updated again process_dhash_description_neighIID4x()
	} i;

	union {
		struct packet_header header;
		unsigned char data[MAX_UDPD_SIZE + 1];
	} packet;

};




extern struct iid_repos my_iid_repos;

extern TIME_T my_local_id_timestamp;

extern struct avl_tree dhash_tree;
extern struct avl_tree dhash_invalid_tree;
extern struct avl_tree local_tree;
extern struct avl_tree link_tree;
extern struct avl_tree link_dev_tree;
extern struct avl_tree neigh_tree;
extern struct avl_tree orig_tree;
extern struct avl_tree blacklisted_tree;


/***********************************************************
 Data Infrastructure
 ************************************************************/

void iid_purge_repos( struct iid_repos *rep );
void iid_free(struct iid_repos *rep, IID_T iid);
void iid_free_neighIID4x_by_myIID4x( struct iid_repos *rep, IID_T myIID4x);
IDM_T iid_set_neighIID4x(struct iid_repos *neigh_rep, IID_T neighIID4x, IID_T myIID4x);
IID_T iid_new_myIID4x( IID_NODE_T *dhn );
IID_NODE_T* iid_get_node_by_neighIID4x(IID_NEIGH_T *nn, IID_T neighIID4x, IDM_T verbose);
IID_NODE_T* iid_get_node_by_myIID4x( IID_T myIID4x );


struct link_dev_node *get_link_dev_node(struct packet_buff *pb);

void blacklist_neighbor(struct packet_buff *pb);

IDM_T blacklisted_neighbor(struct packet_buff *pb, DHASH_T *dhash);

struct neigh_node *is_described_neigh( struct link_node *link, IID_T transmittersIID4x );
void purge_dhash_invalid_list( IDM_T force_purge_all );
void purge_link_route_orig_nodes(struct dev_node *only_dev, IDM_T only_expired);
void block_orig_node(IDM_T block, struct orig_node *on);
void free_orig_node(struct orig_node *on);
struct orig_node * init_orig_node(GLOBAL_ID_T *id);

void purge_local_node(struct local_node *local);

IDM_T update_local_neigh(struct packet_buff *pb, struct dhash_node *dhn);
void update_neigh_dhash(struct orig_node *on, DHASH_T *dhash);

LOCAL_ID_T new_local_id(struct dev_node *dev);

void node_tasks(void);

void cleanup_node(void);
void init_node(void);