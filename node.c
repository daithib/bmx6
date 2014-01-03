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

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if.h>     /* ifr_if, ifr_tun */
#include <linux/rtnetlink.h>
#include <time.h>


#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "metrics.h"
#include "msg.h"
#include "ip.h"
#include "hna.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "plugin.h"
#include "allocate.h"

#define CODE_CATEGORY_NAME "node"

IDM_T my_description_changed = YES;

struct orig_node *self = NULL;

CRYPTKEY_T *my_PubKey = NULL;


LOCAL_ID_T my_local_id = LOCAL_ID_INVALID;

TIME_T my_local_id_timestamp = 0;

static int32_t link_purge_to = DEF_LINK_PURGE_TO;
static int32_t ogm_purge_to = DEF_OGM_PURGE_TO;


AVL_TREE(link_dev_tree, struct link_dev_node, key);

AVL_TREE(link_tree, struct link_node, key);

AVL_TREE(local_tree, struct local_node, local_id);
AVL_TREE(neigh_tree, struct neigh_node, nnkey);

AVL_TREE(dhash_tree, struct dhash_node, dhash);
AVL_TREE(dhash_invalid_tree, struct dhash_node, dhash);

AVL_TREE(orig_tree, struct orig_node, nodeId);

//static AVL_TREE(blacklisted_tree, struct black_node, dhash);

AVL_TREE(status_tree, struct status_handl, status_name);

LIST_SIMPEL( dhash_invalid_plist, struct plist_node, list, list );
static AVL_TREE(blocked_tree, struct orig_node, nodeId);




/***********************************************************
 IID Infrastructure
 ************************************************************/


struct iid_repos my_iid_repos = { 0,0,0,0,{NULL} };

int8_t iid_extend_repos(struct iid_repos *rep)
{
        TRACE_FUNCTION_CALL;

        dbgf_all(DBGT_INFO, "sizeof iid: %zu,  tot_used %d  arr_size %d ",
                (rep == &my_iid_repos) ? sizeof (IID_NODE_T*) : sizeof (IID_T), rep->tot_used, rep->arr_size);

        assertion(-500217, (rep != &my_iid_repos || IID_SPREAD_FK != 1 || rep->tot_used == rep->arr_size));

        if (rep->arr_size + IID_REPOS_SIZE_BLOCK >= IID_REPOS_SIZE_WARN) {

                dbgf_sys(DBGT_WARN, "%d", rep->arr_size);

                if (rep->arr_size + IID_REPOS_SIZE_BLOCK >= IID_REPOS_SIZE_MAX)
                        return FAILURE;
        }

        int field_size = (rep == &my_iid_repos) ? sizeof (IID_NODE_T*) : sizeof (struct iid_ref);

        if (rep->arr_size) {

                rep->arr.u8 = debugRealloc(rep->arr.u8, (rep->arr_size + IID_REPOS_SIZE_BLOCK) * field_size, -300035);

        } else {

                rep->arr.u8 = debugMalloc(IID_REPOS_SIZE_BLOCK * field_size, -300085);
                rep->tot_used = IID_RSVD_MAX+1;
                rep->min_free = IID_RSVD_MAX+1;
                rep->max_free = IID_RSVD_MAX+1;
        }

        memset(&(rep->arr.u8[rep->arr_size * field_size]), 0, IID_REPOS_SIZE_BLOCK * field_size);

        rep->arr_size += IID_REPOS_SIZE_BLOCK;

        return SUCCESS;
}


void iid_purge_repos( struct iid_repos *rep )
{
        TRACE_FUNCTION_CALL;

        if (rep->arr.u8)
                debugFree(rep->arr.u8, -300135);

        memset(rep, 0, sizeof ( struct iid_repos));

}

void iid_free(struct iid_repos *rep, IID_T iid)
{
        TRACE_FUNCTION_CALL;
        int m = (rep == &my_iid_repos);

        assertion(-500330, (iid > IID_RSVD_MAX));
        assertion(-500228, (iid < rep->arr_size && iid < rep->max_free && rep->tot_used > IID_RSVD_MAX));
        assertion(-500229, ((m ? (rep->arr.node[iid] != NULL) : (rep->arr.ref[iid].myIID4x) != 0)));

        if (m) {
                rep->arr.node[iid] = NULL;
        } else {
                rep->arr.ref[iid].myIID4x = 0;
                rep->arr.ref[iid].referred_by_neigh_timestamp_sec = 0;
        }

        rep->min_free = XMIN(rep->min_free, iid);

        if (rep->max_free == iid + 1) {

                IID_T i;

                for (i = iid; i > IID_MIN_USED; i--) {

                        if (m ? (rep->arr.node[i - 1] != NULL) : (rep->arr.ref[i - 1].myIID4x) != 0)
                                break;
                }

                rep->max_free = i;
        }

        rep->tot_used--;

        dbgf_all( DBGT_INFO, "mine %d, iid %d tot_used %d, min_free %d max_free %d",
                m, iid, rep->tot_used, rep->min_free, rep->max_free);

        if (rep->tot_used > 0 && rep->tot_used <= IID_MIN_USED) {

                assertion(-500362, (rep->tot_used == IID_MIN_USED && rep->max_free == IID_MIN_USED && rep->min_free == IID_MIN_USED));

                iid_purge_repos( rep );

        }

}

IID_NODE_T* iid_get_node_by_myIID4x(IID_T myIID4x)
{
        TRACE_FUNCTION_CALL;

        if ( my_iid_repos.max_free <= myIID4x )
                return NULL;

        IID_NODE_T *dhn = my_iid_repos.arr.node[myIID4x];

        assertion(-500328, (!dhn || dhn->myIID4orig == myIID4x));

        if (dhn && !dhn->on) {

                dbgf_track(DBGT_INFO, "myIID4x %d INVALIDATED %d sec ago",
                        myIID4x, (bmx_time - dhn->referred_by_me_timestamp) / 1000);

                return NULL;
        }


        return dhn;
}


IID_NODE_T* iid_get_node_by_neighIID4x(IID_NEIGH_T *nn, IID_T neighIID4x, IDM_T verbose)
{
        TRACE_FUNCTION_CALL;

        if (!nn || nn->neighIID4x_repos.max_free <= neighIID4x) {

                if (verbose) {
                        dbgf_all(DBGT_INFO, "NB: global_id=%s neighIID4x=%d to large for neighIID4x_repos",
                                nn ? cryptShaAsString(&nn->dhn->on->nodeId) : "???", neighIID4x);
                }
                return NULL;
        }

        struct iid_ref *ref = &(nn->neighIID4x_repos.arr.ref[neighIID4x]);


        if (!ref->myIID4x ) {
                if (verbose) {
                        dbgf_all(DBGT_WARN, "neighIID4x=%d not recorded by neighIID4x_repos", neighIID4x);
                }
        } else if (((((uint16_t) bmx_time_sec) - ref->referred_by_neigh_timestamp_sec) >
                ((MIN_DHASH_TO - (MIN_DHASH_TO / DHASH_TO_TOLERANCE_FK)) / 1000))) {

                if (verbose) {
                        dbgf_track(DBGT_WARN, "neighIID4x=%d outdated in neighIID4x_repos, now_sec=%d, ref_sec=%d",
                                neighIID4x, bmx_time_sec, ref->referred_by_neigh_timestamp_sec);
                }

        } else {

                ref->referred_by_neigh_timestamp_sec = bmx_time_sec;

                if (ref->myIID4x < my_iid_repos.max_free) {

                        IID_NODE_T *dhn = my_iid_repos.arr.node[ref->myIID4x];

                        if (dhn)
                                return dhn;

                        if (verbose) {
                                dbgf_track(DBGT_WARN, "neighIID4x=%d -> myIID4x=%d empty!", neighIID4x, ref->myIID4x);
                        }

                } else {

                        if (verbose) {
                                dbgf_track(DBGT_WARN, "neighIID4x=%d -> myIID4x=%d to large!", neighIID4x, ref->myIID4x);
                        }
                }
        }

        return NULL;
}


STATIC_FUNC
void _iid_set(struct iid_repos *rep, IID_T IIDpos, IID_T myIID4x, IID_NODE_T *dhn)
{
        TRACE_FUNCTION_CALL;
        assertion(-500530, (rep && XOR(myIID4x, dhn))); // eihter the one ore the other !!
        assertion(-500531, (!dhn || rep == &my_iid_repos));
        assertion(-500535, (IIDpos >= IID_MIN_USED));

        rep->tot_used++;
        rep->max_free = XMAX( rep->max_free, IIDpos+1 );

        IID_T min = rep->min_free;

        if (min == IIDpos) {
                for (min++; min < rep->arr_size; min++) {

                        if (myIID4x ? !(rep->arr.ref[min].myIID4x) : !(rep->arr.node[min]))
                                break;
                }
        }

        assertion(-500244, (min <= rep->max_free));

        rep->min_free = min;

        if (myIID4x) {
                rep->arr.ref[IIDpos].myIID4x = myIID4x;
                rep->arr.ref[IIDpos].referred_by_neigh_timestamp_sec = bmx_time_sec;
        } else {
                rep->arr.node[IIDpos] = dhn;
                dhn->referred_by_me_timestamp = bmx_time;
        }
}


IID_T iid_new_myIID4x(IID_NODE_T *dhn)
{
        TRACE_FUNCTION_CALL;
        IID_T mid;
#ifndef NO_ASSERTIONS
        IDM_T warn = 0;
#endif

        assertion(-500216, (my_iid_repos.tot_used <= my_iid_repos.arr_size));

        while (my_iid_repos.arr_size <= my_iid_repos.tot_used * IID_SPREAD_FK)
                iid_extend_repos( &my_iid_repos );

        if (IID_SPREAD_FK > 1) {

                uint32_t random = rand_num(my_iid_repos.arr_size);

                // Never put random function intro MAX()! It would be called twice
                mid = XMAX(IID_MIN_USED, random);

                while (my_iid_repos.arr.node[mid]) {

                        mid++;
                        if (mid >= my_iid_repos.arr_size) {

                                mid = IID_MIN_USED;

                                assertion(-500533, (!(warn++)));
                        }
                }

        } else {

                mid = my_iid_repos.min_free;
        }

        _iid_set(&my_iid_repos, mid, 0, dhn);

        return mid;

}


IDM_T iid_set_neighIID4x(struct iid_repos *neigh_rep, IID_T neighIID4x, IID_T myIID4x)
{
        TRACE_FUNCTION_CALL;
        assertion(-500326, (neighIID4x > IID_RSVD_MAX));
        assertion(-500327, (myIID4x > IID_RSVD_MAX));
        assertion(-500384, (neigh_rep && neigh_rep != &my_iid_repos));

        assertion(-500245, (my_iid_repos.max_free > myIID4x));

        IID_NODE_T *dhn = my_iid_repos.arr.node[myIID4x];

        assertion(-500485, (dhn && dhn->on));

        dhn->referred_by_me_timestamp = bmx_time;

        if (neigh_rep->max_free > neighIID4x) {

                struct iid_ref *ref = &(neigh_rep->arr.ref[neighIID4x]);

                if (ref->myIID4x > IID_RSVD_MAX) {

                        if (ref->myIID4x == myIID4x ||
                                (((uint16_t)(((uint16_t) bmx_time_sec) - ref->referred_by_neigh_timestamp_sec)) >=
                                ((MIN_DHASH_TO - (MIN_DHASH_TO / DHASH_TO_TOLERANCE_FK)) / 1000))) {

                                ref->myIID4x = myIID4x;
                                ref->referred_by_neigh_timestamp_sec = bmx_time_sec;
                                return SUCCESS;
                        }

                        IID_NODE_T *dhn_old;
                        dhn_old = my_iid_repos.arr.node[ref->myIID4x]; // avoid -DNO_DEBUG_SYS warnings
                        dbgf_sys(DBGT_ERR, "demanding mapping: neighIID4x=%d to myIID4x=%d "
                                "(global_id=%s updated=%d last_referred_by_me=%d)  "
                                "already used for ref->myIID4x=%d (last_referred_by_neigh_sec=%d %s=%s last_referred_by_me=%jd)! Reused faster than allowed!!",
                                neighIID4x, myIID4x, cryptShaAsString(&dhn->on->nodeId), dhn->on->updated_timestamp,
                                dhn->referred_by_me_timestamp,
                                ref->myIID4x,
                                ref->referred_by_neigh_timestamp_sec,
                                (!dhn_old ? "???" : (dhn_old->on ? cryptShaAsString(&dhn_old->on->nodeId) :
                                (is_zero(&dhn_old->dhash, sizeof (dhn_old->dhash)) ? "FREED" : "INVALIDATED"))),
                                dhn_old ? cryptShaAsString(&dhn_old->dhash) : "???",
                                dhn_old ? (int64_t)dhn_old->referred_by_me_timestamp : -1
                                );

//                        EXITERROR(-500701, (0));

                        return FAILURE;
                }

                assertion(-500242, (ref->myIID4x == IID_RSVD_UNUSED));
        }


        while (neigh_rep->arr_size <= neighIID4x) {

                if (
                        neigh_rep->arr_size > IID_REPOS_SIZE_BLOCK &&
                        neigh_rep->arr_size > my_iid_repos.arr_size &&
                        neigh_rep->tot_used < neigh_rep->arr_size / (2 * IID_SPREAD_FK)) {

                        dbgf_sys(DBGT_WARN, "IID_REPOS USAGE WARNING neighIID4x %d myIID4x %d arr_size %d used %d",
                                neighIID4x, myIID4x, neigh_rep->arr_size, neigh_rep->tot_used );
                }

                iid_extend_repos(neigh_rep);
        }

        assertion(-500243, ((neigh_rep->arr_size > neighIID4x &&
                (neigh_rep->max_free <= neighIID4x || neigh_rep->arr.ref[neighIID4x].myIID4x == IID_RSVD_UNUSED))));

        _iid_set( neigh_rep, neighIID4x, myIID4x, NULL);

        return SUCCESS;
}


void iid_free_neighIID4x_by_myIID4x( struct iid_repos *rep, IID_T myIID4x)
{
        TRACE_FUNCTION_CALL;
        assertion(-500282, (rep != &my_iid_repos));
        assertion(-500328, (myIID4x > IID_RSVD_MAX));

        IID_T p;
        uint16_t removed = 0;

        for (p = IID_RSVD_MAX + 1; p < rep->max_free; p++) {

                if (rep->arr.ref[p].myIID4x == myIID4x) {

                        if (removed++) {
                                // there could indeed be several (if the neigh has timeouted this node and learned it again later)
                                dbgf(DBGL_TEST, DBGT_INFO, "removed %d. stale rep->arr.sid[%d] = %d", removed, p, myIID4x);
                        }

                        iid_free(rep, p);
                }
        }
}




/***********************************************************
 Data Infrastructure
 ************************************************************/

void blacklist_neighbor(struct packet_buff *pb)
{
        TRACE_FUNCTION_CALL;
        dbgf_sys(DBGT_ERR, "%s via %s", pb->i.llip_str, pb->i.iif->label_cfg.str);

        EXITERROR(-500697, (0));
}


IDM_T blacklisted_neighbor(struct packet_buff *pb, DHASH_T *dhash)
{
        TRACE_FUNCTION_CALL;
        //dbgf_all(DBGT_INFO, "%s via %s", pb->i.neigh_str, pb->i.iif->label_cfg.str);
        return NO;
}



struct neigh_node *is_described_neigh( struct link_node *link, IID_T transmittersIID4x )
{
        assertion(-500730, (link));
        assertion(-500958, (link->local));
        struct neigh_node *neigh = link->local->neigh;

        if (neigh && neigh->dhn && neigh->dhn->on &&
                neigh->dhn == iid_get_node_by_neighIID4x(neigh, transmittersIID4x, YES/*verbose*/)) {

                assertion(-500938, (neigh->dhn->neigh == neigh));

                return neigh;
        }

        return NULL;
}








STATIC_FUNC
void purge_dhash_iid(IID_T myIID4orig)
{
        TRACE_FUNCTION_CALL;
        struct avl_node *an;
        struct neigh_node *neigh;

        //reset all neigh_node->oid_repos[x]=dhn->mid4o entries
        for (an = NULL; (neigh = avl_iterate_item(&neigh_tree, &an));) {

                iid_free_neighIID4x_by_myIID4x(&neigh->neighIID4x_repos, myIID4orig);

        }
}


void purge_dhash_invalid_list( IDM_T force_purge_all ) {

        TRACE_FUNCTION_CALL;
        struct dhash_node *dhn;

        dbgf_all( DBGT_INFO, "%s", force_purge_all ? "force_purge_all" : "only_expired");

        while ((dhn = plist_get_first(&dhash_invalid_plist)) ) {

                if (force_purge_all || ((uint32_t) (bmx_time - dhn->referred_by_me_timestamp) > MIN_DHASH_TO)) {

                        dbgf_all( DBGT_INFO, "dhash %8X myIID4orig %d", dhn->dhash.h.u32[0], dhn->myIID4orig);

                        plist_del_head(&dhash_invalid_plist);
                        avl_remove(&dhash_invalid_tree, &dhn->dhash, -300194);

			if (dhn->myIID4orig > IID_RSVD_MAX) {

				iid_free(&my_iid_repos, dhn->myIID4orig);

				purge_dhash_iid(dhn->myIID4orig);
			}

                        debugFree(dhn, -300112);

                } else {
                        break;
                }
        }
}


void invalidate_dhash( struct dhash_node *dhn, DHASH_T *dhash )
{
        TRACE_FUNCTION_CALL;

	assertion( -500000, XOR(dhn, dhash));

	if (!dhn) {
		dhn = debugMallocReset(sizeof(DHASH_T), -300000);
		dhn->dhash = *dhash;
	} else {
		dext_free(&dhn->dext);
		debugFree(dhn->desc_frame, -300000);
		dhn->desc_frame = NULL;
		dhn->desc_frame_len = 0;
	}

        dbgf_track(DBGT_INFO,
                "dhash %8X myIID4orig %d, my_iid_repository: used=%d, inactive=%d  min_free=%d  max_free=%d ",
                dhn->dhash.h.u32[0], dhn->myIID4orig,
                my_iid_repos.tot_used, dhash_invalid_tree.items+1, my_iid_repos.min_free, my_iid_repos.max_free);

        assertion( -500698, (!dhn->on));
        assertion( -500699, (!dhn->neigh));
	assertion( -500000, !avl_find(&dhash_tree, &dhn->dhash));

        avl_insert(&dhash_invalid_tree, dhn, -300168);
        plist_add_tail(&dhash_invalid_plist, dhn);
        dhn->referred_by_me_timestamp = bmx_time;
}

// called to not leave blocked dhash values:
STATIC_FUNC
void release_dhash( struct dhash_node *dhn )
{
        TRACE_FUNCTION_CALL;
        static uint32_t blocked_counter = 1;

        dbgf(terminating ? DBGL_CHANGES : DBGL_SYS, DBGT_INFO,
                "dhash %8X myIID4orig %d", dhn->dhash.h.u32[0], dhn->myIID4orig);

        assertion(-500961, (!dhn->on));
        assertion(-500962, (!dhn->neigh));

        avl_remove(&dhash_tree, &dhn->dhash, -300195);

        purge_dhash_iid(dhn->myIID4orig);

        // It must be ensured that I am not reusing this IID for a while, so it must be invalidated
        // but the description and its' resulting dhash might become valid again, so I give it a unique and illegal value.
        memset(&dhn->dhash, 0, sizeof ( DHASH_T));
        dhn->dhash.h.u32[(sizeof ( DHASH_T) / sizeof (uint32_t)) - 1] = blocked_counter++;

	invalidate_dhash(dhn, NULL);
}

struct dhash_node* get_dhash_node(uint8_t *desc_frame, uint32_t desc_frame_len, struct desc_extension* dext, DHASH_T *dhash)
{

        dext->dhn = debugMallocReset(sizeof ( struct dhash_node), -300001);
	dext->dhn->desc_frame = desc_frame;
	dext->dhn->desc_frame_len = desc_frame_len;
	dext->dhn->dext = dext;
	dext->dhn->dhash = *dhash;

	return dext->dhn;
}


void update_neigh_dhash(struct orig_node *on, struct dhash_node *dhn)
{

        struct neigh_node *neigh = NULL;

        if (on->dhn) {
                neigh = on->dhn->neigh;
                on->dhn->neigh = NULL;
                on->dhn->on = NULL;

		avl_remove(&dhash_tree, &on->dhn->dhash, -300195);

                invalidate_dhash(on->dhn, NULL);
        }

        dhn->myIID4orig = iid_new_myIID4x(dhn);
        dhn->on = on;
        avl_insert(&dhash_tree, dhn, -300142);

        on->dhn = dhn;
        on->updated_timestamp = bmx_time;

        dbgf_track(DBGT_INFO, "dhash %8X.. myIID4orig %d", dhn->dhash.h.u32[0], dhn->myIID4orig);

        if (neigh) {
                neigh->dhn = on->dhn;
                on->dhn->neigh = neigh;
        }

}



STATIC_FUNC
void free_neigh_node(struct neigh_node *neigh)
{
        TRACE_FUNCTION_CALL;

        dbgf_track(DBGT_INFO, "freeing id=%s",
                neigh && neigh->dhn && neigh->dhn->on ? cryptShaAsString(&neigh->dhn->on->nodeId) : DBG_NIL);

        assertion(-500963, (neigh));
        assertion(-500964, (neigh->dhn));
        assertion(-500965, (neigh->dhn->neigh == neigh));
        assertion(-500966, (neigh->local));
        assertion(-500967, (neigh->local->neigh == neigh));

        avl_remove(&neigh_tree, &neigh->nnkey, -300196);
        iid_purge_repos(&neigh->neighIID4x_repos);

        neigh->dhn->neigh = NULL;
        neigh->dhn = NULL;
        neigh->local->neigh = NULL;
        neigh->local = NULL;

        debugFree(neigh, -300129);
}



STATIC_FUNC
void create_neigh_node(struct local_node *local, struct dhash_node * dhn)
{
        TRACE_FUNCTION_CALL;
        assertion(-500400, (dhn && !dhn->neigh));

        struct neigh_node *neigh = debugMallocReset(sizeof ( struct neigh_node), -300131);

        local->neigh = neigh;
        local->neigh->local = local;

        neigh->dhn = dhn;
        dhn->neigh = neigh->nnkey = neigh;
        avl_insert(&neigh_tree, neigh, -300141);
}



void update_local_neigh(struct packet_buff *pb, struct dhash_node *dhn)
{
        TRACE_FUNCTION_CALL;
        struct local_node *local = pb->i.link->local;

        dbgf_all(DBGT_INFO, "local_id=0x%X  dhn->id=%s", local->local_id, cryptShaAsString(&dhn->on->nodeId));

        assertion(-500517, (dhn != self->dhn));
        ASSERTION(-500392, (pb->i.link == avl_find_item(&local->link_tree, &pb->i.link->key.dev_idx)));
        assertion(-500390, (dhn && dhn->on && dhn->on->dhn == dhn));

        if (!local->neigh && dhn->neigh) {

                assertion(-500956, (dhn->neigh->dhn == dhn));
                assertion(-500955, (dhn->neigh->local->neigh == dhn->neigh));

                dbgf_track(DBGT_INFO, "CHANGED link=%s -> LOCAL=%d->%d <- neighIID4me=%d <- dhn->id=%s",
                        pb->i.llip_str, dhn->neigh->local->local_id, local->local_id, dhn->neigh->neighIID4me,
                        cryptShaAsString(&dhn->on->nodeId));

                dhn->neigh->local->neigh = NULL;
                local->neigh = dhn->neigh;
                local->neigh->local = local;


        } else if (!local->neigh && !dhn->neigh) {

                create_neigh_node(local, dhn);

                dbgf_track(DBGT_INFO, "NEW link=%s <-> LOCAL=%d <-> NEIGHIID4me=%d <-> dhn->id=%s",
                        pb->i.llip_str, local->local_id, local->neigh->neighIID4me,
                        cryptShaAsString(&dhn->on->nodeId));

        } else if (
                dhn->neigh &&
                dhn->neigh->dhn == dhn &&
                dhn->neigh->local->neigh == dhn->neigh &&

                local->neigh &&
                local->neigh->local == local &&
                local->neigh->dhn->neigh == local->neigh
                ) {

        } else {

		dbgf_sys(DBGT_ERR, "NONMATCHING LINK=%s -> local=%d -> neighIID4me=%d -> dhn->id=%s",
			pb->i.llip_str, local->local_id,
			local->neigh ? local->neigh->neighIID4me : 0,
			local->neigh && local->neigh->dhn->on ? cryptShaAsString(&local->neigh->dhn->on->nodeId) : DBG_NIL);
		dbgf_sys(DBGT_ERR, "NONMATCHING local=%d <- neighIID4me=%d <- DHN=%s",
			dhn->neigh && dhn->neigh->local ? dhn->neigh->local->local_id : 0,
			dhn->neigh ? dhn->neigh->neighIID4me : 0,
			cryptShaAsString(&dhn->on->nodeId));

		if (dhn->neigh)
			free_neigh_node(dhn->neigh);

		if (local->neigh)
			free_neigh_node(local->neigh);

		cleanup_all(-500000);
	}

        assertion(-500954, (dhn->neigh));
        assertion(-500953, (dhn->neigh->dhn == dhn));
        assertion(-500952, (dhn->neigh->local->neigh == dhn->neigh));

        assertion(-500951, (local->neigh));
        assertion(-500050, (local->neigh->local == local));
        assertion(-500949, (local->neigh->dhn->neigh == local->neigh));
}







STATIC_FUNC
void purge_orig_router(struct orig_node *only_orig, struct link_dev_node *only_lndev, IDM_T only_useless)
{
        TRACE_FUNCTION_CALL;
        struct orig_node *on;
        struct avl_node *an = NULL;
        while ((on = only_orig) || (on = avl_iterate_item( &orig_tree, &an))) {

                struct local_node *local_key = NULL;
                struct router_node *rt;

                while ((rt = avl_next_item(&on->rt_tree, &local_key)) && (local_key = rt->local_key)) {

                        if (only_useless && (rt->mr.umetric >= UMETRIC_ROUTABLE))
                                continue;

                        if (only_lndev && (rt->local_key != only_lndev->key.link->local))
                                continue;

                        if (only_lndev && (rt->path_lndev_best != only_lndev) && (on->curr_rt_lndev != only_lndev))
                                continue;

                        dbgf_track(DBGT_INFO, "only_orig=%s only_lndev=%s,%s only_useless=%d purging metric=%ju router=%X (%s)",
                                only_orig ? cryptShaAsString(&only_orig->nodeId) : DBG_NIL,
                                only_lndev ? ip6AsStr(&only_lndev->key.link->link_ip):DBG_NIL,
                                only_lndev ? only_lndev->key.dev->label_cfg.str : DBG_NIL,
                                only_useless,rt->mr.umetric,
                                ntohl(rt->local_key->local_id),
                                rt->local_key && rt->local_key->neigh ? cryptShaAsString(&rt->local_key->neigh->dhn->on->nodeId) : "???");

                        if (on->best_rt_local == rt)
                                on->best_rt_local = NULL;

                        if (on->curr_rt_local == rt) {

                                set_ogmSqn_toBeSend_and_aggregated(on, on->ogmMetric_next, on->ogmSqn_maxRcvd, on->ogmSqn_maxRcvd);

                                cb_route_change_hooks(DEL, on);
                                on->curr_rt_local = NULL;
                                on->curr_rt_lndev = NULL;
                        }

                        avl_remove(&on->rt_tree, &rt->local_key, -300226);

                        debugFree(rt, -300225);


                        if (only_lndev)
                                break;
                }

                if (only_orig)
                        break;
        }
}


STATIC_FUNC
void purge_link_node(struct link_node_key *only_link_key, struct dev_node *only_dev, IDM_T only_expired)
{
        TRACE_FUNCTION_CALL;

        struct link_node *link;
        struct link_node_key link_key_it;
        memset(&link_key_it, 0, sizeof(link_key_it));
        IDM_T removed_link_adv = NO;

        dbgf_all( DBGT_INFO, "only_link_key=%X,%d only_dev=%s only_expired=%d",
                only_link_key ? ntohl(only_link_key->local_id) : 0, only_link_key ? only_link_key->dev_idx : -1,
                only_dev ? only_dev->label_cfg.str : DBG_NIL, only_expired);

        while ((link = (only_link_key ? avl_find_item(&link_tree, only_link_key) : avl_next_item(&link_tree, &link_key_it)))) {

                struct local_node *local = link->local;

                assertion(-500940, local);
                assertion(-500941, local == avl_find_item(&local_tree, &link->key.local_id));
                assertion(-500942, link == avl_find_item(&local->link_tree, &link->key.dev_idx));

                struct list_node *pos, *tmp, *prev = (struct list_node *) & link->lndev_list;

                link_key_it = link->key;

                list_for_each_safe(pos, tmp, &link->lndev_list)
                {
                        struct link_dev_node *lndev = list_entry(pos, struct link_dev_node, list);

                        if ((!only_dev || only_dev == lndev->key.dev) &&
                                (!only_expired || (((TIME_T) (bmx_time - lndev->pkt_time_max)) > (TIME_T) link_purge_to))) {

                                dbgf_track(DBGT_INFO, "purging lndev link=%s dev=%s",
                                        ip6AsStr( &link->link_ip), lndev->key.dev->label_cfg.str);

                                purge_orig_router(NULL, lndev, NO);

                                purge_tx_task_list(lndev->tx_task_lists, NULL, NULL);

                                if (lndev->link_adv_msg != LINKADV_MSG_IGNORED)
                                        removed_link_adv = YES; // delay update_my_link_adv() until trees are clean again!

                                if (lndev == local->best_lndev)
                                        local->best_lndev = NULL;

                                if (lndev == local->best_rp_lndev)
                                        local->best_rp_lndev = NULL;

                                if (lndev == local->best_tp_lndev)
                                        local->best_tp_lndev = NULL;


                                list_del_next(&link->lndev_list, prev);
                                avl_remove(&link_dev_tree, &lndev->key, -300221);
                                debugFree(lndev, -300044);

                        } else {
                                prev = pos;
                        }
                }

                assertion(-500323, (only_dev || only_expired || !link->lndev_list.items));

                if (!link->lndev_list.items) {

                        dbgf_track(DBGT_INFO, "purging: link local_id=%X link_ip=%s dev_idx=%d only_dev=%s",
                                ntohl(link->key.local_id), ip6AsStr( &link->link_ip),
                                 link->key.dev_idx, only_dev ? only_dev->label_cfg.str : "???");

                        struct avl_node *dev_avl;
                        struct dev_node *dev;
                        for(dev_avl = NULL; (dev = avl_iterate_item(&dev_ip_tree, &dev_avl));) {
                                purge_tx_task_list(dev->tx_task_lists, link, NULL);
                        }

                        avl_remove(&link_tree, &link->key, -300193);
                        avl_remove(&local->link_tree, &link->key.dev_idx, -300330);

                        if (!local->link_tree.items) {

                                dbgf_track(DBGT_INFO, "purging: local local_id=%X", ntohl(link->key.local_id));

                                if (local->neigh)
                                        free_neigh_node(local->neigh);

                                if (local->dev_adv)
                                        debugFree(local->dev_adv, -300339);

                                if (local->link_adv)
                                        debugFree(local->link_adv, -300347);

                                assertion(-501135, (!local->orig_routes));

                                avl_remove(&local_tree, &link->key.local_id, -300331);

                                debugFree(local, -300333);
                                local = NULL;
                        }

                        debugFree( link, -300045 );
                }

                if (only_link_key)
                        break;
        }

        lndev_assign_best(NULL, NULL);
        cb_plugin_hooks(PLUGIN_CB_LINKS_EVENT, NULL);


        if (removed_link_adv)
                update_my_link_adv(LINKADV_CHANGES_REMOVED);

}

void purge_local_node(struct local_node *local)
{
        TRACE_FUNCTION_CALL;

        uint16_t link_tree_items = local->link_tree.items;
        struct link_node *link;

        assertion(-501015, (link_tree_items));

        while (link_tree_items && (link = avl_first_item(&local->link_tree))) {

                assertion(-501016, (link_tree_items == local->link_tree.items));
                purge_link_node(&link->key, NULL, NO);
                link_tree_items--;
        }

}

void block_orig_node(IDM_T block, struct orig_node *on)
{

        if (block && !on->blocked) {

                on->blocked = YES;

                if (!avl_find(&blocked_tree, &on->nodeId))
                        avl_insert(&blocked_tree, on, -300165);


        } else if (!block && on->blocked) {

                on->blocked = NO;
                avl_remove(&blocked_tree, &on->nodeId, -300201);
        }
}

void free_orig_node(struct orig_node *on)
{
        TRACE_FUNCTION_CALL;
        dbgf_all(DBGT_INFO, "id=%s ip=%s", cryptShaAsString(&on->nodeId), on->primary_ip_str);

        //cb_route_change_hooks(DEL, on, 0, &on->ort.rt_key.llip);

/*	if (on==self)
		return;
*/
        purge_orig_router(on, NULL, NO);

        if (on->added) {
		assertion(-500000, (on->dhn && on->dhn->desc_frame));
                process_description_tlvs(NULL, on, on->dhn, TLV_OP_DEL, FRAME_TYPE_PROCESS_ALL);
        }

        if ( on->dhn ) {
                on->dhn->on = NULL;

                if (on->dhn->neigh)
                        free_neigh_node(on->dhn->neigh);

                release_dhash(on->dhn);
        }

        avl_remove(&orig_tree, &on->nodeId, -300200);
        cb_plugin_hooks(PLUGIN_CB_STATUS, NULL);

        uint16_t i;
        for (i = 0; i < plugin_data_registries[PLUGIN_DATA_ORIG]; i++) {
                assertion(-501269, (!on->plugin_data[i]));
        }


        block_orig_node(NO, on);

        debugFree( on, -300086 );
}


void purge_link_route_orig_nodes(struct dev_node *only_dev, IDM_T only_expired)
{
        TRACE_FUNCTION_CALL;

        dbgf_all( DBGT_INFO, "%s %s only expired",
                only_dev ? only_dev->label_cfg.str : DBG_NIL, only_expired ? " " : "NOT");

        purge_link_node(NULL, only_dev, only_expired);

        int i;
        for (i = IID_RSVD_MAX + 1; i < my_iid_repos.max_free; i++) {

                struct dhash_node *dhn;

                if ((dhn = my_iid_repos.arr.node[i]) && dhn->on) {

                        if (!only_dev && (!only_expired ||
                                ((TIME_T) (bmx_time - dhn->referred_by_me_timestamp)) > (TIME_T) ogm_purge_to)) {

                                dbgf_all(DBGT_INFO, "id=%s referred before: %d > purge_to=%d",
                                        cryptShaAsString(&dhn->on->nodeId),
                                        ((TIME_T) (bmx_time - dhn->referred_by_me_timestamp)), (TIME_T) ogm_purge_to);


                                if (dhn->desc_frame && dhn->on != self)
                                        cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_DESTROY, dhn->on);

                                free_orig_node(dhn->on);

                        } else if (only_expired) {

                                purge_orig_router(dhn->on, NULL, YES /*only_useless*/);
                        }
                }
        }
}



SHA1_T *nodeIdFromDescAdv( uint8_t *desc_adv )
{
	struct tlv_hdr tlvHdr = { .u.u16 = ntohs(((struct tlv_hdr*)desc_adv)->u.u16) };
	struct desc_hdr_rhash *rhashHdr = ((struct desc_hdr_rhash*)(desc_adv + sizeof(struct tlv_hdr)));

	assertion( -500000, (tlvHdr.u.tlv.type == BMX_DSC_TLV_RHASH ));
	assertion( -500000, (tlvHdr.u.tlv.length == sizeof(struct tlv_hdr) + sizeof(struct desc_hdr_rhash) + sizeof(struct desc_msg_rhash) ));
	assertion( -500000, (!rhashHdr->compression && !rhashHdr->reserved && rhashHdr->expanded_type == BMX_DSC_TLV_PUBKEY));

	return &rhashHdr->msg->rframe_hash;
}

char *nodeIdAsStringFromDescAdv( uint8_t *desc_adv )
{
	return cryptShaAsString(nodeIdFromDescAdv(desc_adv));
}

struct orig_node *init_orig_node(GLOBAL_ID_T *id)
{
        TRACE_FUNCTION_CALL;
        struct orig_node *on = debugMallocReset(sizeof ( struct orig_node) + (sizeof (void*) * plugin_data_registries[PLUGIN_DATA_ORIG]), -300128);
        on->nodeId = *id;

        AVL_INIT_TREE(on->rt_tree, struct router_node, local_key);

        avl_insert(&orig_tree, on, -300148);

        cb_plugin_hooks(PLUGIN_CB_STATUS, NULL);

        return on;
}


LOCAL_ID_T new_local_id(struct dev_node *dev)
{
        uint16_t tries = 0;
        LOCAL_ID_T new_local_id = LOCAL_ID_INVALID;

        if (!my_local_id_timestamp) {

                // first time we try our mac address:
                if (dev && !is_zero(&dev->mac, sizeof (dev->mac))) {

                        memcpy(&(((char*) &new_local_id)[1]), &(dev->mac.u8[3]), sizeof ( LOCAL_ID_T) - 1);
                        ((char*) &new_local_id)[0] = rand_num(255);
                }


#ifdef TEST_LINK_ID_COLLISION_DETECTION
                new_local_id = LOCAL_ID_MIN;
#endif
        }

        while (new_local_id == LOCAL_ID_INVALID && tries < LOCAL_ID_ITERATIONS_MAX) {

                new_local_id = htonl(rand_num(LOCAL_ID_MAX - LOCAL_ID_MIN) + LOCAL_ID_MIN);
                struct avl_node *an = NULL;
                struct local_node *local;
                while ((local = avl_iterate_item(&local_tree, &an))) {

                        if (new_local_id == local->local_id) {

                                tries++;

                                if (tries % LOCAL_ID_ITERATIONS_WARN == 0) {
                                        dbgf_sys(DBGT_ERR, "No free dev_id after %d trials (local_tree.items=%d, dev_ip_tree.items=%d)!",
                                                tries, local_tree.items, dev_ip_tree.items);
                                }

                                new_local_id = LOCAL_ID_INVALID;
                                break;
                        }
                }
        }

        my_local_id_timestamp = bmx_time;
        return (my_local_id = new_local_id);
}



STATIC_FUNC
struct link_node *get_link_node(struct packet_buff *pb)
{
        TRACE_FUNCTION_CALL;
        struct link_node *link;
        dbgf_all(DBGT_INFO, "NB=%s, local_id=%X dev_idx=0x%X",
                pb->i.llip_str, ntohl(pb->i.link_key.local_id), pb->i.link_key.dev_idx);

        struct local_node *local = avl_find_item(&local_tree, &pb->i.link_key.local_id);


        if (local) {

                if ((((LINKADV_SQN_T) (pb->i.link_sqn - local->packet_link_sqn_ref)) > LINKADV_SQN_DAD_RANGE)) {

                        dbgf_sys(DBGT_ERR, "DAD-Alert NB=%s local_id=%X dev=%s link_sqn=%d link_sqn_max=%d dad_range=%d dad_to=%d",
                                pb->i.llip_str, ntohl(pb->i.link_key.local_id), pb->i.iif->label_cfg.str, pb->i.link_sqn, local->packet_link_sqn_ref,
                                LINKADV_SQN_DAD_RANGE, LINKADV_SQN_DAD_RANGE * my_tx_interval);

                        purge_local_node(local);

                        assertion(-500984, (!avl_find_item(&local_tree, &pb->i.link_key.local_id)));

                        return NULL;
                }
        }


        link = NULL;

        if (local) {

                link = avl_find_item(&local->link_tree, &pb->i.link_key.dev_idx);

                assertion(-500943, (link == avl_find_item(&link_tree, &pb->i.link_key)));

                if (link && !is_ip_equal(&pb->i.llip, &link->link_ip)) {

/*
                        if (((TIME_T) (bmx_time - link->pkt_time_max)) < (TIME_T) dad_to) {

                                dbgf_sys(DBGT_WARN,
                                        "DAD-Alert (local_id collision, this can happen)! NB=%s via dev=%s"
                                        "cached llIP=%s local_id=%X dev_idx=0x%X ! sending problem adv...",
                                        pb->i.llip_str, pb->i.iif->label_cfg.str, ip6AsStr( &link->link_ip),
                                        ntohl(pb->i.link_key.local_id), pb->i.link_key.dev_idx);

                                // be carefull here. Errornous PROBLEM_ADVs cause neighboring nodes to cease!!!
                                //struct link_dev_node dummy_lndev = {.key ={.dev = pb->i.iif, .link = link}, .mr = {ZERO_METRIC_RECORD, ZERO_METRIC_RECORD}};

				struct problem_type problem = { .problem_code = FRAME_TYPE_PROBLEM_CODE_DUP_LINK_ID, .local_id = link->key.local_id };

                                schedule_tx_task(&pb->i.iif->dummy_lndev, FRAME_TYPE_PROBLEM_ADV, sizeof (struct msg_problem_adv),
                                        &problem, sizeof(problem), 0, pb->i.transmittersIID);

                                // its safer to purge the old one, otherwise we might end up with hundrets
                                //return NULL;
                        }
*/
                        dbgf_sys(DBGT_WARN, "Reinitialized! NB=%s via dev=%s "
                                "cached llIP=%s local_id=%X dev_idx=0x%X ! Reinitializing link_node...",
                                pb->i.llip_str, pb->i.iif->label_cfg.str, ip6AsStr( &link->link_ip),
                                ntohl(pb->i.link_key.local_id), pb->i.link_key.dev_idx);

                        purge_link_node(&link->key, NULL, NO);
                        ASSERTION(-500213, !avl_find(&link_tree, &pb->i.link_key));
                        link = NULL;
                }

        } else {

                if (local_tree.items >= LOCALS_MAX) {
                        dbgf_sys(DBGT_WARN, "max number of locals reached");
                        return NULL;
                }

                assertion(-500944, (!avl_find_item(&link_tree, &pb->i.link_key)));
                local = debugMallocReset(sizeof(struct local_node), -300336);
                AVL_INIT_TREE(local->link_tree, struct link_node, key.dev_idx);
                local->local_id = pb->i.link_key.local_id;
                local->link_adv_msg_for_me = LINKADV_MSG_IGNORED;
                local->link_adv_msg_for_him = LINKADV_MSG_IGNORED;
                avl_insert(&local_tree, local, -300337);
        }

        local->packet_link_sqn_ref = pb->i.link_sqn;
        local->packet_time = bmx_time;


        if (!link) {

                link = debugMallocReset(sizeof (struct link_node), -300024);

                LIST_INIT_HEAD(link->lndev_list, struct link_dev_node, list, list);

                link->key = pb->i.link_key;
                link->link_ip = pb->i.llip;
                link->local = local;

                avl_insert(&link_tree, link, -300147);
                avl_insert(&local->link_tree, link, -300334);

                dbgf_track(DBGT_INFO, "creating new link=%s (total %d)", pb->i.llip_str, link_tree.items);

        }

        link->pkt_time_max = bmx_time;

        return link;
}



struct link_dev_node *get_link_dev_node(struct packet_buff *pb)
{
        TRACE_FUNCTION_CALL;

        assertion(-500607, (pb->i.iif));

        struct link_dev_node *lndev = NULL;
        struct dev_node *dev = pb->i.iif;

        struct link_node *link = get_link_node(pb);

        if (!(pb->i.link = link))
                return NULL;


        while ((lndev = list_iterate(&link->lndev_list, lndev))) {

                if (lndev->key.dev == dev)
                        break;
        }

        if (!lndev) {

                lndev = debugMallocReset(sizeof ( struct link_dev_node), -300023);

                lndev->key.dev = dev;
                lndev->key.link = link;
                lndev->link_adv_msg = LINKADV_MSG_IGNORED;


                int i;
                for (i = 0; i < FRAME_TYPE_ARRSZ; i++) {
                        LIST_INIT_HEAD(lndev->tx_task_lists[i], struct tx_task_node, list, list);
                }


                dbgf_track(DBGT_INFO, "creating new lndev %16s %s", ip6AsStr(&link->link_ip), dev->name_phy_cfg.str);

                list_add_tail(&link->lndev_list, &lndev->list);

                ASSERTION(-500489, !avl_find(&link_dev_tree, &lndev->key));

                avl_insert(&link_dev_tree, lndev, -300220);

                lndev_assign_best(link->local, lndev);
                cb_plugin_hooks(PLUGIN_CB_LINKS_EVENT, NULL);

        }

        lndev->pkt_time_max = bmx_time;

        return lndev;
}


void node_tasks(void) {

	struct orig_node *on;
	GLOBAL_ID_T id;
	memset(&id, 0, sizeof (GLOBAL_ID_T));

	purge_link_route_orig_nodes(NULL, YES);

	purge_dhash_invalid_list(NO);

	while ((on = avl_next_item(&blocked_tree, &id))) {

		id = on->nodeId;

		dbgf_all( DBGT_INFO, "trying to unblock nodeId=%s...", nodeIdAsStringFromDescAdv(on->dhn->desc_frame) );

		assertion(-501351, (on->blocked && !on->added));

		int32_t result = process_description_tlvs(NULL, on, on->dhn, TLV_OP_TEST, FRAME_TYPE_PROCESS_ALL);

		assertion(-500000, (result==TLV_RX_DATA_DONE || result==TLV_RX_DATA_BLOCKED));

		if (result == TLV_RX_DATA_DONE) {

			cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_DESTROY, on);

			result = process_description_tlvs(NULL, on, on->dhn, TLV_OP_NEW, FRAME_TYPE_PROCESS_ALL);

			assertion(-500364, (result == TLV_RX_DATA_DONE)); // checked, so MUST SUCCEED!!

			cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_CREATED, on);
		}

		dbgf_track(DBGT_INFO, "unblocking nodeId=%s %s !",
			nodeIdAsStringFromDescAdv(on->dhn->desc_frame), tlv_rx_result_str(result));
	}
}

static struct opt_type node_options[]=
{
#ifndef LESS_OPTIONS
	{ODI,0,ARG_OGM_PURGE_TO,    	0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&ogm_purge_to,	MIN_OGM_PURGE_TO,	MAX_OGM_PURGE_TO,	DEF_OGM_PURGE_TO,0,	0,
			ARG_VALUE_FORM,	"timeout in ms for purging stale originators"}
        ,
	{ODI,0,ARG_LINK_PURGE_TO,    	0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&link_purge_to,	MIN_LINK_PURGE_TO,MAX_LINK_PURGE_TO,DEF_LINK_PURGE_TO,0,0,
			ARG_VALUE_FORM,	"timeout in ms for purging stale links"}
        ,
#endif
};


void init_node(void) {
        register_options_array(node_options, sizeof ( node_options), CODE_CATEGORY_NAME);

}

void cleanup_node(void) {

/*	if (self) {
		if (self->dhn) {
			self->dhn->on = NULL;
			release_dhash(self->dhn);
		}

		avl_remove(&orig_tree, &(self->nodeId), -300203);
		debugFree(self, -300386);
		self = NULL;
	}
*/
	while (status_tree.items) {
		struct status_handl *handl = avl_remove_first_item(&status_tree, -300357);
		if (handl->data)
			debugFree(handl->data, -300359);
		debugFree(handl, -300363);
	}

	purge_dhash_invalid_list(YES);

}