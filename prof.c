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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>


#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "allocate.h"
#include "tools.h"
#include "prof.h"
#include "schedule.h"

static AVL_TREE(prof_tree, struct prof_ctx, k);

struct prof_ctx *prof_init( char *name, char *parent, struct orig_node *orig, struct neigh_node *neigh)
{
	assertion(-500000, (name && strlen(name)< 100));
	assertion(-500000, (!(orig && neigh)));
	struct prof_ctx_key pk = {.name=parent};
	struct prof_ctx_key sk = {.name=name, .neigh=neigh, .orig=orig};

	struct prof_ctx *pp = parent ? avl_find_item(&prof_tree, &pk) : NULL;
	struct prof_ctx *sp = debugMallocReset(sizeof(struct prof_ctx), -300000);

	assertion(-500000, IMPLIES(parent, pp));
	assertion(-500000, (!avl_find_item(&prof_tree, &sk)));

	sp->k = sk;
	AVL_INIT_TREE(sp->childs_tree, struct prof_ctx, k);

	if (pp) {
		avl_insert(&pp->childs_tree, sp, -300000);
		sp->parent = pp;
	}

	avl_insert(&prof_tree, sp, -300000);

	return sp;
}

void prof_free( struct prof_ctx **p)
{
	assertion(-500000, (p && *p));
	assertion(-500000, (!(((*p)->childs_tree).items)));
	assertion(-500000, (avl_find_item(&prof_tree, &((*p)->k))));
//	assertion(-500000, !((*p)->timeBefore));
	
	avl_remove(&prof_tree, &((*p)->k), -300000);

	if ((*p)->parent)
		avl_remove(&((*p)->parent->childs_tree), &((*p)->k), -300000);

	debugFree(*p, -300000);
	*p = NULL;
}

static uint8_t prof_check_disabled = 0;

STATIC_FUNC
int prof_check(struct prof_ctx *p, int childs)
{
	if (prof_check_disabled ||
		!p || (p->active_prof && p->active_childs == childs && prof_check(p->parent, 1) == SUCCESS))
		return SUCCESS;

	dbgf_sys(DBGT_ERR, "%s % %p", p->k.name, p->k.neigh, p->k.orig);

	return FAILURE;
}

void prof_start( struct prof_ctx *p)
{
	assertion(-500000, (!p->active_prof));
	assertion(-500000, (!p->clockBeforePStart));
	assertion(-500000, (!p->active_childs));

	p->clockBeforePStart = (TIME_T)clock();
	p->active_prof = 1;

	if (p->parent)
		p->parent->active_childs++;

	ASSERTION(-500000, (prof_check(p, 0) == SUCCESS));
}

void prof_stop( struct prof_ctx *p)
{
	assertion(-500000, (p->active_prof));
	ASSERTION(-500000, (prof_check(p, 0) == SUCCESS));

	TIME_T clockAfter = clock();
	TIME_T clockPeriod = (clockAfter - p->clockBeforePStart);
	assertion(-500000, (clockPeriod < ((~((TIME_T)0))>>1)) ); //this wraps around some time..

	p->clockRunningPeriod += clockPeriod;

	p->clockBeforePStart = 0;
	p->active_prof = 0;

	if (p->parent)
		p->parent->active_childs--;
}

static uint64_t durationPrevPeriod = 0;
static uint64_t timeAfterPrevPeriod = 0;

STATIC_FUNC
void prof_update_all( void *unused) {

	struct avl_node *an=NULL;
	struct prof_ctx *pn;

	struct timeval tvAfterRunningPeriod;
	upd_time(&tvAfterRunningPeriod);
	uint64_t timeAfterRunningPeriod = (tvAfterRunningPeriod.tv_sec * 1000000) + tvAfterRunningPeriod.tv_usec;

	durationPrevPeriod = (timeAfterRunningPeriod - timeAfterPrevPeriod);

	assertion(-500000, (durationPrevPeriod > 0));
	assertion(-500000, (durationPrevPeriod < 10*1000000));

	prof_check_disabled = YES;

	while ((pn = avl_iterate_item(&prof_tree, &an))) {

		uint8_t active = pn->active_prof;

		dbgf_sys(DBGT_INFO, "updating %s active=%d", pn->k.name, active);

		if (active)
			prof_stop(pn);

		pn->clockPrevPeriod = pn->clockRunningPeriod;
		pn->clockPrevTotal += pn->clockRunningPeriod;

		pn->clockRunningPeriod = 0;

		if (active)
			prof_start(pn);
	}

	prof_check_disabled = NO;

	timeAfterPrevPeriod = timeAfterRunningPeriod;

	task_register(5000, prof_update_all, NULL, -300000);
}


struct prof_status {
        GLOBAL_ID_T *neighId;
        GLOBAL_ID_T *origId;
        char* name;
	char* parent;
//	uint32_t total;
	char sysCurrCpu[10];
	char relCurrCpu[10];
	char sysAvgCpu[10];
	char relAvgCpu[10];

};

static const struct field_format prof_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  prof_status, neighId,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, prof_status, origId,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      prof_status, name,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      prof_status, parent,        1, FIELD_RELEVANCE_HIGH),
//      FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              prof_status, total,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       prof_status, sysCurrCpu,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       prof_status, relCurrCpu,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       prof_status, sysAvgCpu,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       prof_status, relAvgCpu,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_END
};

STATIC_FUNC
struct prof_status *prof_status_iterate(struct prof_ctx *pn, struct prof_status *status)
{
	dbgf_sys(DBGT_INFO, "dbg pn=%s status=%p", pn->k.name, status);

	status->neighId = pn->k.neigh ? &pn->k.neigh->dhn->on->nodeId : NULL;
	status->origId = &pn->k.orig ? &pn->k.orig->nodeId : NULL;
	status->name = pn->k.name;
	status->parent = pn->parent ? pn->parent->k.name : NULL;
	sprintf(status->sysCurrCpu, DBG_NIL);
	sprintf(status->relCurrCpu, DBG_NIL);
	sprintf(status->sysAvgCpu, DBG_NIL);
	sprintf(status->relAvgCpu, DBG_NIL);

	if (!durationPrevPeriod || !timeAfterPrevPeriod)
		goto prof_status_iterate_childs;

	uint32_t loadPrevPeriod = (((uint64_t) pn->clockPrevPeriod)*
		((((uint64_t) 100)*1000 * 1000000) / ((uint64_t) CLOCKS_PER_SEC))) /
		durationPrevPeriod;

	sprintf(status->sysCurrCpu, "%.4f", ((float) loadPrevPeriod) / 1000);

	uint32_t loadPrevTotal = (((uint64_t) pn->clockPrevTotal)*
		((((uint64_t) 100)*1000 * 1000000) / ((uint64_t) CLOCKS_PER_SEC))) /
		timeAfterPrevPeriod;

	sprintf(status->sysAvgCpu, "%.4f", ((float) loadPrevTotal) / 1000);

	if (!pn->parent)
		goto prof_status_iterate_childs;

	uint32_t loadParentPrevPeriod = (((uint64_t) pn->parent->clockPrevPeriod)*
		((((uint64_t) 100)*1000 * 1000000) / ((uint64_t) CLOCKS_PER_SEC))) /
		durationPrevPeriod;

	if (loadParentPrevPeriod)
		sprintf(status->relCurrCpu, "%.4f", ((((float) loadPrevPeriod)*100) / ((float) loadParentPrevPeriod)));
	else if (!loadParentPrevPeriod && loadPrevPeriod)
		sprintf(status->relCurrCpu, "ERR");

	uint32_t loadParentPrevTotal = (((uint64_t) pn->parent->clockPrevTotal)*
		((((uint64_t) 100)*1000 * 1000000) / ((uint64_t) CLOCKS_PER_SEC))) /
		timeAfterPrevPeriod;

	if (loadParentPrevTotal)
		sprintf(status->relAvgCpu, "%.4f", ((((float) loadPrevTotal)*100) / ((float) loadParentPrevTotal)));
	else if (!loadParentPrevTotal && loadPrevTotal)
		sprintf(status->relAvgCpu, "ERR");


prof_status_iterate_childs: {

	status = &(status[1]);

	struct avl_node *an = NULL;
	struct prof_ctx *cn;
	while ((cn=avl_iterate_item(&pn->childs_tree, &an))) {
		status = prof_status_iterate(cn, status);
	}
}
	return status;
}

STATIC_FUNC
int32_t prof_status_creator(struct status_handl *handl, void *data)
{
        struct avl_node *it = NULL;
        struct prof_ctx *pn;
        uint32_t status_size = (prof_tree.items) * sizeof (struct prof_status);
        struct prof_status *status = ((struct prof_status*) (handl->data = debugRealloc(handl->data, status_size, -300366)));
        memset(status, 0, status_size);

	while ((pn = avl_iterate_item(&prof_tree, &it))) {

		if (!pn->parent) {
			status = prof_status_iterate(pn, status);
		}
        }

        return status_size;
}



void init_prof( void )
{
	register_status_handl(sizeof (struct prof_status), 1, prof_status_format, "cpu", prof_status_creator);

	task_register(5000, prof_update_all, NULL, -300000);

}

void cleanup_prof(void)
{

}
