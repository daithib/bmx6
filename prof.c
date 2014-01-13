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

	avl_remove(&prof_tree, &((*p)->k), -300000);

	debugFree(*p, -300000);
	*p = NULL;
}

static uint8_t prof_check_disabled = 0;

STATIC_FUNC
int prof_check(struct prof_ctx *p, int childs)
{
	if (prof_check_disabled ||
		!p || (p->timeBefore && p->active_childs == childs && prof_check(p->parent, 1) == SUCCESS))
		return SUCCESS;

	dbgf_sys(DBGT_ERR, "%s % %p", p->k.name, p->k.neigh, p->k.orig);

	return FAILURE;
}

void prof_start( struct prof_ctx *p)
{
	assertion(-500000, (!p->timeBefore));
	assertion(-500000, (!p->active_childs));

	struct timeval tvBefore;

	upd_time(&tvBefore);
	p->timeBefore = (tvBefore.tv_sec * 1000000) + tvBefore.tv_usec;
	p->clockBefore = (TIME_T)clock();

	if (p->parent)
		p->parent->active_childs++;


	ASSERTION(-500000, (prof_check(p, 0) == SUCCESS));
}

void prof_end( struct prof_ctx *p)
{
	assertion(-500000, (p->timeBefore));
	assertion(-500000, (!p->active_childs));
	ASSERTION(-500000, (prof_check(p, 1) == SUCCESS));

	struct timeval tvAfter;
	TIME_T clockAfter = clock();

	upd_time(&tvAfter);

	uint64_t timeAfter = (tvAfter.tv_sec * 1000000) + tvAfter.tv_usec;

//	assertion(-500000, (clockAfter >= p->clockBefore)); //this wraps around some time..
	assertion(-500000, (timeAfter > p->timeBefore));

	p->clockPeriod += (clockAfter - p->clockBefore);
	p->timePeriod += (timeAfter - p->timeBefore);

	p->clockBefore = p->timeBefore = 0;

	if (p->parent)
		p->parent->active_childs--;
}

STATIC_FUNC
void prof_update( void *unused) {


	struct avl_node *an=NULL;
	struct prof_ctx *pn;

	prof_check_disabled = YES;

	while ((pn = avl_iterate_item(&prof_tree, &an))) {

		uint8_t active = (pn->timeBefore > 0);

		if (active)
			prof_end(pn);

		if (pn->timePeriod) {

			pn->load_kPercent = (((uint64_t)pn->clockPeriod)*
				((((uint64_t)100)*1000*1000000)/((uint64_t)CLOCKS_PER_SEC))) /
				pn->timePeriod;

			pn->clockTotal += pn->clockPeriod;
			pn->timeTotal += pn->timePeriod;

			pn->clockPeriod = 0;
			pn->timePeriod = 0;

		} else {
			pn->load_kPercent = 0;
		}


		if (active)
			prof_start(pn);
	}

	prof_check_disabled = NO;

	task_register(5000, prof_update, NULL, -300000);
}


struct prof_status {
        GLOBAL_ID_T *neighId;
        GLOBAL_ID_T *origId;
        char* name;
	uint32_t total;
	char cpu[10];
};

static const struct field_format prof_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  prof_status, neighId,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, prof_status, origId,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      prof_status, name,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              prof_status, total,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       prof_status, cpu,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_END
};

static int32_t prof_status_creator(struct status_handl *handl, void *data)
{
        struct avl_node *it = NULL;
        struct prof_ctx *pn;
        uint32_t status_size = (data ? 1 : prof_tree.items) * sizeof (struct prof_status);
        uint32_t i = 0;
        struct prof_status *status = ((struct prof_status*) (handl->data = debugRealloc(handl->data, status_size, -300366)));
        memset(status, 0, status_size);

        while (data ? (pn = data) : (pn = avl_iterate_item(&prof_tree, &it))) {

                status[i].neighId = pn->k.neigh ? &pn->k.neigh->dhn->on->nodeId : NULL;
                status[i].origId = &pn->k.orig ? &pn->k.orig->nodeId : NULL;
                status[i].name = pn->k.name;
		status[i].total = pn->clockTotal;
		sprintf(status->cpu, "%f", ((float)pn->load_kPercent)/1000);
                i++;
                if(data)
                        break;
        }

        return status_size;
}

static struct prof_ctx *prof_main = NULL;

void init_prof( void )
{
	register_status_handl(sizeof (struct prof_status), 1, prof_status_format, "cpu", prof_status_creator);

	task_register(5000, prof_update, NULL, -300000);

	prof_main = prof_init("main", NULL, NULL, NULL);

}

void cleanup_prof(void)
{

	prof_free(&prof_main);
}
