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

struct prof_ctx_key {
    struct neigh_node *neigh;
    struct orig_node *orig;
    char *name;
} __attribute__((packed));

struct prof_ctx {
    struct prof_ctx_key k;
    struct prof_ctx *parent;
    struct avl_tree childs_tree;
    int8_t active_childs;
    
    uint64_t timeBefore;
    uint64_t timePeriod;
    uint64_t timeTotal;
    clock_t clockBefore;
    clock_t clockPeriod;
    clock_t clockTotal;
    
    uint32_t load_kPercent;
};

struct prof_ctx *prof_init( char *name, char *parent, struct orig_node *orig, struct neigh_node *neigh);

void prof_free( struct prof_ctx **p);

void prof_start( struct prof_ctx *p);
void prof_stop( struct prof_ctx *p);


void init_prof( void );
void cleanup_prof(void);
