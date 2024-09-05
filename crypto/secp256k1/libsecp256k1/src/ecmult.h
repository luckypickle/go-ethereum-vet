/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_ECMULT_
#define _SECP256K1_ECMULT_

#include "num.h"
#include "group.h"

typedef struct {
    /* For accelerating the computation of a*P + b*G: */
    vet_secp256k1_ge_storage (*pre_g)[];    /* odd multiples of the generator */
#ifdef USE_ENDOMORPHISM
    vet_secp256k1_ge_storage (*pre_g_128)[]; /* odd multiples of 2^128*generator */
#endif
} vet_secp256k1_ecmult_context;

static void vet_secp256k1_ecmult_context_init(vet_secp256k1_ecmult_context *ctx);
static void vet_secp256k1_ecmult_context_build(vet_secp256k1_ecmult_context *ctx, const vet_secp256k1_callback *cb);
static void vet_secp256k1_ecmult_context_clone(vet_secp256k1_ecmult_context *dst,
                                           const vet_secp256k1_ecmult_context *src, const vet_secp256k1_callback *cb);
static void vet_secp256k1_ecmult_context_clear(vet_secp256k1_ecmult_context *ctx);
static int vet_secp256k1_ecmult_context_is_built(const vet_secp256k1_ecmult_context *ctx);

/** Double multiply: R = na*A + ng*G */
static void vet_secp256k1_ecmult(const vet_secp256k1_ecmult_context *ctx, vet_secp256k1_gej *r, const vet_secp256k1_gej *a, const vet_secp256k1_scalar *na, const vet_secp256k1_scalar *ng);

#endif
