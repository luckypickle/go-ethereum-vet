/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_ECDSA_
#define _SECP256K1_ECDSA_

#include <stddef.h>

#include "scalar.h"
#include "group.h"
#include "ecmult.h"

static int vet_secp256k1_ecdsa_sig_parse(vet_secp256k1_scalar *r, vet_secp256k1_scalar *s, const unsigned char *sig, size_t size);
static int vet_secp256k1_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const vet_secp256k1_scalar *r, const vet_secp256k1_scalar *s);
static int vet_secp256k1_ecdsa_sig_verify(const vet_secp256k1_ecmult_context *ctx, const vet_secp256k1_scalar* r, const vet_secp256k1_scalar* s, const vet_secp256k1_ge *pubkey, const vet_secp256k1_scalar *message);
static int vet_secp256k1_ecdsa_sig_sign(const vet_secp256k1_ecmult_gen_context *ctx, vet_secp256k1_scalar* r, vet_secp256k1_scalar* s, const vet_secp256k1_scalar *seckey, const vet_secp256k1_scalar *message, const vet_secp256k1_scalar *nonce, int *recid);

#endif
