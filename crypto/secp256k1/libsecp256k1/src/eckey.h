/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_ECKEY_
#define _SECP256K1_ECKEY_

#include <stddef.h>

#include "group.h"
#include "scalar.h"
#include "ecmult.h"
#include "ecmult_gen.h"

static int vet_secp256k1_eckey_pubkey_parse(vet_secp256k1_ge *elem, const unsigned char *pub, size_t size);
static int vet_secp256k1_eckey_pubkey_serialize(vet_secp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed);

static int vet_secp256k1_eckey_privkey_tweak_add(vet_secp256k1_scalar *key, const vet_secp256k1_scalar *tweak);
static int vet_secp256k1_eckey_pubkey_tweak_add(const vet_secp256k1_ecmult_context *ctx, vet_secp256k1_ge *key, const vet_secp256k1_scalar *tweak);
static int vet_secp256k1_eckey_privkey_tweak_mul(vet_secp256k1_scalar *key, const vet_secp256k1_scalar *tweak);
static int vet_secp256k1_eckey_pubkey_tweak_mul(const vet_secp256k1_ecmult_context *ctx, vet_secp256k1_ge *key, const vet_secp256k1_scalar *tweak);

#endif
