/*
 * TPM2 utilities for LUKS2 TPM2 type keyslot
 *
 * Copyright (C) 2018-2019 Fraunhofer SIT sponsorred by Infineon Technologies AG
 * Copyright (C) 2019 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2019 Daniel Zatovic
 * Copyright (C) 2019 Milan Broz
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _UTILS_TPM2_H
#define _UTILS_TPM2_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct crypt_device;

__attribute__((format(printf, 3, 4)))
void my_logger(struct crypt_device *cd, int level, const char *format, ...);

#define l_std(cd, x...) my_logger(cd, CRYPT_LOG_NORMAL, x)
#define l_err(cd, x...) my_logger(cd, CRYPT_LOG_ERROR, x)
#define l_dbg(cd, x...) my_logger(cd, CRYPT_LOG_DEBUG, x)

/** Flag for activating the SHA1 PCR bank */
#define CRYPT_TPM_PCRBANK_SHA1 (1 << 0)

/** Flag for activating the SHA256 PCR bank */
#define CRYPT_TPM_PCRBANK_SHA256 (1 << 1)

/** Flag for activating the SHA384 PCR bank */
#define CRYPT_TPM_PCRBANK_SHA384 (1 << 2)

/** Flag for activating the SHA512 PCR bank */
#define CRYPT_TPM_PCRBANK_SHA512 (1 << 3)

int tpm_nv_read(struct crypt_device *cd,
	uint32_t tpm_nv,
	const char *pin,
	size_t pin_size,
	uint32_t tpm_pcr,
	uint32_t pcrbanks,
	char *nvkey,
	size_t nvkey_size);

int tpm_nv_write(struct crypt_device *cd,
	uint32_t tpm_nv,
	const char *pin,
	size_t pin_size,
	const char *buffer,
	size_t buffer_size);

int tpm_nv_define(struct crypt_device *cd,
	uint32_t tpm_nv,
	const char *pin,
	size_t pin_size,
	uint32_t tpm_pcr,
	uint32_t pcrbanks,
	bool daprotect,
	const char *ownerpw,
	size_t ownerpw_size,
	size_t nvkey_size);

int tpm_nv_undefine(struct crypt_device *cd, uint32_t tpm_nv);

int tpm_nv_find(struct crypt_device *cd, uint32_t *tpm_nv);

int tpm_nv_exists(struct crypt_device *cd, uint32_t tpm_nv);

int tpm_get_random(struct crypt_device *cd, char *random_bytes, size_t len);

/*
 * TPM2 token helpers
 */

int tpm2_token_add(struct crypt_device *cd,
	uint32_t tpm_nv,
	uint32_t tpm_pcr,
	uint32_t pcrbanks,
	bool daprotect,
	bool pin,
	size_t nvkey_size);

int tpm2_token_read(struct crypt_device *cd,
	const char *json,
	uint32_t *tpm_nv,
	uint32_t *tpm_pcr,
	uint32_t *pcrbanks,
	bool *daprotect,
	bool *pin,
	size_t *nvkey_size);

int tpm2_token_by_nvindex(struct crypt_device *cd, uint32_t tpm_nv);

int tpm2_token_kill(struct crypt_device *cd, int token);
int tpm2_token_validate(const char *json);

int tpm2_token_get_pcrbanks(const char *pcrbanks_str, uint32_t *pcrbanks);
int tpm2_token_get_pcrs(const char *pcrs_str, uint32_t *pcrs);

#endif /* _UTILS_TPM2_H */
