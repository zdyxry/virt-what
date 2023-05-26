/* virt-what-cvm-helper: Are we running inside confidential VM
 * Copyright (C) 2023 Red Hat Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#ifdef HAVE_TPM2_TSS
#include <tss2/tss2_esys.h>
#include <assert.h>
#endif

static bool dodebug = false;

#define debug(...) do { if (dodebug) fprintf(stderr, __VA_ARGS__); } while(0)

/*
 * AMD64 Architecture Programmer’s Manual Volume 3:
 * General-Purpose and System Instructions.
 * Chapter: E4.1 - Maximum Extended Function Number and Vendor String
 *  https://www.amd.com/system/files/TechDocs/24594.pdf
 */
#define CPUID_GET_HIGHEST_FUNCTION 0x80000000

/*
 * AMD64 Architecture Programmer’s Manual Volume 3:
 * General-Purpose and System Instructions.
 * Chapter: E4.17 - Encrypted Memory Capabilities
 *  https://www.amd.com/system/files/TechDocs/24594.pdf
 */
#define CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES 0x8000001f

/*
 * AMD64 Architecture Programmer’s Manual Volume 3:
 * General-Purpose and System Instructions.
 * Chapter: 15.34.10 - SEV_STATUS MSR
 * https://www.amd.com/system/files/TechDocs/24593.pdf
 */
#define MSR_AMD64_SEV 0xc0010131

/*
 * Intel® TDX Module v1.5 Base Architecture Specification
 * Chapter: 11.2
 * https://www.intel.com/content/www/us/en/content-details/733575/intel-tdx-module-v1-5-base-architecture-specification.html
 */

#define CPUID_INTEL_TDX_ENUMERATION 0x21


#define CPUID_SIG_AMD       "AuthenticAMD"
#define CPUID_SIG_INTEL     "GenuineIntel"
#define CPUID_SIG_INTEL_TDX "IntelTDX    "

/*
 * This TPM NV data format is not explicitly documented anywhere,
 * but the header definition is present in code at:
 *
 * https://github.com/kinvolk/azure-cvm-tooling/blob/main/az-snp-vtpm/src/hcl.rs
 */
#define TPM_AZURE_HCLA_REPORT_INDEX 0x01400001

struct TPMAzureHCLAHeader {
  uint32_t signature;
  uint32_t version;
  uint32_t report_len;
  uint32_t report_type;
  uint32_t unknown[4];
};

/* The bytes for "HCLA" */
#define TPM_AZURE_HCLA_SIGNATURE 0x414C4348
#define TPM_AZURE_HCLA_VERSION 0x1
#define TPM_AZURE_HCLA_REPORT_TYPE_SNP 0x2

#if defined(__x86_64__)

#ifdef HAVE_TPM2_TSS
static char *
tpm_nvread(uint32_t nvindex, size_t *retlen)
{
  TSS2_RC rc;
  ESYS_CONTEXT *ctx = NULL;
  ESYS_TR primary = ESYS_TR_NONE;
  ESYS_TR session = ESYS_TR_NONE;
  ESYS_TR nvobj = ESYS_TR_NONE;
  TPM2B_NV_PUBLIC *pubData = NULL;
  TPMT_SYM_DEF sym = {
    .algorithm = TPM2_ALG_AES,
    .keyBits = { .aes = 128 },
    .mode = { .aes = TPM2_ALG_CFB }
  };
  char *ret;
  size_t retwant;

  rc = Esys_Initialize(&ctx, NULL, NULL);
  if (rc != TSS2_RC_SUCCESS)
    return NULL;

  rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
  debug("tpm startup %d\n", rc);
  if (rc != TSS2_RC_SUCCESS)
    goto error;

  rc = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE,
			     ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			     NULL, 0,
			     &sym, TPM2_ALG_SHA256, &session);
  debug("tpm auth session %d\n", rc);
  if (rc != TSS2_RC_SUCCESS)
    goto error;

  rc = Esys_TR_FromTPMPublic(ctx, nvindex, ESYS_TR_NONE,
			     ESYS_TR_NONE, ESYS_TR_NONE, &nvobj);
  debug("tpm from public %d\n", rc);
  if (rc != TSS2_RC_SUCCESS)
    goto error;

  rc = Esys_NV_ReadPublic(ctx, nvobj, ESYS_TR_NONE,
			  ESYS_TR_NONE, ESYS_TR_NONE,
			  &pubData, NULL);
  debug("tpm read public %d\n", rc);
  if (rc != TPM2_RC_SUCCESS)
    goto error;

  retwant = pubData->nvPublic.dataSize;
  free(pubData);
  *retlen = 0;
  ret = malloc(retwant);
  assert(ret);
  while (*retlen < retwant) {
    size_t want = retwant - *retlen;
    TPM2B_MAX_NV_BUFFER *data = NULL;
    if (want > 1024)
      want = 1024;
    rc = Esys_NV_Read(ctx,  ESYS_TR_RH_OWNER, nvobj, session, ESYS_TR_NONE, ESYS_TR_NONE,
		      want, *retlen, &data);
    debug("tpm nv read %d\n", rc);
    if (rc != TPM2_RC_SUCCESS) {
      free(ret);
      goto error;
    }

    memcpy(ret + *retlen, data->buffer, data->size);
    *retlen += data->size;
    free(data);
  }

  return ret;

 error:
  if (nvobj != ESYS_TR_NONE)
    Esys_FlushContext(ctx, nvobj);
  if (session != ESYS_TR_NONE)
    Esys_FlushContext(ctx, session);
  if (primary != ESYS_TR_NONE)
    Esys_FlushContext(ctx, primary);
  Esys_Finalize(&ctx);
  *retlen = 0;
  return NULL;
}
#else /* ! HAVE_TPM2_TSS */
static char *
tpm_nvread(uint32_t nvindex, size_t *retlen)
{
  return NULL;
}
#endif /* ! HAVE_TPM2_TSS */

/* Copied from the Linux kernel definition in
 * arch/x86/include/asm/processor.h
 */
static inline void
cpuid (uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
  debug("CPUID func %x %x\n", *eax, *ecx);
  asm volatile ("cpuid"
                : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
                : "0" (*eax), "2" (*ecx)
                : "memory");
  debug("CPUID result %x %x %x %x\n", *eax, *ebx, *ecx, *edx);
}


static uint32_t
cpuid_leaf (uint32_t eax, char *sig)
{
  uint32_t *sig32 = (uint32_t *) sig;

  cpuid (&eax, &sig32[0], &sig32[2], &sig32[1]);
  sig[12] = 0; /* \0-terminate the string to make string comparison possible */
  debug("CPUID sig %s\n", sig);
  return eax;
}

#define MSR_DEVICE "/dev/cpu/0/msr"

static uint64_t
msr (off_t index)
{
  uint64_t ret;
  int fd = open (MSR_DEVICE, O_RDONLY);
  if (fd < 0) {
    debug ("Cannot open MSR device %s", MSR_DEVICE);
    return 0;
  }

  if (pread (fd, &ret, sizeof(ret), index) != sizeof(ret))
    ret = 0;

  close (fd);

  debug ("MSR %llx result %llx\n", (unsigned long long)index,
	 (unsigned long long)ret);
  return ret;
}

bool
cpu_sig_amd_azure (void)
{
  size_t datalen = 0;
  char *data = tpm_nvread(TPM_AZURE_HCLA_REPORT_INDEX, &datalen);
  struct TPMAzureHCLAHeader *header = (struct TPMAzureHCLAHeader *)data;
  bool ret;

  if (!data)
    return false;

  if (datalen < sizeof(struct TPMAzureHCLAHeader)) {
    debug ("TPM data len is too small to be an Azure HCLA report");
    return false;
  }

  debug ("Azure TPM HCLA report header sig %x ver %x type %x\n",
	 header->signature, header->version, header->report_type);

  ret = (header->signature == TPM_AZURE_HCLA_SIGNATURE &&
	 header->version == TPM_AZURE_HCLA_VERSION &&
	 header->report_type == TPM_AZURE_HCLA_REPORT_TYPE_SNP);
  debug ("Azure TPM HCLA report present ? %d\n", ret);

  free(data);
  return ret;
}

static void
cpu_sig_amd (void)
{
  uint32_t eax, ebx, ecx, edx;
  uint64_t msrval;

  eax = CPUID_GET_HIGHEST_FUNCTION;
  ebx = ecx = edx = 0;

  cpuid (&eax, &ebx, &ecx, &edx);

  if (eax < CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES)
    return;

  eax = CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES;
  ebx = ecx = edx = 0;

  cpuid (&eax, &ebx, &ecx, &edx);

  /* bit 1 == CPU supports SEV feature
   *
   * Note, Azure blocks this CPUID leaf from its SEV-SNP
   * guests, so we must fallback to probing the TPM which
   * exposes a SEV-SNP attestation report as evidence.
   */
  if (!(eax & (1 << 1))) {
    debug ("No sev in CPUID, try azure TPM NV\n");

    if (cpu_sig_amd_azure()) {
      puts ("amd-sev-snp");
      puts ("azure-hcl");
    } else {
      debug("No azure TPM NV\n");
    }
    return;
  }

  msrval = msr (MSR_AMD64_SEV);

  /* Test reverse order, since the SEV-SNP bit implies
   * the SEV-ES bit, which implies the SEV bit */
  if (msrval & (1 << 2)) {
    puts ("amd-sev-snp");
  } else if (msrval & (1 << 1)) {
    puts ("amd-sev-es");
  } else if (msrval & (1 << 0)) {
    puts ("amd-sev");
  }
}

static void
cpu_sig_intel (void)
{
  uint32_t eax, ebx, ecx, edx;
  char sig[13];

  eax = CPUID_GET_HIGHEST_FUNCTION;
  ebx = ecx = edx = 0;

  cpuid (&eax, &ebx, &ecx, &edx);
  debug ("CPUID max function: %x %x %x %x\n", eax, ebx, ecx,edx);

  if (eax < CPUID_INTEL_TDX_ENUMERATION)
    return;

  memset (sig, 0, sizeof sig);
  cpuid_leaf (CPUID_INTEL_TDX_ENUMERATION, sig);

  if (memcmp (sig, CPUID_SIG_INTEL_TDX, sizeof(sig)) == 0)
    puts ("intel-tdx");
}

static void
cpu_sig (void)
{
  char sig[13];

  memset (sig, 0, sizeof sig);
  cpuid_leaf (0, sig);

  if (memcmp (sig, CPUID_SIG_AMD, sizeof(sig)) == 0)
    cpu_sig_amd ();
  else if (memcmp (sig, CPUID_SIG_INTEL, sizeof(sig)) == 0)
    cpu_sig_intel ();
}

#else /* !x86_64 */

static void
cpu_sig (void)
{
  /* nothing for other architectures */
}

#endif

int
main(int argc, char **argv)
{
  int c;

  while (true) {
    int option_index = 0;
    static struct option long_options[] = {
      {"debug", no_argument, 0, 'd' },
      {"version", no_argument, 0, 'v' },
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0 }
    };

    c = getopt_long(argc, argv, "dvh",
		    long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
    case 'd':
      dodebug = true;
      break;
    case 'v':
      fprintf(stdout, "%s\n", PACKAGE_VERSION);
      exit(EXIT_SUCCESS);
      break;
    case 'h':
    default: /* '?' */
      fprintf(c == 'h' ? stdout : stderr,
	      "Usage: %s [--debug|-d] [--help|-h] [--version|-v]\n",
	      argv[0]);
      exit(c == 'h' ? EXIT_SUCCESS : EXIT_FAILURE);
    }
  }

  if (!dodebug)
    setenv("TSS2_LOG", "all+none", 1);

  cpu_sig ();

  exit(EXIT_SUCCESS);
}
