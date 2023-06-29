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

static bool dodebug = false;

#define debug(...) do { if (dodebug) fprintf(stderr, __VA_ARGS__); } while(0)


#define CPUID_PROCESSOR_INFO_AND_FEATURE_BITS 0x1

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

/* Requirements for Implementing the Microsoft Hypervisor Interface
 * https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs
 */
#define CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS 0x40000000

#define CPUID_HYPERV_FEATURES 0x40000003

#define CPUID_HYPERV_ISOLATION_CONFIG 0x4000000C

#define CPUID_HYPERV_MIN 0x40000005
#define CPUID_HYPERV_MAX 0x4000ffff

#define CPUID_SIG_AMD       "AuthenticAMD"
#define CPUID_SIG_INTEL     "GenuineIntel"
#define CPUID_SIG_INTEL_TDX "IntelTDX    "
#define CPUID_SIG_HYPERV    "Microsoft Hv"

/* ecx bit 31: set => hyperpvisor, unset => bare metal */
#define CPUID_FEATURE_HYPERVISOR (1 << 31)

/* Linux include/asm-generic/hyperv-tlfs.h */
#define CPUID_HYPERV_CPU_MANAGEMENT (1 << 12) /* root partition */
#define CPUID_HYPERV_ISOLATION      (1 << 22) /* confidential VM partition */

#define CPUID_HYPERV_ISOLATION_TYPE_MASK 0xf
#define CPUID_HYPERV_ISOLATION_TYPE_SNP 2

#if defined(__x86_64__)

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
cpuid_leaf (uint32_t eax, char *sig, bool swapped)
{
  uint32_t *sig32 = (uint32_t *) sig;

  if (swapped)
    cpuid (&eax, &sig32[0], &sig32[2], &sig32[1]);
  else
    cpuid (&eax, &sig32[0], &sig32[1], &sig32[2]);
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

static bool
cpu_sig_amd_hyperv (void)
{
  uint32_t eax, ebx, ecx, edx;
  char sig[13];
  uint32_t feat;

  feat = cpuid_leaf (CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS, sig, false);

  if (feat < CPUID_HYPERV_MIN ||
      feat > CPUID_HYPERV_MAX)
    return false;

  if (memcmp (sig, CPUID_SIG_HYPERV, sizeof(sig)) != 0)
    return false;

  debug ("CPUID is on hyperv\n");
  eax = CPUID_HYPERV_FEATURES;
  ebx = ecx = edx = 0;

  cpuid(&eax, &ebx, &ecx, &edx);

  if (ebx & CPUID_HYPERV_ISOLATION &&
      !(ebx & CPUID_HYPERV_CPU_MANAGEMENT)) {

    eax = CPUID_HYPERV_ISOLATION_CONFIG;
    ebx = ecx = edx = 0;
    cpuid(&eax, &ebx, &ecx, &edx);

    if ((ebx & CPUID_HYPERV_ISOLATION_TYPE_MASK) ==
	CPUID_HYPERV_ISOLATION_TYPE_SNP) {
      return true;
    }
  }

  return false;
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
   * Note, HyperV/Azure blocks this CPUID leaf from its SEV-SNP
   * guests. We already did an alternative detection mechanism
   * in such VMs, so should not even be running this code.
   */
  if (!(eax & (1 << 1))) {
    debug ("No sev in CPUID, try hyperv CPUID\n");

    if (cpu_sig_amd_hyperv ()) {
      puts ("amd-sev-snp");
      puts ("hyperv-hcl");
    } else {
      debug("No hyperv CPUID\n");
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
  cpuid_leaf (CPUID_INTEL_TDX_ENUMERATION, sig, true);

  if (memcmp (sig, CPUID_SIG_INTEL_TDX, sizeof(sig)) == 0)
    puts ("intel-tdx");
}

static bool
cpu_is_hv (void)
{
  uint32_t eax, ebx, ecx, edx;
  bool is_hv;

  eax = CPUID_PROCESSOR_INFO_AND_FEATURE_BITS;
  ebx = ecx = edx = 0;

  cpuid(&eax, &ebx, &ecx, &edx);

  is_hv = ecx & CPUID_FEATURE_HYPERVISOR;

  debug ("CPUID is hypervisor: %s\n", is_hv ? "yes" : "no");
  return is_hv;
}

static void
cpu_sig (void)
{
  char sig[13];

  /* Skip everything on bare metal */
  if (!cpu_is_hv ())
    return;

  memset (sig, 0, sizeof sig);
  cpuid_leaf (0, sig, true);

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

  cpu_sig ();

  exit(EXIT_SUCCESS);
}
