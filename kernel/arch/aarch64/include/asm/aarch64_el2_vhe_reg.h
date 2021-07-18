/*
 * Copyright (C) 2020 Min Le (lemin9538@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __MINOS_AARCH64_EL2_VHE_REG_H__
#define __MINOS_AARCH64_EL2_VHE_REG_H__

#define ARM64_SCTLR		SCTLR_EL1
#define ARM64_CPTR		CPACR_EL1
#define ARM64_TRFCR		TRFCR_EL1
#define ARM64_TTBR0		TTBR0_EL1
#define ARM64_TTBR1		TTBR1_EL1
#define ARM64_TCR		TCR_EL1
#define ARM64_AFSR0		AFSR0_EL1
#define ARM64_AFSR1		AFSR1_EL1
#define ARM64_ESR		ESR_EL1
#define ARM64_FAR		FAR_EL1
#define ARM64_MAIR		MAIR_EL1
#define ARM64_AMAIR		AMAIR_EL1
#define ARM64_VBAR		VBAR_EL1
#define ARM64_CONTEXTIDR	CONTEXTIDR_EL1
#define ARM64_CNTHCTL		CNTKCTL_EL1
#define ARM64_SPSR		SPSR_EL1
#define ARM64_ELR		ELR_EL1
#define ARM64_TPIDR		TPIDR_EL2
#define ARM64_CNTSIRQ_TVAL	CNTP_TVAL_EL02
#define ARM64_CNTSIRQ_CTL	CNTP_CTL_EL02
#define ARM64_CNTSIRQ_CVAL	CNTP_CVAL_EL02
#define ARM64_CNTSCHED_TVAL	CNTHP_TVAL_EL2
#define ARM64_CNTSCHED_CTL	CNTHP_CTL_EL2
#define ARM64_CNTSCHED_CVAL	CNTHP_CVAL_EL2

#define ARM64_VTCR_EL2		VTCR_EL2
#define ARM64_VTTBR_EL2		VTTBR_EL2
#define ARM64_VMPIDR_EL2	VMPIDR_EL2
#define ARM64_VPIDR_EL2		VPIDR_EL2
#define ARM64_HCR_EL2		HCR_EL2
#define ARM64_DACR32_EL2	DACR32_EL2
#define ARM64_IFSR32_EL2	IFSR32_EL2
#define ARM64_CNTVOFF_EL2	CNTVOFF_EL2

/* the register for guest */
#define ARM64_SCTLR_EL1		SCTLR_EL12
#define ARM64_CPACR_EL1		CPACR_EL12
#define ARM64_ZCR_EL1		ZCR_EL12
#define ARM64_TRFCR_EL1		TRFCR_EL12
#define ARM64_TTBR0_EL1		TTBR0_EL12
#define ARM64_TTBR1_EL1		TTBR1_EL12
#define ARM64_TCR_EL1		TCR_EL12
#define ARM64_AFSR0_EL1		AFSR0_EL12
#define ARM64_AFSR1_EL1		AFSR1_EL12
#define ARM64_ESR_EL1		ESR_EL12
#define ARM64_FAR_EL1		FAR_EL12
#define ARM64_PMSCR_EL1		PMSCR_EL12
#define ARM64_MAIR_EL1		MAIR_EL12
#define ARM64_AMAIR_EL1		AMAIR_EL12
#define ARM64_VBAR_EL1		VBAR_EL12
#define ARM64_CONTEXTIDR_EL1	CONTEXTIDR_EL12
#define ARM64_CNTKCTL_EL1	CNTKCTL_EL12
#define ARM64_SPSR_EL1		SPSR_EL12
#define ARM64_ELR_EL1		ELR_EL12

#define ARM64_SP_EL1		SP_EL1
#define ARM64_ACTLR_EL1		ACTLR_EL1
#define ARM64_TPIDR_EL1		TPIDR_EL1
#define ARM64_CSSELR_EL1	CSSELR_EL1
#define ARM64_PAR_EL1		PAR_EL1

#define ARM64_SP_EL0		SP_EL0
#define ARM64_TPIDR_EL0		TPIDR_EL0
#define ARM64_TPIDRRO_EL0	TPIDRRO_EL0
#define ARM64_CNTV_TVAL_EL0	CNTV_TVAL_EL02
#define ARM64_CNTV_CTL_EL0	CNTV_CTL_EL02
#define ARM64_CNTV_CVAL_EL0	CNTV_CVAL_EL02

#define ARM64_SCTLR_VALUE	0x30c50838
#define ARM64_SPSR_VALUE	0x1c9
#define ARM64_SPSR_KERNEL	AARCH64_SPSR_EL2h
#define ARM64_SPSR_USER		AARCH64_SPSR_EL0t

/* config the TCR_EL1 for kernel
 * mov	x1, #0x0
 * orr	x1, x1, #(0x10 << 16)	// VA 48 bit address range and translation start at lvl0 for kernel
 * orr	x1, x1, #(1 << 24)	// IRGN1 : Normal memory, Inner Write-Back Write-Allocate Cacheable
 * orr	x1, x1, #(1 << 26)	// ORGN1 : Normal memory, Outer Write-Back Write-Allocate Cacheable
 * orr	x1, x1, #(3 << 28)	// Inner shareable
 * orr	x1, x1, #(2 << 30)	// 4KB Granule size
 * orr	x1, x1, #(1 << 37)	// Top bit do not used for address caculate for TTBR0_EL1 (user space).
 * orr	x1, x1, #(0 << 38)	// Top bit used for address caculate for TTBR1_EL1 (kernel space).
 * orr	x1, x1, #0x10		// VA 48 bit address range t0sz
 * orr	x1, x1, #(1 << 8)	// IRGN0 : Normal memory, Inner Write-Back Write-Allocate Cacheable
 * orr	x1, x1, #(1 << 10)	// ORGN0 : Normal memory, Outer Write-Back Write-Allocate Cacheable
 * orr	x1, x1, #(3 << 12)	// Inner shareable
 * ldr	x2, =(5 << 32)		// 256TB IPS
 * orr	x1, x1, x2
 */
#define ARM64_TCR_VALUE		0x25B5103510

#endif
