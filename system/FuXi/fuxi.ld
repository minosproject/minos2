ENTRY(main)
SECTIONS {
	. = 0x400000;

	.text : {
		*(.text)
	}

	.data : {
		*(.data)
	}

	.bss : {
		*(.bss)
	}

	.rodata : {
		KEEP(*(.rodata))
	}
	.rodata.str1.8 : {
		KEEP(*(.rodata.str1.8))
	}
}
