# 源码分析
```
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
    setbuf(stdout, NULL);

    printf("This file demonstrates a simple double-free attack with fastbins.\n");
    printf("Fill up tcache first.\n");

    void *ptrs[8];

    for (int i=0; i<8; i++) {
        ptrs[i] = malloc(8);
    }

    for (int i=0; i<7; i++) {
        free(ptrs[i]);
    }

    printf("Allocating 3 buffers.\n");

    int *a = calloc(1, 8);
    int *b = calloc(1, 8);
    int *c = calloc(1, 8);
    
    printf("1st calloc(1, 8): %p\n", a);
    printf("2nd calloc(1, 8): %p\n", b);
    printf("3rd calloc(1, 8): %p\n", c);

    printf("Freeing the first one...\n");

    free(a);
    
    printf("If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);

    // free(a);
    
    printf("So, instead, we'll free %p.\n", b);

    free(b);

    printf("Now, we can free %p again, since it's not the head of the free list.\n", a);

    free(a);

    printf("Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);

    a = calloc(1, 8);
    b = calloc(1, 8);
    c = calloc(1, 8);

    printf("1st calloc(1, 8): %p\n", a);
    printf("2nd calloc(1, 8): %p\n", b);
    printf("3rd calloc(1, 8): %p\n", c);

    assert(a == c);

}
```
这是第一篇源码分析,所以会从头开始分析,包括但不限于各种宏定义和结构体定义.
## malloc填满tcache

既然要分析源码,那先把源码贴一下:
```
void * __libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;
  _Static_assert (PTRDIFF_MAX <= SIZE_MAX / 2,"PTRDIFF_MAX is not more than half of SIZE_MAX");

  if (!__malloc_initialized)
    ptmalloc_init ();

#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  
  size_t tbytes;
  if (!checked_request2size (bytes, &tbytes))
    {
      __set_errno (ENOMEM);
      return NULL;
    }

  size_t tc_idx = csize2tidx (tbytes);
  MAYBE_INIT_TCACHE ();
  DIAG_PUSH_NEEDS_COMMENT;

  if (tc_idx < mp_.tcache_bins && tcache && tcache->counts[tc_idx] > 0)
    {
      victim = tcache_get (tc_idx);
      return tag_new_usable (victim);
    }

  DIAG_POP_NEEDS_COMMENT;
#endif

  if (SINGLE_THREAD_P)
    {
      victim = tag_new_usable (_int_malloc (&main_arena, bytes));
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
        &main_arena == arena_for_chunk (mem2chunk (victim)));
      return victim;
    }

  arena_get (ar_ptr, bytes);
  
  victim = _int_malloc (ar_ptr, bytes);

  /* Retry with another arena only if we were able to find a usable arena
     before.  */

  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);
   victim = tag_new_usable (victim);

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||ar_ptr ==arena_for_chunk (mem2chunk (victim)));
  return victim;
}
libc_hidden_def (__libc_malloc)
```

### ptmalloc初始化(arena和fastbin初始化完成)

首先为进行fastbin攻击,
先把tcache填满,所以先来分析该部分的源码并进行调试.
![[QQ20251225-174343 1.png]]
```
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;
  
  _Static_assert (PTRDIFF_MAX <= SIZE_MAX / 2,

  if (!__malloc_initialized)
    ptmalloc_init ();
```
这里定义了一个arena指针和一个叫victim的空指针,之后是一个断言(不知道在检测什么=,=),之后是一个简单的malloc初始化判断,然后就进入了`ptmalloc_init(void)`函数(glibc-2.35/malloc/arena.c:315),以进行初始化.
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_dup/图/QQ20251225-115219.png]]
```
/*ptmalloc_init ()*/

if (__malloc_initialized)
    return;
  __malloc_initialized = true;
#if USE_TCACHE
  tcache_key_initialize ();
#endif
```
一个arena的初始化判断.
之后是tcache_key变量的初始化.
```
static void
tcache_key_initialize(void)
{
  if (__getrandom(&tcache_key, sizeof(tcache_key), GRND_NONBLOCK) != sizeof(tcache_key))
  {
    tcache_key = random_bits();
#if __WORDSIZE == 64
    tcache_key = (tcache_key << 32) | random_bits();
#endif
  }
}
```
这里先向tcache_key取一个`_int64`大小的随机数(8bytes),再用`random_bits()`取一个随机数,具体区别直接问了ai,但也看不懂...
	在 glibc 中，`random_bits` 代表了**从高质量熵源到用户可用数值之间的“精炼”过程**。它确保了随机数既能满足性能要求，又能最大限度地利用从内核获取的每一位熵。
总之,这里给tcache_key变量取了一个8bytes随机数.

```
/*ptmalloc_init ()*/

#ifdef USE_MTAG
  if ((TUNABLE_GET_FULL (glibc, mem, tagging, int32_t, NULL) & 1) != 0)
    {
      /* If the tunable says that we should be using tagged memory
   and that morecore does not support tagged regions, then
   disable it.  */
      if (__MTAG_SBRK_UNTAGGED)
  __always_fail_morecore = true;
      mtag_enabled = true;
      mtag_mmap_flags = __MTAG_MMAP_FLAGS;
    }
#endif

#if defined SHARED && IS_IN (libc)
  /* In case this libc copy is in a non-default namespace, never use
     brk.  Likewise if dlopened from statically linked program.  The
     generic sbrk implementation also enforces this, but it is not
     used on Hurd.  */
  if (!__libc_initial)
    __always_fail_morecore = true;
#endif

  thread_arena = &main_arena;
  malloc_init_state (&main_arena);
```
这里的第一个#if跳过了,第二个运行了,但if判断为0,所以没有进行赋值(不要在意它是用来干啥的,我也不知道=,=),之后设置当前线程arena为main_arena的地址,并用`malloc_init_state()`初始化main_arena,具体初始化内容如下:

|**初始化对象**|**描述**|
|---|---|
|**Bins (bins)**|设置 126 个 Bins 的初始指针，形成闭环。|
|**Top Chunk (top)**|初始化 `top` 指针。Top Chunk 是堆顶部的巨大空闲块，当所有 Bin 都找不到合适的内存时，会从这里切割。|
|**Fastbins**|清空快速分配缓冲区（用于小内存的高速分配）。|
|**Flags**|设置标志位，例如 `have_fastchunks`（标记当前是否有快速块可用）。|

```
malloc_init_state (mstate av)
{
  int i;
  mbinptr bin;
  
  /* Establish circular links for normal bins */
  
  for (i = 1; i < NBINS; ++i)
    {
      bin = bin_at (av, i);
      bin->fd = bin->bk = bin;
    }
    /*初始化bin指针,同时因为fastbins的懒加载特性,相当于设置完arena指针就已经初始化完成*/
#if MORECORE_CONTIGUOUS
  if (av != &main_arena)
#endif

  set_noncontiguous (av);
  /*设置flags标志位*/
  if (av == &main_arena)
    set_max_fast (DEFAULT_MXFAST);
    /*设置global_max_fast变量*/
  atomic_store_relaxed (&av->have_fastchunks, false);
  /*设置have_fastchunks标志位*/
  av->top = initial_top (av);
  /*初始化top chunk*/
}
```

结束后,回到`ptmalloc_init ()`
```
/*ptmalloc_init ()*/

#if HAVE_TUNABLES
  TUNABLE_GET (top_pad, size_t, TUNABLE_CALLBACK (set_top_pad));
  TUNABLE_GET (perturb, int32_t, TUNABLE_CALLBACK (set_perturb_byte));
  TUNABLE_GET (mmap_threshold, size_t, TUNABLE_CALLBACK (set_mmap_threshold));
  TUNABLE_GET (trim_threshold, size_t, TUNABLE_CALLBACK (set_trim_threshold));
  TUNABLE_GET (mmap_max, int32_t, TUNABLE_CALLBACK (set_mmaps_max));
  TUNABLE_GET (arena_max, size_t, TUNABLE_CALLBACK (set_arena_max));
  TUNABLE_GET (arena_test, size_t, TUNABLE_CALLBACK (set_arena_test));
  
# if USE_TCACHE
  TUNABLE_GET (tcache_max, size_t, TUNABLE_CALLBACK (set_tcache_max));
  TUNABLE_GET (tcache_count, size_t, TUNABLE_CALLBACK (set_tcache_count));
  TUNABLE_GET (tcache_unsorted_limit, size_t,
         TUNABLE_CALLBACK (set_tcache_unsorted_limit));
# endif
  TUNABLE_GET (mxfast, size_t, TUNABLE_CALLBACK (set_mxfast));
  TUNABLE_GET (hugetlb, size_t, TUNABLE_CALLBACK (set_hugetlb));
  if (mp_.hp_pagesize > 0)
    /* Force mmap for main arena instead of sbrk, so hugepages are explicitly
       used.  */
    /*处理大内存页时关闭sbrk,强制使用mmap*/
    __always_fail_morecore = true;
#else
......
```

第一个在设置HAVE_TUNABLES时运行,第二在使用tcache时运行,都用TUNABLE_GET宏从**系统配置或环境变量**中读取一系列**参数**,一下对这些参数作一些解释:

|**分类**|**参数名称 (Tunable)**|**关键功能描述**|**性能影响与目的**|
|---|---|---|---|
|**线程缓存 (TCACHE)**|**`tcache_max`**|线程私有缓存的最大块尺寸|增加可提升多线程小对象分配速度，减少锁竞争。|
||**`tcache_count`**|每个线程缓存块的数量上限|调大可提速，但会增加线程私有内存的碎片化空间。|
||**`tcache_unsorted_limit`**|从未排序链表填充缓存的限制|平衡复杂分配场景下的扫描耗时。|
|**快速通道 (Fastbins)**|**`mxfast`**|快速分配池（Fastbins）的最大阈值|针对极小块的 LIFO 分配，速度极快但不易合并内存。|
|**并发控制 (Arena)**|**`arena_max`**|允许创建的最大分配区（Arena）数量|限制此值可显著降低多线程程序的内存膨胀（RSS）。|
||**`arena_test`**|触发创建新分配区的竞争阈值|在 CPU 核心数和内存压力之间寻找平衡。|
|**大对象处理 (Mmap)**|**`mmap_threshold`**|切换到 `mmap` 直接分配的字节阈值|大于此值不从堆分配，防止长期持有大块内存导致空闲内存无法归还。|
||**`mmap_max`**|允许同时存在的 `mmap` 映射最大数量|防止消耗过多的系统内核映射资源。|
||**`hugetlb`**|是否使用大页内存（Huge Pages）|**降低 TLB Miss**，显著提升超大数据集的处理效率。|
|**堆管理 (Heap)**|**`top_pad`**|扩展堆（Wilderness）时的填充大小|减少向内核请求内存（sbrk）的系统调用次数。|
||**`trim_threshold`**|触发内存归还给 OS 的空闲阈值|控制 glibc 释放内存的“积极程度”。|
|**调试与安全**|**`perturb`**|内存填充模式（垃圾值填充）|开启后可帮助检测 **Use-after-free** 或未初始化使用的漏洞。|

*这部分不看也行.*
不过要注意的是,最后一个if对大内存页的处理.到这里,ptmalloc的初始化就结束了.

### tcache初始化

下面,我们回到`__libc_malloc (size_t bytes)`.
```
/*__libc_malloc (size_t bytes)*/

#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  
  if (!checked_request2size (bytes, &tbytes))
    {
      __set_errno (ENOMEM);
      return NULL;
    }
    
  size_t tc_idx = csize2tidx (tbytes);
  MAYBE_INIT_TCACHE ();
  DIAG_PUSH_NEEDS_COMMENT;
  
  if (tc_idx < mp_.tcache_bin && tcache && tcache->counts[tc_idx] > 0)
    {
      victim = tcache_get (tc_idx);
      return tag_new_usable (victim);
    }

  DIAG_POP_NEEDS_COMMENT;
#endif
```
这里先来解释一下非常常用的一个宏:
`size_t`:`typedef __SIZE_TYPE__ size_t`,`__SIZE_TYPE__` 是 **编译器（GCC / Clang）内置的宏类型**,其大小与架构关系如下:

| **架构 (Arch)** | **`__SIZE_TYPE__ `实际类型** | **字节大小 (Bytes)** |
| ------------- | ------------------------ | ---------------- |
| **x86_64**    | `unsigned long`          | 8 字节             |
| **i386**      | `unsigned int`           | 4 字节             |
| **ARM64**     | `unsigned long`          | 8 字节             |
| **ARM32**     | `unsigned int`           | 4 字节             |

定义了tbytes变量后,在if的条件中调用了`checked_request2size (bytes, &tbytes)`函数,同时设置了error.

下面,进入`checked_request2size (bytes, &tbytes)`函数
```
checked_request2size (size_t req, size_t *sz) __nonnull (1)
{
  if (__glibc_unlikely (req > PTRDIFF_MAX))
    return false;
  /* When using tagged memory, we cannot share the end of the user
     block with the header form the next chunk, so ensure that we
     allocate blocks that are rounded up to the granule size.  Take
     care not to overflow from close to MAX_SIZE_T to a small
     number.  Ideally, this would be part of request2size(), but that
     must be a macro that produces a compile time constant if passed
     a constant literal.  */

  if (__glibc_unlikely (mtag_enabled))
    {
      /* Ensure this is not evaluated if !mtag_enabled, see gcc PR 99551.  */
      asm ("");
      req = (req + (__MTAG_GRANULE_SIZE - 1)) & ~ (size_t)(__MTAG_GRANULE_SIZE - 1);
    }
    
  *sz = request2size (req);
  
  return true;
}
```

第一个if中的__glibc_unlikely()函数是为了节省运行资源,而对发生可能行小的分支进行一定处理,从而提高性能(具体怎么处理我也不知道喵).这个if对req(即request,需求大小)做了判断,若大于`PTRDIFF_MAX`则直接报错(这里`PTRDIFF_MAX`的大小很大很大,感兴趣可以去翻翻源码).下一个if的`mtag_enable`宏(标志是否启用内存标签)默认是false所以跳过.
最后,向sz指针指向的变量(传入的tbytes)写入`2*size_t`bytes(一般是8bytes)对齐过的size大小.
这里的request2size宏同样很重要,下面我们来具体分析一下:
```
#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
```
这里用了一个三元运算符,判断`req+0x8+0xf`是否小于MINSIZE(0x10)小于则直接返回MINSIZE(0x20),大于则进行0x10bytes对齐处理.(具体原理自行搜索).

下面.把得到的tbytes用如下宏转化成索引(同样,不解释具体实现).
	e.g.`0x10->[0] , 0x20->[1]`
```
/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) \ MALLOC_ALIGNMENT)
```

看下一个宏的定义:
```
# define MAYBE_INIT_TCACHE() \
  if (__glibc_unlikely (tcache == NULL)) \
    tcache_init();
```
一个简单的tcache初始化判断,还用了`__glibc_unlikely()`以减少资源消耗.下面,步入`tcache_init`函数,来看看tcache如何进行初始化.
```
static void
tcache_init(void)
{
 mstate ar_ptr;  /*先定义了一个mstate的结构体指针,即malloc_state结构体*/
  void *victim = 0;  /*一个空指针*/
  const size_t bytes = sizeof (tcache_perthread_struct);
  /*取要申请的tcache结构体的大小,准备在堆上申请tcache(堆的最低地址大部分情况下,就是tcache)*/

  if (tcache_shutting_down)
    return;
/*tcache_shutting_down 是一个布尔标志位（通常也是一个 `static` 的内部变量），用于标记当前线程或进程是否正在进入销毁/退出流程.*/
  arena_get (ar_ptr, bytes);    /*给arena上锁(保证多线程安全),并将arena地址写给ar_ptr*/
  victim = _int_malloc (ar_ptr, bytes);
  /*申请0x280的chunk*/
  if (!victim && ar_ptr != NULL)
    {
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  /* In a low memory situation, we may not be able to allocate memory
     - in which case, we just keep trying later.  However, we
     typically do this very early, so either there is sufficient
     memory, or there isn't enough memory to do non-trivial
     allocations anyway.  */

  if (victim)
    {
      tcache = (tcache_perthread_struct *) victim;
      memset (tcache, 0, sizeof (tcache_perthread_struct));
    }
}
```

下面先来看一下tcache的结构体
```
typedef struct tcache_perthread_struct
{
  uint16_t counts[TCACHE_MAX_BINS];
  /*注:这里的数量是目前在tcache中的chunk数量*/
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  uintptr_t key;
} tcache_entry;
```
先定义了uint16类型(无符号16bits整型)的64个元素的数组(`TCACHE_MAX_BINS`宏大小为64).之后是tcache_entry结构体的结构体指针,该结构体中先是一个next指针,用以构成链表,之后,是一个uintptr_t(`typedef unsigned __int64 uintptr_t`)类型变量用以堆tcache的double free攻击加以限制(key校验存在的情况下,想进行double free,需要泄露key,且能对key位置进行覆盖.),这个结构体大小为(`2*64+8*64=128+512=0x80+0x200`)0x280bytes,所以0x10对齐后,可以看到在堆底申请到了0x290大小的chunk.
![[notes/pwn/堆利用/堆机制/图/QQ20251226-165248.png]]
#### `_int_malloc (mstate av, size_t bytes)`部分分析
下面,步入` _int_malloc (ar_ptr, bytes)`看看如何进行chunk申请(这一部分非常重要,可以说是堆利用的重中之重,这里只分析在调用的部分,不做全部分析).
```
static void *
_int_malloc (mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;               /* normalized request size */
  unsigned int idx;                 /* associated bin index */
  mbinptr bin;                      /* associated bin */

  mchunkptr victim;                 /* inspected/selected chunk */
  INTERNAL_SIZE_T size;             /* its size */
  int victim_index;                 /* its bin index */

  mchunkptr remainder;              /* remainder from a split */
  unsigned long remainder_size;     /* its size */

  unsigned int block;               /* bit map traverser */
  unsigned int bit;                 /* bit map traverser */
  unsigned int map;                 /* current word of binmap */

  mchunkptr fwd;                    /* misc temp for linking */
  mchunkptr bck;                    /* misc temp for linking */
  
#if USE_TCACHE
  size_t tcache_unsorted_count;     /* count of unsorted chunks processed */
#endif
```
定义一些变量,这些变量后面会经常用,不用全记住,但请先看一遍.
```
/*_int_malloc (mstate av, size_t bytes)*/
  if (!checked_request2size (bytes, &nb))
    {
      __set_errno (ENOMEM);
      return NULL;
    }
```
对size的对齐与报错处理.

```
/*_int_malloc (mstate av, size_t bytes)*/
  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  */
  if (__glibc_unlikely (av == NULL))
    {
      void *p = sysmalloc (nb, av);
      if (p != NULL)
        alloc_perturb (p, bytes);
      return p;
    }
```
处理arena指针为空的情况:
- 正常情况下：
    - 单线程 → `av = &main_arena`
    - 多线程 → 从 arena 链表里选一个
- 现在 **`av == NULL`**，说明：
    - 没有可用 arena
    - 可能：
        - arena 初始化失败
        - arena 数量达到上限
        - 内部选择失败（极端情况）
这里,不会进入,略过.
```
/*_int_malloc (mstate av, size_t bytes)*/
#define REMOVE_FB(fb, victim, pp)     \
  do              \
    {             \
      victim = pp;          \
      if (victim == NULL)       \
  break;            \
      pp = REVEAL_PTR (victim->fd);                                     \
      if (__glibc_unlikely (pp != NULL && misaligned_chunk (pp)))       \
  malloc_printerr ("malloc(): unaligned fastbin chunk detected"); \
    }             \
  while ((pp = catomic_compare_and_exchange_val_acq (fb, pp, victim)) \
   != victim);          \
```
宏定义,忽略.

```
/*_int_malloc (mstate av, size_t bytes)*/
 if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
    ......
```
步入`get_max_fast ()`
```
get_max_fast (void)
{
  /* Tell the GCC optimizers that global_max_fast is never larger
     than MAX_FAST_SIZE.  This avoids out-of-bounds array accesses in
     _int_malloc after constant propagation of the size parameter.
     (The code never executes because malloc preserves the
     global_max_fast invariant, but the optimizers may not recognize
     this.)  */
     
  if (global_max_fast > MAX_FAST_SIZE)
    __builtin_unreachable ();
    /*帮助编译器做更激进的优化，并消除“永远走不到的分支”.*/
  return global_max_fast;  /*0x80*/
}
```
所以这一快if也是不会进入的,忽略,后面再做解释.

下面,申请的部分,直接在源码里解释.
```
/*_int_malloc (mstate av, size_t bytes)*/
/*
     If a small request, check regular bin.  Since these "smallbins"
     hold one size each, no searching within bins is necessary.
     (For a large request, we need to wait until unsorted chunks are
     processed to find best fit. But for small ones, fits are exact
     anyway, so we can check now, which is faster.)
   */
  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb); /*对大小进行索引处理*/
      bin = bin_at (av, idx);  /*在arena中寻找该索引处第一个chunk的地址*/
      /*
      #define smallbin_index(sz) \
  ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3))\
   + SMALLBIN_CORRECTION)
     
     #define bin_at(m, i) \
  (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))           \
             - offsetof (struct malloc_chunk, fd))
      */
		/*判断该bins处是否有chunk,回忆以下arena.bins[]中指针初始化操作:
	for (i = 1; i < NBINS; ++i)
	    {
	      bin = bin_at (av, i);
	      bin->fd = bin->bk = bin;
	    }
		所以,不会进入,跳过以下部分*/
      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;

          if (av != &main_arena)
	    set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
 /*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
   */
/*这里注意,对largebins的判断是通过排除fastbins和smallbins的范围来实现的.*/
  else
    {
      idx = largebin_index (nb);
      if (atomic_load_relaxed (&av->have_fastchunks))
        malloc_consolidate (av);
    }
```
对上面的if判断,再做一下解释,可以看到ptmalloc结束以后,内存中arena的bins部分中的值,具体再理解一下bins的初始化.
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_dup/图/QQ20251227-152038.png]]

由于判断smallbins为空,所以准备进入unsortedbin寻找,下面是准备中对tcache的处理.
```
/*_int_malloc (mstate av, size_t bytes)*/
#if USE_TCACHE
  INTERNAL_SIZE_T tcache_nb = 0;
  /*初始化tcache_nb为0(这里大小为size_t)*/
  size_t tc_idx = csize2tidx (nb);
  /*把needbytes(nb)转化为索引值*/
  
  /*由于tcache没有初始化,这里不会进入*/
  if (tcache && tc_idx < mp_.tcache_bins)
    tcache_nb = nb;
  int return_cached = 0;
  /*标志位,标志是否从tcache直接返回chunk,这里表示false.*/
  tcache_unsorted_count = 0;
  /*限制一次malloc中,从unsortbin中移入tcache的chunk数量,这里初始化为0.*/
#endif

  for (;; )
    {
      int iters = 0;
      /*初始化一个unsortedbin查找次数计数器,这里初始化为0*/
      
      /*unsouted判断为空,不进入.*/
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
        ......
        
        
        #if USE_TCACHE
      /* If all the small chunks we found ended up cached, return one now.  */
      /*由于上面的设置,这里不进入.*/
      if (return_cached)
  {
    return tcache_get (tc_idx);
  }
#endif
/*_int_malloc (mstate av, size_t bytes)*/
/*这里在smallbin中,不会进入.*/
      if (!in_smallbin_range (nb))
        {
        ......
        }
              /*
         Search for a chunk by scanning bins, starting with next largest
         bin. This search is strictly by best-fit; i.e., the smallest
         (with ties going to approximately the least recently used) chunk
         that fits is selected.

         The bitmap avoids needing to check that most blocks are nonempty.
         The particular case of skipping all bins during warm-up phases
         when no chunks have been returned yet is faster than it might look.
       */
```
以上是largebin的搜索过程,后续解释.

```
/*_int_malloc (mstate av, size_t bytes)*/
/*以下是简单分配失败后,用arena中的binmap来对所有free的chunk进行快速搜索*/
  ++idx;
  bin = bin_at (av, idx);
  block = idx2block (idx);
  map = av->binmap[block];
  bit = idx2bit (idx);
```
这段代码通常出现在一个循环中，用于寻找比请求尺寸更大的空闲内存块：
1. **`++idx;`**
    - **含义**：将索引移动到下一个 Bin。
    - **背景**：如果你请求的大小对应第 $N$ 个 Bin，但该 Bin 是空的，程序就会查看第 $N+1$ 个 Bin。

2. **`bin = bin_at (av, idx);`**
    - **含义**：获取当前索引对应的 Bin 结构体的指针。
    - **背景**：`av` 指向 `malloc_state`（即当前的 Arena）。这个宏根据索引计算出对应的内存池链表头部。

3. **`block = idx2block (idx);`**
    - **含义**：计算当前 Bin 属于位图中的哪一个“块（Block）”。
    - **背景**：`binmap` 是一个数组（通常是 `unsigned int`），为了提高效率，每 32 个 Bin 被归类为一个 Block。

4. **`map = av->binmap[block];`**
    - **含义**：读取该块的位图数值。
    - **背景**：如果 `map` 的值为 `0`，说明这连续的 32 个 Bin 全是空的，`malloc` 可以直接跳过这整个 Block，而不需要一个一个检查。

5. **`bit = idx2bit (idx);`**
    - **含义**：计算当前 Bin 在该 `map`（32位数值）中对应的具体位（Bit）。
    - **背景**：通过位运算（如 `map & bit`），可以瞬间判断该特定的 Bin 是否包含空闲 chunk。
通过调试,看一下几个重要变量:
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_dup/图/QQ20251227-173503.png]]
```
/*_int_malloc (mstate av, size_t bytes)*/
 for (;; )
        {
          /* Skip rest of block if there are no more set bits in this block.  */
          if (bit > map || bit == 0)
            {
              do
                {
                  if (++block >= BINMAPSIZE) /* out of bins */
                  /*BINMAPSIZE为4*/
                    goto use_top;
                }
              while ((map = av->binmap[block]) == 0);
              /*之前初始化为0,继续循环,直到满足if条件跳到use_top*/
              
              bin = bin_at (av, (block << BINMAPSHIFT));
              bit = 1;
            }
            ......
          }
```

下面看`use_top`.

```
/*_int_malloc (mstate av, size_t bytes)*/
use_top:
      /*
         If large enough, split off the chunk bordering the end of memory
         (held in av->top). Note that this is in accord with the best-fit
         search rule.  In effect, av->top is treated as larger (and thus
         less well fitting) than any other available chunk since it can
         be extended to be as large as necessary (up to system
         limitations).

         We require that av->top always exists (i.e., has size >=
         MINSIZE) after initialization, so if it would otherwise be
         exhausted by current request, it is replenished. (The main
         reason for ensuring it exists is that we may need MINSIZE space
         to put in fenceposts in sysmalloc.)
       */

      victim = av->top;  /*从arena取top chunk地址*/
      size = chunksize (victim);  /*取top chunk的size*/
      
/*对top chunk的大小检验,让直接覆盖top chunk的size进行任意地址分配成为过去式*/
      if (__glibc_unlikely (size > av->system_mem))
        malloc_printerr ("malloc(): corrupted top size");
```
这里由于这里从未申请任何chunk,所以,堆区没初始化,所以根本没有top chunk.
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_dup/图/QQ20251227-180244.png]]
```
/*_int_malloc (mstate av, size_t bytes)*/
      if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
        {
          remainder_size = size - nb;
          remainder = chunk_at_offset (victim, nb);
          av->top = remainder;
          set_head (victim, nb | PREV_INUSE |
                    (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head (remainder, remainder_size | PREV_INUSE);

          check_malloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }

      /* When we are using atomic ops to free fast chunks we can get
         here for all block sizes.  */
/*这里因为没free过fast chunk,标志位没有被设置不进入*/
      else if (atomic_load_relaxed (&av->have_fastchunks))  
	      /*atomic_load_relaxed()能以高性能方式从指定地址获取变量值.*/
        {
          malloc_consolidate (av);
          /* restore original bin index */

          if (in_smallbin_range (nb))
            idx = smallbin_index (nb);

          else
            idx = largebin_index (nb);
        }

      /*Otherwise, relay to handle system-dependent cases */
```
 
这里先解释一下`sysmalloc`函数,`sysmalloc` 的内部逻辑非常复杂，但大致遵循以下逻辑：
1. **检查边界条件**：确认是否需要初始化堆（如果是程序第一次分配内存）。
2. **决定分配策略**：判断请求大小是否超过 `mmap` 阈值。
3. **尝试扩展**：
    - 如果是主分配区（Main Arena），尝试 `sbrk`。
    - 如果 `sbrk` 失败，或者是在非主分配区，尝试 `mmap`。
4. **前向合并**：如果新申请的内存与旧的 Top Chunk 物理上连续，`sysmalloc` 会将它们合并成一个新的、更大的 Top Chunk。(这里就会在这创建top chunk)
5. **容错处理**：如果系统内存彻底耗尽（`sbrk` 和 `mmap` 都失败），`sysmalloc` 返回 `NULL`，最终导致 `malloc` 返回 `NULL`。
```
      else
        {
          void *p = sysmalloc (nb, av);
          if (p != NULL)
            alloc_perturb (p, bytes);
            /*p指针位置填充bytes长度随机数据,由perturb_byte标志位控制,这里没开启,不会填充*/
          return p;
          /*返回p指针.*/
        }
    }
```
到这,`_int_malloc`就执行完了.

---
现在,回到`tcache_init(void)`函数.

下一个if的进入条件为victim全0(未malloc成功)且ar_ptr指针不为空,进入后调用`arena_get_retry (ar_ptr, bytes)`尝试找到其他arena并上锁,且再次尝试malloc.

```
/*tcache_init(void)*/
  if (!victim && ar_ptr != NULL)
    {
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }
```
下面步入`arena_get_retry (ar_ptr, bytes)`.
```
/* If we don't have the main arena, then maybe the failure is due to running
   out of mmapped areas, so we can try allocating on the main arena.
   Otherwise, it is likely that sbrk() has failed and there is still a chance
   to mmap(), so try one of the other arenas.  */
static mstate
arena_get_retry (mstate ar_ptr, size_t bytes)
{
  LIBC_PROBE (memory_arena_retry, 2, bytes, ar_ptr);
  /*在日志中写入多线程arena竞争*/
  if (ar_ptr != &main_arena)
    {
      __libc_lock_unlock (ar_ptr->mutex);
      ar_ptr = &main_arena;
      __libc_lock_lock (ar_ptr->mutex);
    }
    /*若之前get到的arena不是main_arena,这里直接将其地址赋给ar_ptr,并解锁之前get到的arena*/
    /*注:之前的arena_get()函数直接从thread_arena对ar_ptr进行赋值*/
  else
    {
      __libc_lock_unlock (ar_ptr->mutex);
      ar_ptr = arena_get2 (bytes, ar_ptr);
    }
    /*这里直接调用了arena_get2进行赋值,去找一个可用arena*/
  return ar_ptr;
}
```
由于arena_get2的操作只是为了处理多线程arena共用问题,在此不步入和解释.
下面回到`tcache_init(void)`
```
/*tcache_init(void)*/
 if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);
/*arena解锁*/
  /* In a low memory situation, we may not be able to allocate memory
     - in which case, we just keep trying later.  However, we
     typically do this very early, so either there is sufficient
     memory, or there isn't enough memory to do non-trivial
     allocations anyway.  */
  if (victim)
    {
      tcache = (tcache_perthread_struct *) victim;
      memset (tcache, 0, sizeof (tcache_perthread_struct));
      tcache处内存初始化为\x00
    }
```
至此,tcache初始化结束,也完成了关于堆的所有初始化.

### 申请chunk
接下来,回到`glibc-2.35/malloc/malloc.c:3309`
```
/*__libc_malloc (size_t bytes)*/
  DIAG_PUSH_NEEDS_COMMENT;   /*是用来“控制编译器警告”的宏,与堆分配机制无关*/
  if (tc_idx < mp_.tcache_bins
      && tcache
      && tcache->counts[tc_idx] > 0)
    {
      victim = tcache_get (tc_idx);
      return tag_new_usable (victim);
    }
  DIAG_POP_NEEDS_COMMENT;
```
因为这里是第一次malloc,所以不会进入这个if,留着下次解释.
	*这里的进入条件是:申请的索引大小合适(即申请的大小在tcache范围内),tcache存在,tcache中有剩余chunk.

```
/*__libc_malloc (size_t bytes)*/
  if (SINGLE_THREAD_P)  /*用来判断“当前进程是否只有一个线程”的宏.*/
    {
      victim = tag_new_usable (_int_malloc (&main_arena, bytes));
      /*申请chunk,并打内存标签(这里一般是不运行的)*/
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
        &main_arena == arena_for_chunk (mem2chunk (victim)));
        /*一个断言判断,检测申请的chunk是否为空,chunk是否是被mmap申请的,是否是main arena处申请到的chunk*/
      return victim;
      /*结束函数,返回victim(申请到的chunk)的地址*/
    }
```
一般内存标签都是不开启的,所以这里不会进入下面`tag_new_usable (void *ptr)`的主逻辑(if中的内容),直接通过`_int_malloc()`函数申请chunk后,直接返回victim(申请chunk的地址)值.
```
/*__libc_malloc (size_t bytes)*/
static __always_inline void *
tag_new_usable (void *ptr)
{
  if (__glibc_unlikely (mtag_enabled) && ptr)
    {
      mchunkptr cp = mem2chunk(ptr);
      ptr = __libc_mtag_tag_region (__libc_mtag_new_tag (ptr), memsize (cp));
    }
  return ptr;
}
```

下面是处理多线程情况(多个arena,需要lock arena)的情况下,才会调用的部分,所以这里不具体解释
```
/*__libc_malloc (size_t bytes)*/
 arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);
  victim = tag_new_usable (victim);

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
  return victim;
}
libc_hidden_def (__libc_malloc)
/*基本每个函数调用后都有,用于隐藏函数名(隐藏符号)*/
```


下面再次步入`_int_malloc (&main_arena, bytes)`,之前解释过的部分不再解释,直接看fastbin的运行逻辑.
```
`_int_malloc (&main_arena, bytes)`
  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);  /*needbytes转化成index*/
      mfastbinptr *fb = &fastbin (av, idx);  /*取对应大小的fastbinsY[]数组指针的值*/
      mchunkptr pp;
      victim = *fb;
/*这里由于fastbin中啥也没有,取victim为\x00,跳过下一个结构*/
      if (victim != NULL)
  {
  ......
  }
```

下面的逻辑与上面差不多,会跳过smallbins,largebins和unsortedbins的检测,唯一不同的是下面的判断程序:
```
_int_malloc (&main_arena, bytes)
if (!in_smallbin_range (nb))
        {
          bin = bin_at (av, idx);

          /* skip scan if empty or largest chunk is too small */
          if ((victim = first (bin)) != bin
        && (unsigned long) chunksize_nomask (victim)
          >= (unsigned long) (nb))
            {
            ......
            }
```
这里由于nb不在smallbins中,会进入第一个if,但是largebins为空,所以跳过下一个大的if,进入binmap的查找逻辑后,直接跳到`use_top:`部分,从top chunk切.
```
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
        {
          remainder_size = size - nb;
          remainder = chunk_at_offset (victim, nb);
          av->top = remainder;
          set_head (victim, nb | PREV_INUSE |
                    (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head (remainder, remainder_size | PREV_INUSE);

          check_malloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
```

之后的7次malloc与以上运行逻辑完全一样,不再解释.

---
### 七次free

```
void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  if (mem == 0)                              /* free(0) has no effect */
    return;

  /* Quickly check that the freed pointer matches the tag for the memory.
     This gives a useful double-free detection.  */
     /*内存页标记开启才进入*/
  if (__glibc_unlikely (mtag_enabled))
    *(volatile char *)mem;
/*保存之前函数调用的返回值*/
  int err = errno;
  /*user data地址转到chunk头地址*/
    p = mem2chunk (mem);
    /*由于堆利用不涉及mmap的大chunk,略过.*/
    if (chunk_is_mmapped (p))                       /* release mmapped memory. */
    {
    ......
    }
```
下面是对errno全局变量的解释:
`errno` 是一个定义在 `<errno.h>` 头文件中的**全局变量**（在多线程环境下是线程局部变量）。
当一个系统调用（比如打开文件 `fopen`）或库函数出错时，它会把一个特定的**错误代码**存入 `errno`。
	- **0**：表示没有错误。
	- **非 0**：表示发生了特定错误（例如 `ENOENT` 代表文件不存在，`EACCES` 代表权限不足）。

```
  else
    {
    /*tcache'初始化的检测*/
      MAYBE_INIT_TCACHE ();

      /* Mark the chunk as belonging to the library again.  */
      (void)tag_region (chunk2mem (p), memsize (p));
/*寻找该chunk的arena*/
      ar_ptr = arena_for_chunk (p);
      /*调用_int_free,free的主逻辑在这里.*/
      _int_free (ar_ptr, p, 0);
    }
/*设置errno全局变量为之前保存的err*/
  __set_errno (err);
}
libc_hidden_def (__libc_free)
```

下面进入_int_free函数分析:
```
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr *fb;             /* associated fastbin */
  mchunkptr nextchunk;         /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int nextinuse;               /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr bck;               /* misc temp for linking */
  mchunkptr fwd;               /* misc temp for linking */
/*一些变量的初始化.*/

/*取chunk的size*/
  size = chunksize (p);

  /* Little security check which won't hurt performance: the
     allocator never wrapps around at the end of the address space.
     Therefore we can exclude some size values which might appear
     here by accident or by "design" from some intruder.  */
     
     /*检测size是否太大,检测chunk地址是否0x10对齐*/
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    malloc_printerr ("free(): invalid pointer");
    
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT.  */
     /*检测chunk大小是否小于0x10,内存大小是否0x10对齐*/
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    malloc_printerr ("free(): invalid size");

/*检测操作,如果开启MALLOC_DEBUG则不进行检测*/
  check_inuse_chunk(av, p);
```
这里进入该宏指向的函数
```
static void
do_check_inuse_chunk (mstate av, mchunkptr p)
{
  mchunkptr next;

  do_check_chunk (av, p);

  if (chunk_is_mmapped (p))
    return; /* mmapped chunks have no next/prev */

  /* Check whether it claims to be in use ... */
  /*查看这个chunk物理相邻的下一个chunk的p位是否为1,为0则报错*/
  assert (inuse (p));

  next = next_chunk (p);

  /* ... and is surrounded by OK chunks.
     Since more things can be checked with free chunks than inuse ones,
     if an inuse chunk borders them and debug is on, it's worth doing them.
   */
   /*检测物理相邻上一个chunk是否被free*/
  if (!prev_inuse (p))
    {
      /* Note that we cannot even look at prev unless it is not inuse */
      mchunkptr prv = prev_chunk (p);
      /*检测物理相邻的前一个chunk,的size大小*/
      assert (next_chunk (prv) == p);
      
      do_check_free_chunk (av, prv);
    }
/*如果next chunk是top chunk,则检测它的p标志位(防止被向后合并),和size位最小大小*/
  if (next == av->top)
    {
      assert (prev_inuse (next));
      assert (chunksize (next) >= MINSIZE);
    }
    /*检测物理相邻下一个chunk的下一个chunkl的p标志位*/
  else if (!inuse (next))
    do_check_free_chunk (av, next);
    /*这个宏有点麻烦,暂时不再深入*/
}
```
总结一下:这个宏主要检测nextchunk的p标志位,如果pre chunk是被free的,会检测其size,而对top chunk的检测则不太重要.

下面回到`_int_free()`函数
```
/*_int_free (mstate av, mchunkptr p, int have_lock)*/
#if USE_TCACHE
  {
  /*size转成索引*/
    size_t tc_idx = csize2tidx (size);
    /*索引是否在tcache范围内*/
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
  /* Check to see if it's already in the tcache.  */
  tcache_entry *e = (tcache_entry *) chunk2mem (p);

  /* This test succeeds on double free.  However, we don't 100%
     trust it (it also matches random payload data at a 1 in
     2^<size_t> chance), so verify it's not an unlikely
     coincidence before aborting.  */
     /*检测key值*/
  if (__glibc_unlikely (e->key == tcache_key))
    {
      tcache_entry *tmp;
      size_t cnt = 0;
      LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
      /*
      这里遍历next链表,做tcache链表中最大数量检测,地址对齐检测,链表中地址是否重复的检测(防止double free)
      */
      for (tmp = tcache->entries[tc_idx];
     tmp;
     tmp = REVEAL_PTR (tmp->next), ++cnt)
        {
	    if (cnt >= mp_.tcache_count)
	      malloc_printerr ("free(): too many chunks detected in tcache");
	    if (__glibc_unlikely (!aligned_OK (tmp)))
	      malloc_printerr ("free(): unaligned chunk detected in tcache 2");
	    if (tmp == e)
	      malloc_printerr ("free(): double free detected in tcache 2");
    /* If we get here, it was a coincidence.  We've wasted a
       few cycles, but don't abort.  */
        }
    }
/*检测对应索引处是否还有chunk,若有则直接放进去并return*/
  if (tcache->counts[tc_idx] < mp_.tcache_count)
    {
      tcache_put (p, tc_idx);
      return;
    }
      }
  }
#endif
```
下面进入最后的`tcache_put`函数.
```
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
/*写key值*/
  e->key = tcache_key;

/*处理链表,和tcachebins处的entry指针*/
  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
  tcache->entries[tc_idx] = e;
  
  /*处理tcache计数*/
  ++(tcache->counts[tc_idx]);
}
```
下面看一下用于safe linking,保护next指针的两个宏.
```
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
  /*这里是chunk的&next处理后和要储存的地址位xor*/

#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```
之后的几次free与上面流程一致,不再讨论.
 这里有趣的是,第一个进入tcache的next指针为0,但物理地址中由于safe linking保护却非0
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_dup/图/QQ20260105-103540.png]]
![[notes/pwn/堆利用/how2heap源码分析/2.35/fastbin_dup/图/QQ20260105-103525.png]]

---
## 攻击详解

到这里,相信你已经对堆的分配机制有了更深的理解,下面,不会在一步步解释程序运行逻辑,只会对攻击所利用的源码段做详细解释.

```
 printf("Allocating 3 buffers.\n");

    int *a = calloc(1, 8);
    int *b = calloc(1, 8);
    int *c = calloc(1, 8);
    
    printf("1st calloc(1, 8): %p\n", a);
    printf("2nd calloc(1, 8): %p\n", b);
    printf("3rd calloc(1, 8): %p\n", c);

    printf("Freeing the first one...\n");

    free(a);
    
    printf("If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);

    // free(a);
    
    printf("So, instead, we'll free %p.\n", b);

    free(b);

    printf("Now, we can free %p again, since it's not the head of the free list.\n", a);

    free(a);

    printf("Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);

    a = calloc(1, 8);
    b = calloc(1, 8);
    c = calloc(1, 8);

    printf("1st calloc(1, 8): %p\n", a);
    printf("2nd calloc(1, 8): %p\n", b);
    printf("3rd calloc(1, 8): %p\n", c);

    assert(a == c);

}
```
这里样例大量使用calloc,其与malloc区别是它会给申请的chunk的user data的部分重要数据全用\x00覆盖.
首先申请三个chunk后,以a,b,a的顺序free了三个chunk,下面看一下源码对free进fastbin的检查:
```
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
	  malloc_printerr ("double free or corruption (fasttop)");
	p->fd = PROTECT_PTR (&p->fd, old);
	*fb = p;
      }
```
可以看到,这里只会保存两个之前被free的chunk,分别是old和old2,但这里只对old1做了检查,就开始维护fastbin的链表了.所以,只要按a,b,a顺序,就能进行double free,之后任意地址申请.
