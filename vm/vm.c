/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "vm/uninit.h"
#include "vm/file.h"
#include "vm/anon.h"
/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
	int ty = VM_TYPE(page->operations->type);
	switch (ty)
	{
	case VM_UNINIT:
		return VM_TYPE(page->uninit.type);
	default:
		return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
/* 
 *
 *	이 함수는 spt에서 찾아보고 만약 없으면 빈 페이지를 할당하고 페이지에 맞는 initializer를 넣어준다
 * 
 */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux)
{
	ASSERT(VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page(spt, upage) == NULL)
	{
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		// 1. malloc으로  page struct를 만든다.
		struct page *new_page = (struct page *)malloc(sizeof(struct page));

		switch (type)
		{
		case VM_ANON:
			uninit_new(new_page, upage, init, type, aux, anon_initializer);
			break;

		case VM_FILE:
			uninit_new(new_page, upage, init, type, aux, file_backed_initializer);
			break;
		}

		/* TODO: Insert the page into the spt. */
		spt_insert_page(spt, new_page);
	}

	return true;

err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page(struct supplemental_page_table *spt, void *va)
{
	struct page temp_page;
	temp_page.va = pg_round_down(va);

	struct hash_elem *temp_hash_elem = hash_find(&spt->table, &temp_page.hash_elem);
	if (temp_hash_elem == NULL)
		return NULL;

	return hash_entry(temp_hash_elem, struct page, hash_elem);
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page)
{
	struct hash_elem *temp_elem = hash_insert(&spt->table, &page->hash_elem);
	if (temp_elem == NULL)
		return true;

	return false;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
	// vm_dealloc_page(page);
	// return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void)
{
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
	struct frame *victim UNUSED = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame(void)
{
	struct frame *frame = (struct frame *)malloc(sizeof(struct frame));

	frame->kva = palloc_get_page(PAL_USER);
	if (frame->kva == NULL)
		PANIC("TO DO");

	frame->page = NULL;

	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);

	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
	uintptr_t addr_page = pg_round_down(addr);
	vm_alloc_page(VM_ANON, addr_page, true); //page가 stack growth에 해당됨! 
	thread_current()->stack_bottom = addr_page;
	/* while 문으로 주어야 되는 것 아님 ? 될 때 까지? */

}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user, bool write, bool not_present)
{
	bool succ = false;
	/* TODO: Validate the fault */
	if (is_kernel_vaddr(addr) || addr == NULL)
		return false;

	struct supplemental_page_table *spt = &thread_current()->spt;

	/********* stack growth setting************/
	uintptr_t stack_limit = USER_STACK - (1<<20); 
	//stack이 끝에서부터 자라는 것은 오케이, 2^20은 그냥 우리가 정한 어떤 값?
	uintptr_t rsp = user ? f->rsp : thread_current()->user_rsp;
	uintptr_t stack_bottom = pg_round_down(rsp);

	if (addr <= USER_STACK && addr >= stack_limit && addr >= rsp - 8)
	{
		// if (addr >= stack_bottom + PGSIZE) //이건 왜 있는 거지..
		// 	return false;                  //이것은 왜 있는 것인가.... 
		vm_stack_growth(addr);		
	}
	
	/* 해야할 것:스택 증가를 확인합니다. */
	struct page *page = spt_find_page(spt, addr);
	if (page == NULL)
		return false;
	
	// 프레임을 할당해준다
	succ = vm_do_claim_page(page);

	return succ;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va)
{
	struct page *page = spt_find_page(&thread_current()->spt.table, va);
	if (page == NULL)
		return false;

	return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page(struct page *page)
{
	struct thread *curr = thread_current();
	struct frame *frame = vm_get_frame();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if (!pml4_set_page(curr->pml4, page->va, frame->kva, true))
		return false;

	return swap_in(page, frame->kva);
}

unsigned spt_hash(const struct hash_elem *elem, void *aux UNUSED);
static unsigned spt_less(const struct hash_elem *a, const struct hash_elem *b);

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
	hash_init(&spt->table, spt_hash, spt_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
								  struct supplemental_page_table *src UNUSED)
{
	struct hash_iterator i;
	struct hash *parent_hash = &(src->table);
	hash_first(&i, parent_hash);
	/* 해야할 것!
	 * 1. 부모 spt를 가져온다
	 * 2. page를 hash를 통해서 부른다 
	 * 3. user virtual addrress에 해당하는 페이지를 할당한다 
	 * 4. 갖고 온다 
	 * 5. uninit이 아닌것만 
	*/
	while (hash_next(&i))
	{ 
		// parent page를 hash를 통해서 가져오기
		struct page *parent_page = hash_entry(hash_cur(&i), struct page, hash_elem);
		// uninit page또한 갖구 와야함
		if (parent_page->operations->type == VM_UNINIT)
		{
			vm_initializer *init = parent_page->uninit.init;
			void *aux = parent_page->uninit.aux;
			vm_alloc_page_with_initializer(parent_page->uninit.type, parent_page->va, parent_page->writable, init, aux);
		}
		else
		// 페이지를 존재하는 것을 통해 할당하기
		{
			vm_alloc_page(page_get_type(parent_page), parent_page->va, parent_page->writable);
			// 페이지를 가져오기 
			vm_claim_page(parent_page->va);
			// 페이지에다가 덮어 씌우기
			struct page* child_page = spt_find_page(dst, parent_page->va);
			memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
		}
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	struct hash_iterator i;
	struct hash *parent_hash = &(spt->table);
	if (parent_hash == NULL)
	{
		return false;
	}
	
	// 첫번째 hash 할당해주기
	if (parent_hash == NULL)
	{
		return false;
	}
	
	hash_first(&i, parent_hash);
	while(hash_next(&i))
	{
		struct page *page_tobe_destroyed = hash_entry(hash_cur(&i), struct page, hash_elem);
		destroy(page_tobe_destroyed);
		hash_delete(parent_hash, hash_cur(&i));
	}
}

/********** project 3: virtaul memory **********/
unsigned spt_hash(const struct hash_elem *elem, void *aux UNUSED)
{
	const struct page *temp_page = hash_entry(elem, struct page, hash_elem);
	return hash_bytes(&temp_page->va, sizeof(temp_page->va));
}

static unsigned spt_less(const struct hash_elem *a, const struct hash_elem *b)
{
	const struct page *page_a = hash_entry(a, struct page, hash_elem);
	const struct page *page_b = hash_entry(b, struct page, hash_elem);

	return page_a->va < page_b->va;
}