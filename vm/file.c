/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/*lazy loading for mmap function */
static bool lazy_load_file(struct page *page, void *aux)
{
	struct file_info *file_info = (struct file_info *)aux;

	page->file.file = file_info->file;
	page->file.offset = file_info->ofs;
	page->file.length = file_info->page_read_bytes;

	int page_zero_bytes = file_info->page_zero_bytes;

	file_seek(page->file.file, page->file.offset);

	int temp;
	if ((temp = file_read(page->file.file, page->frame->kva, page->file.length))!= page->file.length)
	{
		free(file_info);
		return false;
	}

	memset(page->frame->kva + page->file.length, 0 , page_zero_bytes);
	
	return true;
}



/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) 
{
	// int fd 라고 되어 있는데 여기에서는 struct file이라고 되어있다. file을 통해서 file descriptor를 어캐 찾을 까? 이것은 syscall 에서 찾아와 준다 
	/* The entire file is mapped into consecutive virtual pages starting at addr. 
	 * If the length of the file is not a multiple of PGSIZE, then some bytes in the final mapped page "stick out" 
	 * beyond the end of the file. Set these bytes to zero when the page is faulted in, and discard them when the page 
	 * is written back to disk. If successful, this function returns the virtual address where the file is mapped. 
	 * On failure, it must return NULL which is not a valid address to map a file.*/


	struct thread *curr = thread_current();
	
	// STEP 1
	// mmap_file이라는 것을 할당하여 현재 thread에게 필요한 file를 걸어 놓는다. 그림은 다음과 같다. 
	// 즉, thread에도 큰 mmap_list라고 mmap_file을 관리하는 부분이 있다.
	
	struct mmap_file *mmap_file = (struct mmap_file *)malloc(sizeof(struct mmap_file));
	mmap_file->addr = addr;
	list_init(&mmap_file->page_list);
	list_push_back(&curr->mmap_list, &mmap_file->elem);
	
	/*
	 *    thread -----> mmap_list ---- mmap_file  ---- page_list ---- page
	 *                             |-- mmap_file   |-- page_list  |-- page
	 * 							   |-- mmap_file   |-- page_list  |-- page
	 * 							   |-- mmap_file   |-- page_list  |-- page
	 * 							   |__ mmap_file   |__ page_list  |__ page
	 */

	// STEP 2 
	// mmap_file에다가 할당해놓기!
	mmap_file->file = file_reopen(file); // 이것을 왜  reopen을 해야하는지? 
	if (mmap_file->file == NULL)
		return NULL;
	
	// STEP 3
	// while 문 돌기 전 : read_bytes 그리고 zero bytes setting 
	size_t read_bytes = length > file_length(mmap_file->file) ? file_length(mmap_file->file) : length;
	size_t zero_bytes = pg_round_up(read_bytes) - read_bytes;
	uintptr_t upage = addr;
	off_t ofs = offset;

	while (read_bytes > 0 || zero_bytes > 0)
	{
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct file_info *file_info = (struct file_info *)malloc(sizeof(struct file_info));

		file_info->file = mmap_file->file;
		file_info->ofs = ofs;
		file_info->page_read_bytes = page_read_bytes;
		file_info->page_zero_bytes = page_zero_bytes;

		if (!vm_alloc_page_with_initializer(VM_FILE, upage, writable, lazy_load_file, file_info))
			return false;
		
		struct page *page = spt_find_page(&curr->spt, upage);
		if (page == NULL)
			return false;
		
		list_push_back( &mmap_file->page_list, &page->mmap_elem);
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += PGSIZE;
	}
	return addr;
}


static struct mmap_file *find_mmap_file(void *addr)
{
	struct thread *curr = thread_current();
	struct list_elem *temp_elem = list_begin(&curr->mmap_list);
	for (;temp_elem!= list_tail(&curr->mmap_list); temp_elem = temp_elem->next)
	{
		struct mmap_file *temp_file = list_entry(temp_elem , struct mmap_file, elem);
		if (temp_file->addr == addr)
			return temp_file;
	}
	return NULL;
}


/* Do the munmap */
void
do_munmap (void *addr) 
{
	struct thread *curr = thread_current();
	struct mmap_file *mmap_file = find_mmap_file(addr);
	struct list_elem *temp_elem = list_begin(&mmap_file->page_list);

	for (;temp_elem != list_tail(&mmap_file->page_list);)
	{
		struct page *page = list_entry(temp_elem, struct page, mmap_elem);
		temp_elem = temp_elem->next;
		
		if (pml4_get_page(curr->pml4, page->va) == NULL)
			continue;
		if (pml4_is_dirty(curr->pml4, page->va))
		{
			file_write_at(mmap_file->file, )
		}
	}
}
