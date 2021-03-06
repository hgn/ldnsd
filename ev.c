/* Hagen Paul Pfeifer <hagen@jauu.net>
 * Public Domain Software - do what ever you want */

#include "ev.h"

#ifndef rdtscll
#define rdtscll(val) \
	__asm__ __volatile__("rdtsc" : "=A" (val))
#endif

#ifdef __GNUC__
#undef __always_inline
#if __GNUC_PREREQ (3,2)
# define __always_inline __inline __attribute__ ((__always_inline__))
#else
# define __always_inline __inline
#endif
#if !defined(likely) && !defined(unlikely)
# define likely(x)   __builtin_expect(!!(x), 1)
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#else /* !__GNUC__ */
# define likely(x) (x)
# define unlikely(x) (x)
#endif

#if !defined(ARRAY_SIZE)
# define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#if defined(LIBEVE_DEBUG)
#define pr_debug(fmt_str, ...) \
	fprintf(stderr, fmt_str, ##__VA_ARGS__)
#define	eve_assert(x) assert(x)
#else
#define pr_debug(fmt_str, ...) \
        ({ if (0) fprintf(stderr, fmt_str, ##__VA_ARGS__); 0; })
#define	eve_assert(x)
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>

/* FIXME: check for wrong subtraction/addition operation of struct timespec */

/* cmp: <, <=, >, >= or == */
#define timespec_cmp(tvp, uvp, cmp)               \
	(((tvp)->tv_sec == (uvp)->tv_sec) ?       \
	 ((tvp)->tv_nsec cmp (uvp)->tv_nsec) :    \
	 ((tvp)->tv_sec cmp (uvp)->tv_sec))

#define	timespec_eq(tvp, uvp) \
	(((tvp)->tv_sec == (uvp)->tv_sec) && ((tvp)->tv_nsec == (uvp)->tv_nsec))

#define timespec_add(res, vvp, uvp)                       \
do {                                                      \
	(res)->tv_sec  = (vvp)->tv_sec  + (uvp)->tv_sec;  \
	(res)->tv_nsec = (vvp)->tv_nsec + (uvp)->tv_nsec; \
	if ((res)->tv_nsec >= 1000000000) {               \
		(res)->tv_sec++;                          \
		(res)->tv_nsec -= 1000000000;             \
	}                                                 \
} while (0)

#define timespec_sub(res, vvp, uvp)                       \
do {                                                      \
	(res)->tv_sec = (vvp)->tv_sec - (uvp)->tv_sec;    \
	(res)->tv_nsec = (vvp)->tv_nsec - (uvp)->tv_nsec; \
	if ((res)->tv_nsec < 0) {                         \
		(res)->tv_sec--;                          \
		(res)->tv_nsec += 1000000000;             \
	}                                                 \
} while (0)

static struct ev *struct_ev_new_internal(void)
{
	struct ev *ev;

	ev = malloc(sizeof(*ev));
	if (!ev)
		return NULL;

	memset(ev, 0, sizeof(*ev));

	return ev;
}

inline void ev_entry_set_data(struct ev_entry *entry, void *data)
{
	entry->data = data;
}

int ev_run_out(struct ev *ev)
{
	eve_assert(ev);
	ev->break_loop = 1;
	return EV_SUCCESS;
}

/* similar for all implementations, at least
 * under Linux. Solaris, AIX, etc. differs and need
 * a separate implementation */
int ev_set_non_blocking(int fd) {
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return EV_FAILURE;

	flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (flags < 0)
		return EV_FAILURE;

	return EV_SUCCESS;
}


#if defined(HAVE_EPOLL)

#include <sys/epoll.h>
#include <sys/timerfd.h>

struct ev_entry_data_epoll {
	uint32_t flags;
};

#define	EVE_EPOLL_BACKING_STORE_HINT 64
#define EVE_EPOLL_ARRAY_SIZE 64

static inline void ev_free_epoll(struct ev *ev)
{
	eve_assert(ev);

	/* close epoll descriptor */
	close(ev->fd);

	memset(ev, 0, sizeof(struct ev));
	free(ev);
}

static inline struct ev *ev_new_epoll(void)
{
	struct ev *ev;

	ev = struct_ev_new_internal();
	if (!ev)
		return NULL;

	ev->fd = epoll_create(EVE_EPOLL_BACKING_STORE_HINT);
	if (ev->fd < 0) {
		ev_free_epoll(ev);
		return NULL;
	}

	ev->size        = 0;
	ev->break_loop = 0;

	return ev;
}

static struct ev_entry *ev_entry_new_epoll_internal(void)
{
	struct ev_entry *ev_entry;

	ev_entry = malloc(sizeof(struct ev_entry));
	if (!ev_entry)
		return NULL;

	memset(ev_entry, 0, sizeof(struct ev_entry));

	ev_entry->priv_data = malloc(sizeof(struct ev_entry_data_epoll));
	if (!ev_entry->priv_data) {
		free(ev_entry);
		return NULL;
	}

	memset(ev_entry->priv_data, 0, sizeof(struct ev_entry_data_epoll));

	return ev_entry;
}

static inline struct ev_entry *ev_entry_new_epoll(int fd, int what,
		void (*cb)(int, int, void *), void *data)
{
	struct ev_entry *ev_entry;
	struct ev_entry_data_epoll *ev_entry_data_epoll;

	eve_assert(what == EV_READ || what == EV_WRITE);
	eve_assert(cb);
	eve_assert(fd >= 0);

	ev_entry = ev_entry_new_epoll_internal();
	if (!ev_entry)
		return NULL;

	ev_entry->fd    = fd;
	ev_entry->type  = what;
	ev_entry->fd_cb = cb;
	ev_entry->data  = data;

	ev_entry_data_epoll = ev_entry->priv_data;

	switch (what) {
	case EV_READ:
		ev_entry_data_epoll->flags = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;
		break;
	case EV_WRITE:
		ev_entry_data_epoll->flags = EPOLLOUT | EPOLLPRI | EPOLLERR | EPOLLHUP;
		break;
	default:
		/* cannot happen - previously catched via assert(3) */
		break;
	}

	return ev_entry;
}

static inline struct ev_entry *ev_timer_new_epoll(struct timespec *timespec,
		void (*cb)(void *), void *data)
{
	struct ev_entry *ev_entry;

	eve_assert(timespec && cb);

	ev_entry = ev_entry_new_epoll_internal();
	if (!ev_entry)
		return NULL;

	ev_entry->type     = EV_TIMEOUT;
	ev_entry->timer_cb = cb;
	ev_entry->data     = data;

	memcpy(&ev_entry->timespec, timespec, sizeof(struct timespec));

	return ev_entry;
}

static inline void ev_entry_free_epoll(struct ev_entry *ev_entry)
{
	eve_assert(ev_entry);
	eve_assert(ev_entry->priv_data);

	free(ev_entry->priv_data);
	memset(ev_entry, 0, sizeof(struct ev_entry));
	free(ev_entry);
}

static int ev_arm_timerfd_internal(struct ev_entry *ev_entry)
{
	int ret, fd;
	struct timespec now;
	struct itimerspec new_value;
	struct ev_entry_data_epoll *ev_entry_data_epoll = ev_entry->priv_data;

	memset(&new_value, 0, sizeof(struct itimerspec));

	ret = clock_gettime(CLOCK_REALTIME, &now);
	if (ret < 0) {
		return EV_FAILURE;
	}

	new_value.it_value.tv_sec  = now.tv_sec  + ev_entry->timespec.tv_sec;
	new_value.it_value.tv_nsec = now.tv_nsec + ev_entry->timespec.tv_nsec;

	/* timerfd_settime() cannot handle larger nsecs - catch overflow */
	if (new_value.it_value.tv_nsec >= 1000000000) {
		new_value.it_value.tv_sec++;
		new_value.it_value.tv_nsec -= 1000000000;
		eve_assert(new_value.it_value.tv_nsec > 0);
	}

	new_value.it_interval.tv_sec  = 0;
	new_value.it_interval.tv_nsec = 0;

	fd = timerfd_create(CLOCK_REALTIME, 0);
	if (fd < 0) {
		return EV_FAILURE;
	}

	ret = timerfd_settime(fd, TFD_TIMER_ABSTIME, &new_value, NULL);
	if (ret < 0) {
		close(fd);
		return EV_FAILURE;
	}

	ev_entry_data_epoll->flags = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;

	ev_entry->fd = fd;

	return EV_SUCCESS;
}

static inline int ev_add_epoll(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;
	struct epoll_event epoll_ev;
	struct ev_entry_data_epoll *ev_entry_data_epoll;

	eve_assert(ev);
	eve_assert(ev_entry);

	ev_entry_data_epoll = ev_entry->priv_data;

	memset(&epoll_ev, 0, sizeof(struct epoll_event));

	if ((ev_entry->type == EV_TIMEOUT) &&
			(ev_arm_timerfd_internal(ev_entry) == EV_FAILURE)) {
		return EV_FAILURE;
	}

	/* FIXME: the mapping must be a one to one mapping */
	epoll_ev.events   = ev_entry_data_epoll->flags;
	epoll_ev.data.ptr = ev_entry;

	pr_debug("set descriptor %d to epoll set\n", ev->fd);

	ret = epoll_ctl(ev->fd, EPOLL_CTL_ADD, ev_entry->fd, &epoll_ev);
	if (ret < 0) {
		return EV_FAILURE;
	}

	ev->size++;

	return EV_SUCCESS;
}

static inline int ev_del_epoll(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;
	struct epoll_event epoll_ev;

	eve_assert(ev);
	eve_assert(ev_entry);

	memset(&epoll_ev, 0, sizeof(struct epoll_event));

	ret = epoll_ctl(ev->fd, EPOLL_CTL_DEL, ev_entry->fd, &epoll_ev);
	if (ret < 0) {
		return EV_FAILURE;
	}

	ev->size--;

	return EV_SUCCESS;
}

static inline int ev_timer_cancel_epoll(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;

	eve_assert(ev_entry);
	eve_assert(ev_entry->type == EV_TIMEOUT);

	ret = ev_del_epoll(ev, ev_entry);
	if (ret != EV_SUCCESS)
		return EV_FAILURE;

	/* close the timer fd specific descriptor */
	close(ev_entry->fd);
	ev_entry_free_epoll(ev_entry);

	return EV_SUCCESS;
}

static inline void ev_process_call_epoll_timeout(
		struct ev *ev, struct ev_entry *ev_entry)
{
	ssize_t ret;
	int64_t time_buf;

	/* first of all - call user callback */
	ev_entry->timer_cb(ev_entry->data);

	/* and now: cleanup timer specific data and
	 * finally all event specific data */
	ret = read(ev_entry->fd, &time_buf, sizeof(int64_t));
	if ((ret < (ssize_t)sizeof(int64_t)) ||
			(time_buf > 1)) {
		/* failure - should not happens: kernel bug */
		eve_assert(0);
	}

	ev_del_epoll(ev, ev_entry);
	close(ev_entry->fd);
	ev_entry_free_epoll(ev_entry);
}


static inline void ev_process_call_internal(
		struct ev *ev, struct ev_entry *ev_entry)
{
	(void) ev;

	eve_assert(ev_entry);

	switch (ev_entry->type) {
		case EV_READ:
		case EV_WRITE:
			ev_entry->fd_cb(ev_entry->fd, ev_entry->type, ev_entry->data);
			return;
			break;
		case EV_TIMEOUT:
			ev_process_call_epoll_timeout(ev, ev_entry);
			break;
		default:
			return;
			break;
	}
	return;
}

static inline int ev_loop_epoll(struct ev *ev, uint32_t flags)
{
	int nfds, i;
	struct epoll_event events[EVE_EPOLL_ARRAY_SIZE];

	eve_assert(ev);

	(void) flags; /* currently ignored */

	while (ev->size > 0) {
		nfds = epoll_wait(ev->fd, events, EVE_EPOLL_ARRAY_SIZE, -1);
		if (nfds < 0) {
			return EV_FAILURE;
		}

		/* multiplex and call the registerd callback handler */
		for (i = 0; i < nfds; i++) {
			struct ev_entry *ev_entry = (struct ev_entry *)events[i].data.ptr;
			ev_process_call_internal(ev, ev_entry);
		}

		if (ev->break_loop)
			break;
	}

	return EV_SUCCESS;
}


/* actual epoll/timer_fd API methods definitions is here */
struct ev *ev_new(void)
{
	return ev_new_epoll();
}

void ev_free(struct ev *ev)
{
	return ev_free_epoll(ev);
}

struct ev_entry *ev_entry_new(int fd, int what,
		void (*cb)(int, int, void *), void *data)
{
	return ev_entry_new_epoll(fd, what, cb, data);
}

struct ev_entry *ev_timer_new(struct timespec *timespec,
		void (*cb)(void *), void *data)
{
	return ev_timer_new_epoll(timespec, cb, data);
}

void ev_entry_free(struct ev_entry *ev_entry)
{
	ev_entry_free_epoll(ev_entry);
}

int ev_timer_cancel(struct ev *ev, struct ev_entry *ev_entry) {
	return ev_timer_cancel_epoll(ev, ev_entry);
}

int ev_add(struct ev *ev, struct ev_entry *ev_entry) {
	return ev_add_epoll(ev, ev_entry);
}

int ev_del(struct ev *ev, struct ev_entry *ev_entry)
{
	return ev_del_epoll(ev, ev_entry);
}

int ev_loop(struct ev *ev, uint32_t flags)
{
	return ev_loop_epoll(ev, flags);
}


#elif defined(HAVE_SELECT)

/* According to POSIX.1-2001 */
#include <sys/select.h>
/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

enum rbtree_color { RED, BLACK };

struct rbtree_node {

	struct rbtree_node *left;
	struct rbtree_node *right;
	struct rbtree_node *parent;

	/* key is of type struct timespec * */
	void *key;
	/* data is of type struct ev_entry * */
	void *data;

	enum rbtree_color color;
};

struct ev_entry_data_select {
	uint32_t flags;
	struct rbtree_node *node;
};

struct rbtree {
	struct rbtree_node *root;
	int (*compare)(void *, void *);
	size_t size;
};


struct rbtree *rbtree_init(int (*cmp)(void *, void *));

struct rbtree_node *rbtree_lookup(struct rbtree *, void *key);
struct rbtree_node *rbtree_insert(struct rbtree *, void *key, void *data);
struct rbtree_node *rbtree_delete(struct rbtree *, void *key);
struct rbtree_node *rbtree_delete_by_node(struct rbtree* t, struct rbtree_node *n);

struct rbtree_node *rbtree_lookup_max_node(struct rbtree_node *);
struct rbtree_node *rbtree_lookup_min_node(struct rbtree_node *);

size_t rbtree_size(struct rbtree *);
struct rbtree_node *rbtree_node_alloc(void);
void rbtree_node_free(struct rbtree_node *);
/* deletes rbtree only, rbtree_node are NOT freed */
void rbtree_rbtree_free(struct rbtree *);

static struct rbtree_node *sibling(struct rbtree_node *n);
static struct rbtree_node *uncle(struct rbtree_node *n);
static enum rbtree_color node_color(struct rbtree_node *n);

static void rotate_left(struct rbtree *, struct rbtree_node *);
static void rotate_right(struct rbtree *, struct rbtree_node *);

/* forward declarations */
static void replace_node(struct rbtree *, struct rbtree_node *, struct rbtree_node *);
static void insert_1(struct rbtree *, struct rbtree_node *);
static void insert_2(struct rbtree *, struct rbtree_node *);
static void insert_3(struct rbtree *, struct rbtree_node *);
static void insert_4(struct rbtree *, struct rbtree_node *);
static void insert_5(struct rbtree *, struct rbtree_node *);
static void delete_1(struct rbtree *, struct rbtree_node *);
static void delete_2(struct rbtree *, struct rbtree_node *);
static void delete_3(struct rbtree *, struct rbtree_node *);
static void delete_4(struct rbtree *, struct rbtree_node *);
static void delete_5(struct rbtree *, struct rbtree_node *);
static void delete_6(struct rbtree *, struct rbtree_node *);

static struct rbtree_node* grandparent(struct rbtree_node* n) {

	eve_assert(n);
	eve_assert(n->parent);
	eve_assert(n->parent->parent);

	return n->parent->parent;
}

static void delete_1(struct rbtree* t, struct rbtree_node* n)
{
	if (n->parent == NULL)
		return;
	else
		delete_2(t, n);
}


static void delete_2(struct rbtree* t, struct rbtree_node* n)
{
	if (node_color(sibling(n)) == RED) {
		n->parent->color = RED;
		sibling(n)->color = BLACK;
		if (n == n->parent->left)
			rotate_left(t, n->parent);
		else
			rotate_right(t, n->parent);
	}
	delete_3(t, n);
}


static void delete_3(struct rbtree* t, struct rbtree_node* n)
{
	if (node_color(n->parent) == BLACK &&
			node_color(sibling(n)) == BLACK &&
			node_color(sibling(n)->left) == BLACK &&
			node_color(sibling(n)->right) == BLACK)
	{
		sibling(n)->color = RED;
		delete_1(t, n->parent);
	}
	else
		delete_4(t, n);
}


static void delete_4(struct rbtree* t, struct rbtree_node* n)
{
	if (node_color(n->parent) == RED &&
			node_color(sibling(n)) == BLACK &&
			node_color(sibling(n)->left) == BLACK &&
			node_color(sibling(n)->right) == BLACK)
	{
		sibling(n)->color = RED;
		n->parent->color = BLACK;
	}
	else
		delete_5(t, n);
}


static void delete_5(struct rbtree* t, struct rbtree_node* n)
{
	if (n == n->parent->left &&
			node_color(sibling(n)) == BLACK &&
			node_color(sibling(n)->left) == RED &&
			node_color(sibling(n)->right) == BLACK)
	{
		sibling(n)->color = RED;
		sibling(n)->left->color = BLACK;
		rotate_right(t, sibling(n));
	} else if (n == n->parent->right &&
			node_color(sibling(n)) == BLACK &&
			node_color(sibling(n)->right) == RED &&
			node_color(sibling(n)->left) == BLACK)
	{
		sibling(n)->color = RED;
		sibling(n)->right->color = BLACK;
		rotate_left(t, sibling(n));
	}
	delete_6(t, n);
}

static void delete_6(struct rbtree* t, struct rbtree_node* n)
{
	sibling(n)->color = node_color(n->parent);
	n->parent->color = BLACK;

	if (n == n->parent->left) {
		eve_assert (node_color(sibling(n)->right) == RED);
		sibling(n)->right->color = BLACK;
		rotate_left(t, n->parent);
	} else {
		eve_assert (node_color(sibling(n)->left) == RED);
		sibling(n)->left->color = BLACK;
		rotate_right(t, n->parent);
	}
}

static void insert_1(struct rbtree* t, struct rbtree_node* n)
{
	if (n->parent == NULL)
		n->color = BLACK;
	else
		insert_2(t, n);
}

static void insert_2(struct rbtree* t, struct rbtree_node* n)
{
	if (node_color(n->parent) == BLACK)
		return;
	else
		insert_3(t, n);
}

static void insert_3(struct rbtree* t, struct rbtree_node* n)
{
	if (node_color(uncle(n)) == RED) {
		n->parent->color = BLACK;
		uncle(n)->color = BLACK;
		grandparent(n)->color = RED;
		insert_1(t, grandparent(n));
	} else {
		insert_4(t, n);
	}
}

static void insert_4(struct rbtree* t, struct rbtree_node* n)
{
	if (n == n->parent->right && n->parent == grandparent(n)->left) {
		rotate_left(t, n->parent);
		n = n->left;
	} else if (n == n->parent->left && n->parent == grandparent(n)->right) {
		rotate_right(t, n->parent);
		n = n->right;
	}
	insert_5(t, n);
}

static void insert_5(struct rbtree* t, struct rbtree_node* n)
{
	n->parent->color = BLACK;
	grandparent(n)->color = RED;
	if (n == n->parent->left && n->parent == grandparent(n)->left) {
		rotate_right(t, grandparent(n));
	} else {
		eve_assert (n == n->parent->right && n->parent == grandparent(n)->right);
		rotate_left(t, grandparent(n));
	}
}


static struct rbtree_node* sibling(struct rbtree_node* n)
{
	eve_assert(n != NULL);
	eve_assert(n->parent != NULL);

	if (n == n->parent->left)
		return n->parent->right;
	else
		return n->parent->left;
}

static struct rbtree_node* uncle(struct rbtree_node* n)
{
	eve_assert(n != NULL);
	eve_assert(n->parent != NULL);
	eve_assert(n->parent->parent != NULL);

	return sibling(n->parent);
}

static enum rbtree_color node_color(struct rbtree_node* n)
{
	return n == NULL ? BLACK : n->color;
}

struct rbtree *rbtree_init(int (*compare)(void *, void *))
{
	struct rbtree *tree;

	tree = malloc(sizeof(*tree));
	if (tree == NULL)
		return NULL;

	memset(tree, 0, sizeof(*tree));

	tree->root    = NULL;
	tree->size    = 0;

	tree->compare = compare;

	return tree;
}

struct rbtree_node *rbtree_lookup(struct rbtree* t, void* key) {

	int comp_result;
	struct rbtree_node* n = t->root;

	while (n != NULL) {
		comp_result = t->compare(key, n->key);
		if (comp_result == 0) {
			return n;
		} else if (comp_result < 0) {
			n = n->left;
		} else {
			eve_assert(comp_result > 0);
			n = n->right;
		}
	}
	return n;
}

void rotate_left(struct rbtree* t, struct rbtree_node* n) {

	struct rbtree_node* r = n->right;

	replace_node(t, n, r);
	n->right = r->left;

	if (r->left != NULL) {
		r->left->parent = n;
	}

	r->left = n;
	n->parent = r;
}

void rotate_right(struct rbtree* t, struct rbtree_node* n) {

	struct rbtree_node* left = n->left;

	replace_node(t, n, left);
	n->left = left->right;
	if (left->right != NULL) {
		left->right->parent = n;
	}

	left->right = n;
	n->parent   = left;
}

void replace_node(struct rbtree* t, struct rbtree_node* oldn,
		struct rbtree_node* newn)
{
	if (oldn->parent == NULL) {
		t->root = newn;
	} else {
		if (oldn == oldn->parent->left)
			oldn->parent->left = newn;
		else
			oldn->parent->right = newn;
	}
	if (newn != NULL) {
		newn->parent = oldn->parent;
	}
}

struct rbtree_node *rbtree_insert(struct rbtree* t, void *key, void *data)
{
	struct rbtree_node *n, *new_node;

	new_node = malloc(sizeof(*new_node));
	if (new_node == NULL)
		return NULL;

	memset(new_node, 0, sizeof(*new_node));

	new_node->key  = key;
	new_node->data = data;

	new_node->color  = RED;
	new_node->left   = NULL;
	new_node->right  = NULL;
	new_node->parent = NULL;

	if (t->root == NULL) {
		t->root = new_node;
		goto out;
	}

	n = t->root;

	while (1) {
		int comp_result = t->compare(new_node->key, n->key);
		if (comp_result == 0) {
			goto err;
		} else if (comp_result < 0) {
			if (n->left == NULL) {
				n->left = new_node;
				break;
			} else {
				n = n->left;
			}
		} else {
			eve_assert (comp_result > 0);
			if (n->right == NULL) {
				n->right = new_node;
				break;
			} else {
				n = n->right;
			}
		}
	}
	new_node->parent = n;

out:
	t->size++;
	insert_1(t, new_node);

	return new_node;

err:
	free(new_node);
	return NULL;
}

struct rbtree_node *rbtree_delete_by_node(struct rbtree* t, struct rbtree_node *n)
{
	struct rbtree_node* child;

	eve_assert(t);
	eve_assert(n);

	if (n->left != NULL && n->right != NULL) {
		/* Copy key/data from predecessor and then delete it instead */
		struct rbtree_node* pred = rbtree_lookup_max_node(n->left);
		n->key = pred->key;
		n->data = pred->data;
		n = pred;
	}

	eve_assert(n->left == NULL || n->right == NULL);

	child = n->right == NULL ? n->left : n->right;
	if (node_color(n) == BLACK) {
		n->color = node_color(child);
		delete_1(t, n);
	}
	replace_node(t, n, child);

	t->size--;

	return n;
}

struct rbtree_node *rbtree_delete(struct rbtree* t, void* key)
{
	struct rbtree_node *n;

	n = rbtree_lookup(t, key);
	if (n == NULL)
		return NULL;

	return rbtree_delete_by_node(t, n);
}


struct rbtree_node *rbtree_lookup_max_node(struct rbtree_node* n)
{
	if (n == NULL)
		return NULL;

	while (n->right != NULL)
		n = n->right;

	return n;
}

struct rbtree_node *rbtree_lookup_min_node(struct rbtree_node* n)
{
	if (n == NULL)
		return NULL;

	while (n->left != NULL)
		n = n->left;

	return n;
}

struct rbtree_node *rbtree_next(struct rbtree_node *node)
{
	struct rbtree_node *parent;

	if (!node)
		return NULL;

	if (node->right) {
		node = node->right;
		while (node->left != NULL)
			node = node->left;
		return node;
	}

	while (node && (parent = node->parent) && node == parent->right)
		node = parent;

	return parent;
}

size_t rbtree_size(struct rbtree *tree)
{
	return tree->size;
}

struct rbtree_node *rbtree_node_alloc(void)
{
	return malloc(sizeof(struct rbtree_node));
}

void rbtree_node_free(struct rbtree_node *n)
{
	free(n);
}

void rbtree_rbtree_free(struct rbtree *tree)
{
	free(tree);
}

static int cmp_fd(void *left, void *right)
{
	int l, r;

	eve_assert(left);
	eve_assert(right);

	l = *(int *)left;
	r = *(int *)right;

	if (l < r)
		return -1;
	else if (l > r)
		return 1;
	else
		return 0;
}

static int cmp_timespec(void *left, void *right)
{
	struct timespec *l, *r;

	eve_assert(left);
	eve_assert(right);

	l = (struct timespec *)left;
	r = (struct timespec *)right;

	if (l->tv_sec < r->tv_sec) {
		return -1;
	}
	else if (l->tv_sec > r->tv_sec) {
		return 1;
	}
	else { /* seconds identical */
		if (l->tv_nsec < r->tv_nsec) {
			return -1;
		}
		else if (l->tv_nsec > r->tv_nsec) {
			return 1;
		}
		else {
			/* seconds AND nanoseconds identical,
			 * uniqueness via pointer value */
			if (left < right)
				return -1;
			else if (left > right)
				return 1;
			else /* Failure: duplicate */
				return 0;
		}
	}
}

struct ev_fd_set {
	unsigned long *fds_bits;
	size_t   fds_size;
};

static void ev_fd_free(struct ev_fd_set *fdset)
{
	if (fdset->fds_bits)
		free(fdset->fds_bits);
}


static void ev_fd_zero(struct ev_fd_set *fdset)
{
	ev_fd_free(fdset);

	fdset->fds_bits = NULL;
	fdset->fds_size = 0;
}

/* FIXME: handle ENOMEM */
void ev_fd_set(int fd, struct ev_fd_set *fdset)
{
	unsigned long bit, byte, *tmp_bits;
	size_t new_size;

	if (fd < 0)
		return;

	if (fd >= (int)fdset->fds_size) {
		new_size = sizeof(long) * ((fd + sizeof(long) - 1) / sizeof(long));
		pr_debug("new size: %ld\n", new_size);
		if (!(tmp_bits = realloc(fdset->fds_bits, new_size)))
			return;
		fdset->fds_bits = tmp_bits;
		fdset->fds_size = new_size;
	}

	byte = fd / sizeof(long);
	bit  = (byte > 0) ? 1L << ((fd % sizeof(long)) - 1) : 1L << (fd % sizeof(long));

	fdset->fds_bits[byte] |= bit;

	pr_debug("ev_fd_set: fd: %d -- long: %ld, bit 0x%lx\n", fd, byte, bit);
}

int ev_fd_isset(int fd, struct ev_fd_set *fdset)
{
	unsigned long bit, byte;

	if (fd < 0 || fd >= (int)fdset->fds_size)
		return 0;

	byte = fd / sizeof(long);
	bit  = (byte > 0) ? 1L << ((fd % sizeof(long)) - 1) : 1L << (fd % sizeof(long));

	pr_debug("ev_fd_isset: fd: %d -- long: %ld, bit 0x%lx\n", fd, byte, bit);

	return fdset->fds_bits[byte] & bit;
}

int ev_fd_size(struct ev_fd_set *fdset)
{
	return fdset->fds_size;
}

struct ev_data_select {
	/* rbtree for timers */
	struct rbtree *tm_tree;
	/* rbtree for read fd's */
	struct rbtree *rd_tree;
	/* rbtree for write fd's */
	struct rbtree *wr_tree;
};

static inline struct ev *ev_new_select(void)
{
	struct ev *ev;
	struct ev_data_select *ev_priv_data;

	ev = struct_ev_new_internal();
	if (!ev)
		return NULL;

	ev_priv_data = malloc(sizeof(*ev_priv_data));
	if (!ev_priv_data)
		goto err_priv;

	memset(ev_priv_data, 0, sizeof(*ev_priv_data));
	ev->priv_data = ev_priv_data;

	ev_priv_data->tm_tree = rbtree_init(cmp_timespec);
	if (!ev_priv_data->tm_tree)
		goto err_tree_init;

	ev_priv_data->rd_tree = rbtree_init(cmp_fd);
	if (!ev_priv_data->rd_tree)
		goto err_rd_tree_init;

	ev_priv_data->wr_tree = rbtree_init(cmp_fd);
	if (!ev_priv_data->wr_tree)
		goto err_wr_tree_init;

	ev->size        = 0;
	ev->break_loop  = 0;

	return ev;

err_wr_tree_init:
	rbtree_rbtree_free(ev_priv_data->rd_tree);
err_rd_tree_init:
	rbtree_rbtree_free(ev_priv_data->tm_tree);
err_tree_init:
	free(ev_priv_data);
err_priv:
	free(ev);

	return NULL;
}

static inline void ev_free_select(struct ev *ev)
{
	struct ev_data_select *ev_priv_data;

	eve_assert(ev);
	eve_assert(ev->priv_data);

	ev_priv_data = ev->priv_data;

	eve_assert(ev_priv_data->tm_tree);
	eve_assert(ev_priv_data->rd_tree);
	eve_assert(ev_priv_data->wr_tree);

	rbtree_rbtree_free(ev_priv_data->tm_tree);
	rbtree_rbtree_free(ev_priv_data->rd_tree);
	rbtree_rbtree_free(ev_priv_data->wr_tree);

	free(ev->priv_data);
	free(ev);

	ev = NULL;
}

static struct ev_entry *ev_entry_new_select_internal(void)
{
	struct ev_entry *ev_entry;

	ev_entry = malloc(sizeof(struct ev_entry));
	if (!ev_entry)
		return NULL;

	memset(ev_entry, 0, sizeof(struct ev_entry));

	ev_entry->priv_data = malloc(sizeof(struct ev_entry_data_select));
	if (!ev_entry->priv_data) {
		free(ev_entry);
		return NULL;
	}

	memset(ev_entry->priv_data, 0, sizeof(struct ev_entry_data_select));

	return ev_entry;
}

static inline struct ev_entry *ev_entry_new_select(int fd, int what,
		void (*cb)(int, int, void *), void *data)
{
	struct ev_entry *ev_entry;

	eve_assert(what == EV_READ || what == EV_WRITE);
	eve_assert(cb);
	eve_assert(fd >= 0);

	ev_entry = malloc(sizeof(struct ev_entry));
	if (!ev_entry)
		return NULL;

	memset(ev_entry, 0, sizeof(struct ev_entry));

	ev_entry->fd    = fd;
	ev_entry->type  = what;
	ev_entry->fd_cb = cb;
	ev_entry->data  = data;

	return ev_entry;
}

static inline struct ev_entry *ev_timer_new_select(struct timespec *timespec,
		void (*cb)(void *), void *data)
{
	struct ev_entry *ev_entry;

	eve_assert(timespec);
	eve_assert(cb);

	ev_entry = ev_entry_new_select_internal();
	if (!ev_entry)
		return NULL;

	ev_entry->type     = EV_TIMEOUT;
	ev_entry->timer_cb = cb;
	ev_entry->data     = data;

	memcpy(&ev_entry->timespec, timespec, sizeof(*timespec));

	return ev_entry;
}

static inline void ev_entry_free_select(struct ev_entry *ev_entry)
{
	eve_assert(ev_entry);
	eve_assert(ev_entry->priv_data);

	free(ev_entry->priv_data);
	free(ev_entry);
}

static inline int ev_free_time_event_select(struct ev *ev,
		struct rbtree_node *node)
{
	struct ev_data_select *ev_data_select;
	struct ev_entry_data_select *ev_entry_data_select;
	struct ev_entry *ev_entry;

	eve_assert(ev);
	eve_assert(ev->priv_data);
	eve_assert(node);
	eve_assert(node->data);

	ev_entry = node->data;
	ev_entry_data_select = ev_entry->priv_data;

	eve_assert(ev_entry_data_select);

	ev_data_select = ev->priv_data;

	/* remove from rbtree */
	node = rbtree_delete_by_node(ev_data_select->tm_tree, node);
	if (!node) {
		pr_debug("Failure in deleting node from rbtree\n");
		return EV_FAILURE;
	}

	/* free rbtree_node memory */
	rbtree_node_free(node);

	/* free ev_entry data */
	ev_entry_free(ev_entry);

	return EV_SUCCESS;
}

static int ev_timer_cancel_select(struct ev *ev, struct ev_entry *ev_entry)
{
	struct ev_entry_data_select *ev_entry_data_select;

	ev_entry_data_select = ev_entry->priv_data;

	return ev_free_time_event_select(ev, ev_entry_data_select->node);
}

/* insert timer into rbtree */
static int ev_select_arm_timer(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;
	struct rbtree_node *node;
	struct ev_entry_data_select *ev_entry_data_select;
	struct ev_data_select *ev_data_select;
	struct timespec now;

	eve_assert(ev);
	eve_assert(ev->priv_data);
	eve_assert(ev_entry);
	eve_assert(ev_entry->priv_data);

	ev_entry_data_select = ev_entry->priv_data;

	ev_data_select = ev->priv_data;

	/* ok, it is time to convert the offset into a absolute time */
	ret = clock_gettime(CLOCK_REALTIME, &now);
	if (ret < 0) {
		return EV_FAILURE;
	}

	timespec_add(&ev_entry->timespec, &ev_entry->timespec, &now);

	/* insert into timer tree */
	node = rbtree_insert(ev_data_select->tm_tree,
			(void *)&ev_entry->timespec, (void *)ev_entry);
	if (node == NULL) {
		return EV_FAILURE;
	}

	ev_entry_data_select->node = node;

	return EV_SUCCESS;
}

static int ev_add_select(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;
	struct ev_data_select *ev_data_select;
	struct rbtree_node *node;

	eve_assert(ev);
	eve_assert(ev->priv_data);

	ev_data_select = ev->priv_data;

	switch (ev_entry->type) {
	case EV_READ:
		node = rbtree_insert(ev_data_select->rd_tree,
				(void *)&ev_entry->fd, (void *)ev_entry);
		if (node == NULL) {
			pr_debug("failure in adding read ev_entry to rbtree\n");
			return EV_FAILURE;
		}
		break;
	case EV_WRITE:
		node = rbtree_insert(ev_data_select->wr_tree,
				(void *)&ev_entry->fd, (void *)ev_entry);
		if (node == NULL) {
			pr_debug("failure in adding write ev_entry to rbtree\n");
			return EV_FAILURE;
		}
		break;
	case EV_TIMEOUT:
		ret = ev_select_arm_timer(ev, ev_entry);
		if (ret != EV_SUCCESS)
			return ret;
		break;
	default:
		return EV_FAILURE;
	}


	ev->size++;

	return EV_SUCCESS;
}

static int ev_del_select(struct ev *ev, struct ev_entry *ev_entry)
{
	struct ev_data_select *ev_data_select;
	struct rbtree_node *node;

	eve_assert(ev);
	eve_assert(ev->priv_data);

	ev_data_select = ev->priv_data;

	switch (ev_entry->type) {
	case EV_READ:
		node = rbtree_delete(ev_data_select->rd_tree, (void *)&ev_entry->fd);
		if (node == NULL) {
			pr_debug("delete failure, key not in tree\n");
			return EV_FAILURE;
		}
		ev->size--;
		break;
	case EV_WRITE:
		node = rbtree_delete(ev_data_select->wr_tree, (void *)&ev_entry->fd);
		if (node == NULL) {
			pr_debug("delete failure, key not in tree\n");
			return EV_FAILURE;
		}
		ev->size--;
		break;
	default:
		return EV_FAILURE;
		break;
	}

	return EV_SUCCESS;
}

/* process all expired timeouts. ts_next returns the timespec of the
 * next timeout or NULL if no more timeouts are available */
static inline int ev_loop_select_process_timer(struct ev *ev, struct timespec *ts_next)
{
	int ret;
	struct timespec now;
	struct ev_data_select *ev_data_select;
	struct ev_entry *ev_entry;
	struct rbtree_node *min_node;

	ev_data_select = ev->priv_data;

	while (1) {

		/* select next element from tree and arm select loop */
		min_node = rbtree_lookup_min_node(ev_data_select->tm_tree->root);
		if (!min_node) {
			/* no more timeout event are available or operated
			 * with no timeouts at all */
			ts_next->tv_sec = ts_next->tv_nsec = 0;
			return EV_SUCCESS;
		}

		ev_entry = min_node->data;

		ret = clock_gettime(CLOCK_REALTIME, &now);
		if (ret < 0) {
			return EV_FAILURE;
		}

		if (timespec_cmp(&now, &ev_entry->timespec, <)) {
			/* ok the next timeout is in the future! We convert
			 * the absolut time to a offset and return the value
			 * */
			timespec_sub(ts_next, &ev_entry->timespec, &now);
			return EV_SUCCESS;
		}

		/* ev_entry is expired, now call the user provided callback
		 * and free the datastructures afterwards. After that we probe
		 * if another timeout intermediate expired */
		eve_assert(ev_entry->type == EV_TIMEOUT);

		/* call user provided callback */
		pr_debug("execute user callback timout 0x%p\n", min_node);
		ev_entry->timer_cb(ev_entry->data);

		ret = ev_free_time_event_select(ev, min_node);
		if (ret != EV_SUCCESS)
			return ret;

	}
}

static int ev_loop_select_check_call_set(struct ev *ev,
		struct ev_fd_set *rd_set, struct ev_fd_set *wr_set)
{
	struct rbtree_node *node;
	struct ev_data_select *ev_data_select;
	struct ev_entry *ev_entry;

	eve_assert(ev);
	eve_assert(ev->priv_data);
	eve_assert(rd_set);
	eve_assert(wr_set);

	ev_data_select = ev->priv_data;

	/* iterate over rd_tree */
	node = rbtree_lookup_min_node(ev_data_select->rd_tree->root);
	if (node) {
		ev_entry = node->data;

		if (ev_fd_isset(ev_entry->fd, rd_set)) {
			ev_entry->fd_cb(ev_entry->fd, EV_READ, ev_entry->data);
		}

		while ((node = rbtree_next(node)) != NULL) {

			ev_entry = node->data;

			eve_assert(ev_entry->type & EV_READ);

			if (ev_fd_isset(ev_entry->fd, rd_set)) {
				ev_entry->fd_cb(ev_entry->fd, EV_READ, ev_entry->data);
			}
		}
	}

	/* iterate over rd_tree */
	node = rbtree_lookup_min_node(ev_data_select->wr_tree->root);
	if (node) {
		ev_entry = node->data;

		if (ev_fd_isset(ev_entry->fd, wr_set)) {
			ev_entry->fd_cb(ev_entry->fd, EV_WRITE, ev_entry->data);
		}

		while ((node = rbtree_next(node)) != NULL) {

			ev_entry = node->data;

			if (ev_fd_isset(ev_entry->fd, wr_set)) {
				ev_entry->fd_cb(ev_entry->fd, EV_WRITE, ev_entry->data);
			}
		}
	}

	return EV_SUCCESS;
}

/* returns the maximum fd or negative code for error */
static inline int ev_loop_select_build_set(struct ev *ev,
		struct ev_fd_set *rd_set, struct ev_fd_set *wr_set, int *max_fd)
{
	struct rbtree_node *node;
	struct ev_data_select *ev_data_select;
	struct ev_entry *ev_entry;

	eve_assert(ev);
	eve_assert(ev->priv_data);
	eve_assert(rd_set);
	eve_assert(wr_set);

	*max_fd = -1;

	ev_fd_zero(rd_set);
	ev_fd_zero(wr_set);

	ev_data_select = ev->priv_data;

	/* iterate over rd_tree */
	node = rbtree_lookup_min_node(ev_data_select->rd_tree->root);
	if (node) {
		ev_entry = node->data;

		eve_assert(ev_entry->type & EV_READ);

		ev_fd_set(ev_entry->fd, rd_set);

		if (ev_entry->fd > *max_fd)
			*max_fd = ev_entry->fd;


		while ((node = rbtree_next(node)) != NULL) {

			ev_entry = node->data;

			eve_assert(ev_entry->type & EV_READ);

			ev_fd_set(ev_entry->fd, rd_set);

			if (ev_entry->fd > *max_fd)
				*max_fd = ev_entry->fd;
		}
	}

	/* iterate over rd_tree */
	node = rbtree_lookup_min_node(ev_data_select->wr_tree->root);
	if (node) {
		ev_entry = node->data;

		eve_assert(ev_entry->type & EV_WRITE);

		pr_debug("add FD %d for write\n", ev_entry->fd);
		ev_fd_set(ev_entry->fd, wr_set);

		if (ev_entry->fd > *max_fd)
			*max_fd = ev_entry->fd;

		while ((node = rbtree_next(node)) != NULL) {

			ev_entry = node->data;

			eve_assert(ev_entry->type & EV_WRITE);

			pr_debug("add FD %d for write\n", ev_entry->fd);
			ev_fd_set(ev_entry->fd, wr_set);

			if (ev_entry->fd > *max_fd)
				*max_fd = ev_entry->fd;
		}
	}

	return EV_SUCCESS;
}

static int ev_loop_select(struct ev *ev, uint32_t flags)
{
	int ret, max_fd;
	struct ev_fd_set rd_fds, wr_fds;
	struct timeval tv, *tvp;
	struct timespec timespec_res;

	/* not used yet and ignored */
	(void) flags;

	eve_assert(ev);
	eve_assert(ev->priv_data);

	memset(&rd_fds, 0, sizeof(struct ev_fd_set));
	memset(&wr_fds, 0, sizeof(struct ev_fd_set));

	while (ev->size > 0) {

		/* check for pending timeouts */
		ret = ev_loop_select_process_timer(ev, &timespec_res);
		if (ret != EV_SUCCESS) {
			pr_debug("ev_loop_select_process_timer() return a failure: %d\n",
					ret);
			return ret;
		}

		if (timespec_res.tv_sec || timespec_res.tv_nsec) {
			tv.tv_sec  = timespec_res.tv_sec;
			tv.tv_usec = timespec_res.tv_nsec / 1000;
			tvp = &tv;
		} else {
			/* we will block endless in select() - until a fd
			 * becomes read/writeable */
			tvp = NULL;
		}

		ret = ev_loop_select_build_set(ev, &rd_fds, &wr_fds, &max_fd);
		if (ret < 0) {
			pr_debug("failure in ev_loop_select_build_set()\n");
			return EV_FAILURE;
		}

		/* check if there is no more events available, if so we return
		 * gracelly */
		if (!tvp && max_fd == -1)
			return EV_SUCCESS;

		pr_debug("rdbits: 0x%lx (max_fd: %u)\n", *rd_fds.fds_bits, max_fd);

		ret = select(max_fd + 1, (fd_set *)rd_fds.fds_bits, (fd_set *)wr_fds.fds_bits, NULL, tvp);
		if (ret == -1) {
			pr_debug("select(): %s", strerror(errno));
			return EV_FAILURE;
		} else if (ret) {
			pr_debug("select returned with FD change (write or read)\n");
			ret = ev_loop_select_check_call_set(ev, &rd_fds, &wr_fds);
			if (ret < 0) {
				pr_debug("failure in ev_loop_select_build_set()\n");
				return EV_FAILURE;
			}
		} else {
			/* timer fired, handled in next loop iteration by
			 * ev_loop_select_process_timer() */
		}
	}

	ev_fd_free(&rd_fds);
	ev_fd_free(&wr_fds);

	return EV_SUCCESS;
}

/* actual select API methods definitions is here */
struct ev *ev_new(void)
{
	return ev_new_select();
}

void ev_free(struct ev *ev)
{
	return ev_free_select(ev);
}

struct ev_entry *ev_entry_new(int fd, int what,
		void (*cb)(int, int, void *), void *data)
{
	return ev_entry_new_select(fd, what, cb, data);
}

struct ev_entry *ev_timer_new(struct timespec *timespec,
		void (*cb)(void *), void *data)
{
	return ev_timer_new_select(timespec, cb, data);
}

void ev_entry_free(struct ev_entry *ev_entry)
{
	ev_entry_free_select(ev_entry);
}

int ev_timer_cancel(struct ev *ev, struct ev_entry *ev_entry) {
	return ev_timer_cancel_select(ev, ev_entry);
}

int ev_add(struct ev *ev, struct ev_entry *ev_entry) {
	return ev_add_select(ev, ev_entry);
}

int ev_del(struct ev *ev, struct ev_entry *ev_entry)
{
	return ev_del_select(ev, ev_entry);
}

int ev_loop(struct ev *ev, uint32_t flags)
{
	return ev_loop_select(ev, flags);
}


#else
# error "No event mechanism defined (epoll, select, ..) - "
        "adjust your Makefile and define -DHAVE_EPOLL, -DHAVE_SELECT or something"
#endif
