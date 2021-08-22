## LockFree

在多執行緒的情況下，難免會有兩個以上的 thread 同時存取到共享資源，而依照雙方執行順序的不同會有不同的結果，此就稱為 Race Condition，避免 Race Condition 的方法有許多種，如眾所周知的 semaphore、mutex 都是以類似 lock 的形式達成，不過使用這兩個機制可能會造成 deadlock、livelock，或是不公平的情況發生 (某個 thread 一直拿到 lock)，因此在之後工程師提出了 lockfree 的方法，lockfree 並非不使用 lock，而是 lock 之間不會有衝突，並且根據不同 level，能保證:

- lock-free: 眾多 thread 當中至少有一個 thread 是可以有進展的 (progress)，如 hp (hazard pointer)
- wait-free: 每個 thread 都能有進展，如 rcu (read-copy-update)

可知 wait-free 被包含在 lock-free 的範疇當中，並且等級更高。

lock-free 聽起來很不錯，能保證 thread 的進行，不過由於需要大量的 `atomic` operation 來確保操作的正確，因此實際上不一定會比較快 (甚至更慢)，並且程式碼會更加複雜，接下來會探討這些不同的機制是如何實作。



#### 正常情況

假設有個 stack，12 個 thread 瘋狂 pop 同個 stack，直覺來看最後 `top = 0` 以及 `sum = (1+2+...+49152)`，不過實際上每次出現的值都不一樣:

```c
#include <stdio.h>
#include <pthread.h>
#define MAX_SIZE 49152
#define N_THREAD 12

static int stack[MAX_SIZE];
static int top;
static int sum;
    
void init_proc()
{
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    top = 0;
    sum = 0;
    for (int i = 1; i <= MAX_SIZE; i++)
        stack[top++] = i;
    printf("top: %d, sum: %d\n", top, sum);
}

int pop()
{
    return stack[--top];
}

void *t_pop()
{
    for (int i = 0; i < MAX_SIZE / N_THREAD; i++) {
        sum += pop();
    }
}

int main()
{
    pthread_t tid[N_THREAD];

    init_proc();
    for (int i = 0; i < N_THREAD; i++)
        pthread_create(&tid[i], NULL, t_pop, NULL);
    for (int i = 0; i < N_THREAD; i++)
        pthread_join(tid[i], NULL);
    printf("top: %d, sum: %d\n", top, sum);
    return 0;
}
```

```shell
 gcc -g -o test test.c -lpthread
```



但是如果用 mutex 確保一次只會有一個 thread 執行 `sum += pop()`，就會輸出成功的結果:

```c
#include <stdio.h>
#include <pthread.h>
#define MAX_SIZE 65536
#define N_THREAD 12

static int stack[MAX_SIZE];
static int top;
static int sum;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void init_proc()
{
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    for (int i = 0; i < MAX_SIZE; i++)
        stack[i] = 0;
    top = -1;
    sum = 0;
}

void push(int v)
{
    stack[++top] = v;
}

int pop()
{
    pthread_mutex_lock(&lock);
    int tmp = top >= 0 ? stack[top--] : 0;
    pthread_mutex_unlock(&lock);
    return tmp;
}

void *t_push()
{
    pthread_mutex_lock(&lock);
    for (int i = 0; i < MAX_SIZE; i++)
        push(i);
    pthread_mutex_unlock(&lock);
}

void *t_pop()
{
    sum += pop();
}

int main()
{
    pthread_t tid[N_THREAD];
    int i = 0;

    init_proc();
    pthread_create(&tid[i++], NULL, t_push, NULL);
    
    for (; i < 3; i++)
        pthread_create(&tid[i], NULL, t_pop, NULL);
    for (int j = 0; j < i; j++)
        pthread_join(tid[j], NULL);
    printf("top: %d, sum: %d\n", top, sum);
    return 0;
}
```



而在這個情況中，用 mutex 可以保證操作的安全，但是犧牲了其他 thread 等待的時間，如果能以變數為單位去保護，執行 **atomic operation**，就能確保修改一次到位，實踐了簡單的 lockfree:

```c
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#define MAX_SIZE 49152
#define N_THREAD 12

static int stack[MAX_SIZE];
static atomic_int top;
static atomic_int sum;

void init_proc()
{
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    top = 0;
    sum = 0;
    for (int i = 1; i <= MAX_SIZE; i++)
        stack[top++] = i;
    printf("top: %d, sum: %d\n", top, sum);
}

int pop()
{
    int old_top;
    do {
        old_top = top;
    } while (!atomic_compare_exchange_weak(&top, &old_top, old_top - 1));

    return stack[old_top];
}

void *t_pop()
{
    for (int i = 0; i < MAX_SIZE / N_THREAD; i++)
        atomic_fetch_add_explicit(&sum, pop(), memory_order_relaxed);
}

int main()
{
    pthread_t tid[N_THREAD];

    init_proc();
    for (int i = 0; i < N_THREAD; i++)
        pthread_create(&tid[i], NULL, t_pop, NULL);
    for (int i = 0; i < N_THREAD; i++)
        pthread_join(tid[i], NULL);
    printf("top: %d, sum: %d\n", top, sum);
    return 0;
}
```



前面的例子為 MRSW (multiple read single write)，而如果今天是 MRMW 的話該怎麼處理? 可以使用 Double compare-and-swap (又稱作 DCAS or CAS2)，一個 CAS 檢查讀，一個 CAS 檢查寫，確保同時只能有讀 or 只能有寫，而操作的都是同一個變數:

```c
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#define MAX_SIZE 49152
#define N_THREAD 12

static int stack[MAX_SIZE];
static atomic_int top;
static atomic_int sum;
/* 最低位的 byte 是用來記錄 reader / writer */
static atomic_int flag; /* (writer cnt) --> 0000 0000 <-- (reader cnt) */

void init_proc()
{
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    top = 0;
    sum = 0;
    flag = 0;
}

void push(int v)
{
    int old_top, old_flag;

    do {
        old_top = top;
        if (old_top >= MAX_SIZE)
            return;

        old_flag = flag & (~0x0f);
        /* 如果過程中被更新 or 有 reader，則讓出 cpu 使用資源，等待下一次嘗試 */
        if (!atomic_compare_exchange_weak(&flag,
                        &old_flag, old_flag + 0x10 /* a new writer */)) {
            sched_yield();
            continue;
        }
        /* 過程中 top 已被更新，因此等待下一次機會 */
        while (!atomic_compare_exchange_weak(&top, &old_top, old_top + 1))
            sched_yield();
        break;
    } while (1);
    stack[top - 1] = v;

    /* writer leave */
    do {
        old_flag = flag;
    } while (!atomic_compare_exchange_weak(&flag, &old_flag, old_flag - 0x10));
}

void *t_push()
{
    for (int i = 1; i <= MAX_SIZE / 12; i++)
        push(i);
}

int pop()
{
    int old_top, old_flag;

    do {
        old_top = top;
        if (old_top < 0)
            return 0;

        old_flag = flag & (~0xf0);
        /* 如果過程中被更新 or 有 writer，則讓出 cpu 使用資源，等待下一次嘗試 */
        if (!atomic_compare_exchange_weak(&flag,
                        &old_flag, old_flag + 1 /* a new reader */)) {
            sched_yield();
            continue;
        }
        /* 過程中 top 已被更新，因此等待下一次機會 */
        while (!atomic_compare_exchange_weak(&top, &old_top, old_top - 1))
            sched_yield();
        break;
    } while (1);

    /* reader leave */
    do {
        old_flag = flag;
    } while (!atomic_compare_exchange_weak(&flag, &old_flag, old_flag - 1));

    return stack[old_flag - 1];
}

void *t_pop()
{
    for (int i = 0; i < MAX_SIZE / N_THREAD; i++)
        atomic_fetch_add_explicit(&sum, pop(), memory_order_relaxed);
}

int main()
{
    pthread_t tid[N_THREAD];

    init_proc();
    for (int i = 0; i < N_THREAD; i++)
        pthread_create(&tid[i], NULL, i & 1 ? t_pop : t_push, NULL);
    for (int i = 0; i < N_THREAD; i++)
        pthread_join(tid[i], NULL);
    printf("top: %d, sum: %d\n", top, sum);
    return 0;
}
```

- 不過麻煩的一點是我不知道該如何測試 MRMW 的正確性
- 沒辦法同時讀寫，只能允許一方執行