## Pwn01

```
chall: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=bfd9ad43dce52db78a625f3b2837cb420a9dc767, for GNU/Linux 3.2.0, stripped

[*] '/docker_vol/tetctf/pwn01/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

- 漏洞一：`auth()` 檢查使用者帳號密碼時使用 `strcmp()`，因此只要輸入 NULL byte 即可繞過，並以 root 的身份 (程式中) 執行讀檔操作
- 漏洞二：`login()` 時 overflow 可以蓋到 auth server IP，控制要往哪邊連線，這也可以拿來繞驗證
- 漏洞三：`read_file()` read file buffer 有 overflow，並且會將 buffer data 以 `puts()` 印出，除了可以控制 stack 的內容，也可以用來 leak



## mailservice

```
mailclient: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=18da87fb6db72ea8c9186ec0ccf0e507401e5789, stripped
[*] '/docker_vol/tetctf/user_build/mailclient'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

mailserver: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=bbf5dbe39bb06e65fb7371d6abdacd86eb5b301c, stripped
[*] '/docker_vol/tetctf/user_build/mailserver'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```



- mailclient：
  - login - 傳送 username 與 password 到 server
  - register - 傳送 username 與 password 到 server
  - send_mail - 將檔案路徑、標題與傳送對象的使用名稱送到 server
    - content_name - generate randomly
    - content_path - `/tmp/<content_name>`
    - content_size: max 2048
    - content:
      - 1 ~ 4: size
      - 5 ~: data
  - read_mail - 從 server 讀接收到的 mail，內容包含 subject 以及檔案名稱，讀取檔案後印到 stdout
- mailserver
  - login - 去 `/home/mailserver/data/users/<username>/passwd` 取得密碼並檢查
  - register - 將使用者密碼新增至 `/home/mailserver/data/users/<username>/passwd`
  - send_mail handler - 將請求儲存至檔案 `/home/mailserver/data/<user>`，內容則為 `<subject>|<content_path>`
  - read_mail handler - 將檔案 `/home/mailserver/data/<user>` 內容讀出後傳給使用者



---

- 漏洞一：server send/read mail handler 都有 path traversal
  - 搭配可以控制的 password 能構造任意的檔案內容
- 漏洞二：由於條件檢查為 `if ( (int)content_size > 2048 )`，因此大小可以塞入負數，會以字串 `-001` 儲存起來
  - 不過呼叫 read / write system call 的時候會壞掉
- 漏洞三：**subject 沒有初始化**，並且在輸入不滿足 `scanf()` 的 format 時，變數不會被更新
  - 如果可以控制內容，像是 `xxx;content_path=XXXXX`，就能控制 content_path 的路徑
  - `content_path` 控制成 `/proc/uptime` 即可做 info leak



## Game

> 參考 writeup：https://mochinishimiya.github.io/posts/tetctf2023/

題目敘述：

> I wrote a Metamod plugin to retrieve the classname of any entities on a running Sven Co-Op game server. I have installed it on my server, but something unexpected happen and I haven't got the time to test my plugin yet. Can you test it for me?

Note：

> You should research on how Metamod and Metamod plugin works, what is an "entity" in GoldSrc engine (Source Engine uses the same concept, so can refer to), what are the data structures that an entity has, the GoldSrc network protocol, etc...



題目提供了以下檔案：

- metamod.so

- note_mm.cpp

  - common implementation of Metamod's plugin interface

- note_mm.so

- Dockerfile，截取部分：
  ```dockerfile
  # 下載 steam linux cmd
  RUN curl -sqL "https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz" | tar zxvf -
  
  # 安裝到 /home/game/svends 底下
  RUN ./steamcmd.sh +force_install_dir /home/game/svends +login anonymous +app_update 276060 validate +exit
  
  # 建立 steam 環境
  RUN mkdir -p /home/game/.steam/sdk32/
  RUN ln -s /home/game/Steam/linux32/steamclient.so /home/game/.steam/sdk32/steamclient.so
  
  # 將 metamod.so 丟到 svencoop 目錄中
  WORKDIR /home/game/svends
  RUN mkdir -p svencoop/addons/metamod/dlls
  ADD --chown=game:game metamod.so /home/game/svends/svencoop/addons/metamod/dlls/metamod.so
  
  # "linux addons/note_mm/note_mm.so" 放到 plugins.ini
  RUN echo linux addons/note_mm/note_mm.so > svencoop/addons/metamod/plugins.ini
  RUN ln -s /home/game/svends/svencoop/dlls/server.so /home/game/svends/svencoop/dlls/hl_i386.so
  
  RUN mkdir svencoop/addons/note_mm
  ADD --chown=game:game note_mm.so /home/game/svends/svencoop/addons/note_mm/note_mm.so
  
  # 執行 game with metamod.so
  CMD ./svends_run -dll addons/metamod/dlls/metamod.so +sv_password $CS_PASSWORD +log on +maxplayers 8 +map stadium4
  ```



關於一些 steam server 的環境架構，可以參考：https://gkzhb.gitee.io/2019/02/sven/

- steamcmd_linux.tar.gz 本身就是提供 steam game server 的建置
- 安裝後會有 server 相關的執行檔案，包含 svends_run，即是 Sven Co-op (戰慄時空合作版) 遊戲的 server



note_mm.so 的 cehcksec：

```
[*] '/docker_vol/tetctf/game/note_mm.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```



---

- Metamod
  - An API manager，在 Half-Life 2 Engine (Source) 與 subsequent Game Modification (MOD) 間攔截操作
    - Half-Life 2 為遊戲 "戰慄時空2"
  - 可以動態載入 "Metamod:Source Plugins", written in C++, to intercept, override, and hook Engine and GameDLL API interfaces
  - [wiki](https://wiki.alliedmods.net/Metamod:Source)
    - Valve Server Plugins - built-in plugin technology for the Half-Life 2 server engine



Metamod vs. SourceMod

- Metamod:Source - C++ plugin environment for Half-Life 2
  - It acts as a "Metamod" (a term coined by Will Day) which sits in between the Game and the Engine, and allows plugins to intercept calls that flow between
  - It provides a mechanism called **SourceHook**, a very powerful library for intercepting, overridding, and superseding virtual function calls
  - Although Valve provides their own C++ plugin environment, we found two major reasons to develop Metamod:Source:
    - If separate plugins use their own hooking mechanisms, conflicts will arise. The centralized SourceHook engine solves that by providing a unified gateway for hooking.
    - Valve's layer has idiosyncracies, such as not fully unloading from memory and poor console and programmatic control.
  - 不等於 "Mani Admin Plugin," "SourceMod," or "EventScripts."
- SourceMod - an open source Half-Life 2 modification which focuses on server modification, server administration, and plugin writing
  - Plugins are scripted in the SourcePawn language, and they allow you to script actions on your server and access the Half-Life 2 (Source) engine with ease.
  - SourceMod is highly optimized and ideal for getting the most performance out of your Source servers, without the complexity of writing C++ code.



GoldSrc engine - game engine developed by Valve

- 為 Source engine 的前身

https://twhl.info/wiki/page/Half-Life_Programming_-_Getting_Started

- 關於 entity 的介紹在第三章
- PEV - Pointer to Entity Variables



---

````
svends_run -dll metamod.so ...
````

- 在啟動 server 時載入 metamod.so，而 plugins.ini 就定義了需要被 insert 的 plugin list 與對應使用平台
- 透過稍微看一下 metamod.so 的 decompile 結果能知道，在編譯 metamod.so 時會一起把執行環境給編譯進去，像是 `pluginFile` 就是 config 路徑名稱 + "plugin.ini"

參考官方的[範例](https://github.com/theAsmodai/metamod-r/blob/adc94141a4b11389ab7669034984c4d3bc13c9b3/metamod/extra/example/meta_api.cpp#L30)與 note_mm.cpp 做對照：

- `pfnGetEntityAPI2` 註解表示 "called before game"
- Meta_{Attach,Detach,Query} - 相同
- 多 export 兩個 API - `GetEntityAPI2`, `GiveFnptrsToDll`

```c
static META_FUNCTIONS gMetaFunctionTable = {
    .pfnGetEntityAPI = nullptr,
    .pfnGetEntityAPI_Post = nullptr,
    .pfnGetEntityAPI2 = GetEntityAPI2,
    .pfnGetEntityAPI2_Post = nullptr,
    .pfnGetNewDLLFunctions = nullptr,
    .pfnGetNewDLLFunctions_Post = nullptr,
    .pfnGetEngineFunctions = nullptr,
    .pfnGetEngineFunctions_Post = nullptr,
}
```

- 也就是在遊戲啟動時會呼叫 `GetEntityAPI2()`，將 `pfnConnectionlessPacket` 設為自定義的 `ConnectionlessPacket`，並且其他 entry 都清空
  ```c
  C_DLLEXPORT int GetEntityAPI2(DLL_FUNCTIONS *pFunctionTable, int *interfaceVersion) {
      if (*interfaceVersion != INTERFACE_VERSION) {
          *interfaceVersion = INTERFACE_VERSION;
          return 0;
      }
  
      memset(pFunctionTable, 0, sizeof(*pFunctionTable));
      pFunctionTable->pfnConnectionlessPacket = ConnectionlessPacket;
  
      return 1;
  }
  ```

也就是在遊戲啟動後，客戶端只能夠呼叫 `pFunctionTable->pfnConnectionlessPacket()` ---> `ConnectionlessPacket()`：

```c
static int ConnectionlessPacket(const struct netadr_s *net_from, const char *args, char *response_buffer, int *response_buffer_size) {
    edict_t *ent = ENT(atoi(++args));
    strcpy(response_buffer, STRING(ent->v.classname));
    *response_buffer_size = strlen(response_buffer);

    RETURN_META_VALUE(MRES_SUPERCEDE, 1);
}
```

- 看起來該 function 會以客戶端傳來的 value 為 entity index，並回傳對應 entity 的名稱

下一步就是想要如何觸發 `ConnectionlessPacket()` 並控制參數，writeup 中註明參考 https://developer.valvesoftware.com/wiki/Counter-Strike:_Global_Offensive_Network_Channel_Encryption，只需要送 UDP + 前面四個 bytes 為 `\xff\xff\xff\xff` 就能觸發，或其實隨便找一下 "metamod Connetionless packet" 也能搜尋到 https://github.com/dreamstalker/rehlds/blob/master/rehlds/engine/sv_main.cpp#L3173，因此當能控制傳入的參數後，就可以讓 ent 超出 entry array 範圍來 leak，得到 library 的 base address。



剛好上面找到的 code 就是呼叫 `ConnectionlessPacket()` 的地方：

```c
int SVC_GameDllQuery(const char *s)
{
	int len;
	unsigned char data[4096];
	int valid;

	if (!g_psv.active || g_psvs.maxclients <= 1)
		return 0;

	Q_memset(data, 0, sizeof(data));
	len = 2044 - sizeof(data);
    // here
	valid = gEntityInterface.pfnConnectionlessPacket(&net_from, s, (char *) &data[4], &len);
	if (len && len <= 2044)
	{
		*(uint32 *)data = 0xFFFFFFFF; //connectionless packet
		NET_SendPacket(NS_SERVER, len + 4, data, net_from);
	}
	return valid;
}
```

- `data[]` - 大小 4096 的 buffer
- `s` - 我們的 input

於是透過 leak address + offset 取得我們 input 所存放的 address 後，透過 `strcpy()` 做 overflow，透過 `system()` 執行 reverse shell 即可。

- 因為這題是 x86，因此 library address 或是其他 address 不會摻雜 NULL byte，可以用 `strcpy()` 複製

