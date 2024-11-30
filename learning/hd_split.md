`blkid` 顯示當前有哪些 hard disk device 與對應的 ID：

```bash
sudo blkid

/dev/nvme0n1p3: UUID="TjLDJj-XTxH-li5n-QF8Z-mW87-xs1u-Y173aJ" TYPE="LVM2_member" PARTUUID="a1a5f58d-23c1-49e8-acae-14bea3ca7170"
/dev/nvme0n1p1: UUID="1541-9DEA" BLOCK_SIZE="512" TYPE="vfat" PARTUUID="5f3a42de-940e-4ced-ba86-64bf01a6824f"
/dev/nvme0n1p2: UUID="696fcd06-1d49-44d6-9827-5249c0567ecb" BLOCK_SIZE="4096" TYPE="ext4" PARTUUID="37c75a13-84b7-4094-a98f-4b72fa31dbaf"
/dev/mapper/ubuntu--vg-ubuntu--lv: UUID="7f67520c-958a-49e5-b93f-3126f4914656" BLOCK_SIZE="4096" TYPE="ext4"
/dev/sda: PTUUID="0cc2c46a-fa9d-4241-a8b1-38118d893798" PTTYPE="gpt"
```



`fdisk` 可以印出 disk 的資訊，像是所有大小，以及切割方式：

```bash
sudo fdisk -l

Disk /dev/nvme0n1: 953.87 GiB, 1024209543168 bytes, 2000409264 sectors
Disk model: INTEL SSDPEKNW010T9
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: C5CAC065-42A9-4D8F-89E7-A5BE208F6B08

Device           Start        End    Sectors   Size Type
/dev/nvme0n1p1    2048    2203647    2201600     1G EFI System
/dev/nvme0n1p2 2203648    6397951    4194304     2G Linux filesystem
/dev/nvme0n1p3 6397952 2000406527 1994008576 950.8G Linux filesystem


Disk /dev/mapper/ubuntu--vg-ubuntu--lv: 355.25 GiB, 381442588672 bytes, 745005056 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/sda: 1.82 TiB, 2000398934016 bytes, 3907029168 sectors
Disk model: ST2000DM008-2FR1
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 4096 bytes
I/O size (minimum/optimal): 4096 bytes / 4096 bytes
Disklabel type: gpt
Disk identifier: 0CC2C46A-FA9D-4241-A8B1-38118D893798
```

- SSD - /dev/nvme0n1
- virtual disk - /dev/mapper/ubuntu--vg-ubuntu--lv
- HDD - /dev/sda



`vgs` 查看 volume group：

```bash
sudo vgs
  VG        #PV #LV #SN Attr   VSize    VFree
  ubuntu-vg   1   1   0 wz--n- <950.82g 595.57g
```



`vgdisplay` 印出更詳細的資訊：

```bash
sudo vgdisplay
  --- Volume group ---
  VG Name               ubuntu-vg
  System ID
  Format                lvm2
  Metadata Areas        1
  Metadata Sequence No  3
  VG Access             read/write
  VG Status             resizable
  MAX LV                0
  Cur LV                1
  Open LV               1
  Max PV                0
  Cur PV                1
  Act PV                1
  VG Size               <950.82 GiB
  PE Size               4.00 MiB
  Total PE              243409
  Alloc PE / Size       90943 / <355.25 GiB
  Free  PE / Size       152466 / 595.57 GiB
  VG UUID               qzf3cn-3RGN-oncy-m4EP-F2KJ-KnTZ-xpBWUx
```



`lsblk` 印出切割方式與掛載點：

```bash
lsblk

NAME                      MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS
sda                         8:0    0   1.8T  0 disk
nvme0n1                   259:0    0 953.9G  0 disk
├─nvme0n1p1               259:1    0     1G  0 part /boot/efi
├─nvme0n1p2               259:2    0     2G  0 part /boot
└─nvme0n1p3               259:3    0 950.8G  0 part
  └─ubuntu--vg-ubuntu--lv 253:0    0 355.2G  0 lvm  /
```



`lvextend` 將 logical volume 做擴充，將還沒分配到的空間 (nvme0n1p3) 再擴充給現有的 block (ubuntu--vg-ubuntu--lv)：

```bash
lvextend -l +30%FREE /dev/ubuntu-vg/ubuntu-lv
resize2fs /dev/ubuntu-vg/ubuntu-lv
```

