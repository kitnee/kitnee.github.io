---
title: "CSCV 2026 Final — FOR02"
description: "Writeup bài FOR02 vòng Chung kết CSCV 2026: khôi phục dữ liệu từ workstation bị xóa sạch."
pubDate: 2026-10-18
lang: en
category: writeup
ctf: "CSCV 2026 Final"
tags:
  - "Writeup"
  - "Forensics"
  - "CSCV2026"
  - "Final"
---

## FOR02

* **Scenario:** A workstation holding internal data was compromised. The attacker wiped the data and overwrote all free disk space to make recovery impossible. It is known that a very important text file once existed on the data partition but no longer does. Recover the full directory path of that file.
* **Flag format:** `CSCV2026{<full_filepath>}`

### Investigation
We are given a `6.8 GB` disk image `.E01` of the workstation:

![](/images/posts/cscv-for02/pic1.png)

The disk size is quite heavy, right? But I guess that's just for demotivation, the challenge itself is quite ez tho. Opened the disk using `FTK Imager`:

![](/images/posts/cscv-for02/pic2.png)

As you can see, almost all data had been wiped from this disk, as the scenario said; however, there are some important files the attacker forgot to delete: `$MFT` and `$UsnJrnl`:

![](/images/posts/cscv-for02/pic3.png)

![](/images/posts/cscv-for02/pic4.png)

I extracted `$MFT` and `$J` from the alternate data stream of `$UsnJrnl`, using `MFTECmd` developed by `Eric Zimmerman` to parse them to CSV files:

![](/images/posts/cscv-for02/pic5.png)

Using `Timeline Explorer` to open the `$J` parsed file and search for `.txt` extension:

![](/images/posts/cscv-for02/pic6.png)

At record numbers `672-681` and `710`, I found a suspicious file named `playlist_balladsong.txt`, and the file itself was deleted:

![](/images/posts/cscv-for02/pic7.png)

Normally, when parsing `$J` with `$MFT` together, the parent path of the file should be resolved; however, in this disk, the folder containing the file was also deleted and overwritten, so the tool can't resolve this path anymore. However, it's still able to keep the `ParentEntryNumber` as well as `ParentSequenceNumber` of this file:

> *ParentEntryNumber:* The MFT record index of the parent directory containing the file.

> *ParentSequenceNumber:* A counter tracking how many times the parent directory's MFT record has been reused, combined with the entry number to prevent false path resolution when MFT entries are overwritten.

So we just need to do a backtrack homework until the root archive to find the full path:

![](/images/posts/cscv-for02/pic8.png)

![](/images/posts/cscv-for02/pic9.png)

![](/images/posts/cscv-for02/pic10.png)

![](/images/posts/cscv-for02/pic11.png)

![](/images/posts/cscv-for02/pic12.png)

![](/images/posts/cscv-for02/pic13.png)

The `EntryNumber = 5` stands for the root archive, which means we have reached the full path of the deleted file, it's `\Archive\legal_14\proj_F3\vault_CA\ops_7B\playlist_balladsong.txt`.

> In NTFS architecture, the first 16 MFT records (0-15) are strictly reserved for system metadata files, where Entry Number 5 is hardcoded as the root directory (.) of the volume.

### Flag
* The flag is: `CSCV2026{\Archive\legal_14\proj_F3\vault_CA\ops_7B\playlist_balladsong.txt}`
