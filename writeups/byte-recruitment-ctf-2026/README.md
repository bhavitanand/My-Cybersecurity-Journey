# [BYTE Cybersecurity Recruitment Task 2026](https://bytesoc.dev/tasks/cybersecurity)

**Date Completed:** 4/10/2026
**Difficulty:** Beginner–Intermediate
**Format:** Multi-domain CTF (Cryptography, Steganography, Binary Exploitation)
**Context:** Society recruitment challenge
**Status:** Completed (All tasks solved)

---

## Summary

This write-up documents my attempt at BYTE's cybersecurity recruitment CTF, covering **cryptography, steganography, and binary exploitation (pwn)**. My background going in was mostly networking, cryptography and forensics-oriented, so pwn and stego especially were outside my comfort zone, since I've historically avoided them in past CTFs.

Each task forced a different kind of thinking:

- **Cryptography** required recognizing when a known plaintext (the expected flag format) could be used to crack an unknown cipher layer
- **Steganography** required understanding the raw PNG file format well enough to manually patch a corrupted file byte-by-byte
- **Binary Exploitation** required reading x86 disassembly, understanding stack layout, and writing/running a real exploit against a live remote service

I used Claude for parts of this, mainly to help write the exploit script for Task 3, since scripting isn't my strong suit yet, and as a guide for tools/workflow on stego, which I have ~zero prior experience with. I made sure to understand the reasoning behind every step rather than blind copy-pasting; the crypto key derivation in Task 1 specifically was something I worked out myself from the pattern in the output.

---

## Challenge Breakdown

| Task   | Category            | Focus                                                |
| ------ | ------------------- | ---------------------------------------------------- |
| Task 1 | Cryptography        | Base64 + known-plaintext Vigenère cracking           |
| Task 2 | Steganography       | PNG chunk structure corruption + manual repair       |
| Task 3 | Binary Exploitation | Stack buffer overflow (ret2win), remote exploitation |

<img width="1500" height="682" alt="Image 1" src="https://github.com/user-attachments/assets/ef847234-cfee-41f9-ae5e-9039b187ffab" />

---

## Task 1 — Cryptography

### Problem Statement

A short string of challenge text was given, with the flag stated to be in the format `BYTE{...}`.

**Goal:** Decode/decrypt the string to recover the flag.

---

### Approach & Analysis

The challenge text looked like Base64 at a glance (mixed-case alphanumerics with no obvious separators).

Steps taken:

1. Ran the challenge text through CyberChef's **"From Base64"** recipe.

<img width="1327" height="757" alt="Image 2" src="https://github.com/user-attachments/assets/26afaa4b-4838-41af-8c0b-4a1c6692c96e" />

2. The output was readable-ish (letters, digits, underscores, curly braces) but started with `BAIN{` instead of the expected `BYTE{` — so Base64 alone wasn't the whole cipher. There was a second layer on top, applied _before_ the Base64 encoding.

3. First ruled out the obvious simple options:
   - A single Caesar shift — doesn't work, because the shift needed to turn each letter of `BAIN` into the matching letter of `BYTE` isn't constant (B→B is a shift of 0, but A→Y and I→T and N→E are different shifts each)
   - Atbash, ROT47, plain reversal; none of these reproduced `BYTE{` either

<img width="1507" height="777" alt="Image 3" src="https://github.com/user-attachments/assets/f902a52d-c366-47a5-a02e-1629e0f76487" />
<img width="1272" height="751" alt="Also Image 3" src="https://github.com/user-attachments/assets/c301cae2-d5e7-40da-b37e-c6a86b096978" />

4. Since I _knew_ the plaintext had to start with `BYTE{` (known-plaintext/crib), and the ciphertext from step 1 started with `BAIN{`, I used that as a crib to back out a Vigenère key by hand:

   For each of the first 4 letters, `key_letter = (cipher_letter − plain_letter) mod 26`:

   | Position | Plaintext | Ciphertext | Shift (key letter) |
   | -------- | --------- | ---------- | ------------------ |
   | 0        | B         | B          | 0 → **A**          |
   | 1        | Y         | A          | 2 → **C**          |
   | 2        | T         | I          | 15 → **P**         |
   | 3        | E         | N          | 9 → **J**          |

   That gives a 4-letter repeating key: **`ACPJ`**.

5. Plugged `ACPJ` into CyberChef's **"Vigenère Decode"** operation (key = `ACPJ`), applied to the full Base64-decoded string:

<img width="1350" height="775" alt="Image 4" src="https://github.com/user-attachments/assets/233dfc3a-f976-467b-a6af-aa4679677b04" />
<img width="1752" height="916" alt="Also Image 4" src="https://github.com/user-attachments/assets/2bb992ec-c480-4286-916a-aacb6de1cd7d" />

6. This produced a clean `BYTE{...}` flag. One nice confirmation that this was the right key (and not a coincidence): one segment of the decoded flag, `bY73`, reads as the word **"byte"** in leetspeak (7→T, 3→E).. a thematically perfect easter egg for a flag from the BYTE society, and not something that would show up from a wrong key.

---

### Result

**Flag:**
`BYTE{bY73_B8I_ApsYC_V4jXcB}`

---

### Reflection

This was the task I was somewhat confident going in, since cryptography is something I really enjoy working with. Although I got a bit side-tracked initially, what eventually saved it was treating the _expected flag format_ itself as information instead of trying to brute-force an unknown cipher or just purely relying on the "Magic" function of CyberChef. Using the known `BYTE{` prefix as a crib turned an open-ended guessing problem into a solvable equation. That's a technique (known-plaintext attack) I remember applying in a few CTFs before this challenge.

---

## Task 2 — Steganography

### Problem Statement

A PNG file was provided, described as "corrupted." The flag was stated to be in the format `flag{...}`.

**Goal:** Repair/analyze the file to recover the hidden flag.

---

### Approach & Analysis

I have close to no prior stego experience, so I started from the file format itself rather than a specific stego tool. A PNG is just a signature followed by a sequence of length prefixed "chunks" like IHDR, IDAT, IEND, etc. each with its own CRC checksum, so 'corrupted" usually means something is wrong at that structural level.

Steps taken:

1. Ran `pngcheck -v` (and opened the file in a hex editor, HxD) against the file to see what it flagged.

<img width="2557" height="1437" alt="Image 5" src="https://github.com/user-attachments/assets/987fe280-e347-4def-92a0-63a17f25b73c" />

2. Searched the raw hex for the literal chunk-type markers (`IDAT`, `IEND`) rather than trusting the declared chunk-length fields, and compared their real spacing against what the lengths claimed. This exposed a **fake 12-byte `IEND` chunk** (a zero-length IEND, complete with its standard checksum `AE 42 60 82`) spliced into the middle of one of the real `IDAT` chunks — enough to make naive parsers think the file ends early.

<img width="1236" height="217" alt="Image 6" src="https://github.com/user-attachments/assets/8ea05e6f-c25c-4c87-ab54-84e231556443" />
<img width="1247" height="362" alt="Also Image 6" src="https://github.com/user-attachments/assets/81ac3c21-44da-4cd6-89e5-fe241231d31c" />

3. Removed those 12 bytes (wrote a short Python script to do the byte surgery cleanly, rather than editing raw hex by hand). Confirmed each chunk's CRC with a script afterward — the `IHDR` chunk's checksum was _also_ invalid, which I patched by recomputing it.

<img width="2496" height="460" alt="Image 7" src="https://github.com/user-attachments/assets/f25137a5-a5df-4dd3-8564-0e9dbd2097cb" />

4. Even after both fixes, the file loaded — but the decompressed pixel data was larger than the declared `724×800` dimensions should produce. Dividing the leftover bytes by the per-row size (`width*3 + 1`) gave exactly 50 extra rows — meaning the real image was **850px tall**, and the header was lying about the height to hide the bottom strip from ever being rendered.

<img width="724" height="800" alt="Image 8" src="https://github.com/user-attachments/assets/759cd74c-3045-4eed-8e0a-3b0725b7ca76" />

5. Patched the `IHDR` height field, recomputed its CRC, and re-rendered. The newly revealed bottom 50px strip had the flag printed in plain text.

<img width="724" height="191" alt="Image 9" src="https://github.com/user-attachments/assets/872624b5-1316-4eb8-af1b-aa8d6ddebdde" />

---

### Result

**Flag:**
`flag{g0t_1t_in_pLAin_sight}`

---

### Reflection

Going in, I expected stego to mean pixel-level tricks (LSB encoding, etc.) although this one turned out to be entirely about the _container format_ rather than the image data itself, which honestly played more to my forensics background than I expected. The flag's own text (`g0t_1t_in_pLAin_sight`) is a fitting joke as the "hidden" data wasn't encoded at all, it was just sitting past where the file header told viewers to stop looking. (thanks guys haha)

---

## Task 3 — Binary Exploitation

### Problem Statement

A dummy 32-bit Linux binary was provided locally, with the real challenge running as a remote service (`nc cybersub.bytesoc.dev 9999`). The local binary's flag is fake; the goal is to find and trigger the vulnerability locally, then exploit the real remote instance.

**Goal:** Exploit a buffer overflow to reach a hidden `win()` function and print the flag.

---

### Approach & Analysis

1. Checked the binary's protections and disassembled it (Ghidra/objdump) to find the vulnerable function.

<img width="1307" height="287" alt="Image 10" src="https://github.com/user-attachments/assets/a1efd456-ac28-445f-ad20-698848579e3c" />

2. Found `vuln()`: it reads up to 200 bytes (`read(0, buf, 0xc8)`) into a 68-byte stack buffer — no bounds checking, classic stack buffer overflow. Also found a `win()` function that's never called during normal execution but is clearly meant to print the flag.

<img width="2226" height="1360" alt="image" src="https://github.com/user-attachments/assets/f99e0f4e-c34b-472c-b4da-ec1bc7141179" />
<img width="2397" height="1393" alt="image" src="https://github.com/user-attachments/assets/c1dc4916-560c-4c16-8048-921519e1beb0" />

3. Worked out the stack layout: 68 bytes of buffer + 4 bytes saved `ebx` + 4 bytes saved `ebp` = **76 bytes** before hitting the saved return address. Since there's no PIE/ASLR to defeat, `win()` sits at a fixed, known address.

4. I'm not strong at scripting yet, so I used Claude to help write the exploit in Python (pwntools), the logic (pad to the return address, overwrite it with `win()`'s address) is something I understood and directed; I'm just not confident enough yet to have written the pwntools boilerplate from scratch myself.

```python
from pwn import *

context.arch = 'i386'
elf = context.binary = ELF('./chall', checksec=False)
win_addr = elf.symbols['win']

OFFSET = 76
payload = b"A" * OFFSET + p32(win_addr)

io = remote('cybersub.bytesoc.dev', 9999)
io.sendline(payload)
print(io.recvall(timeout=3).decode())
```

5. Tested locally against the dummy binary first to confirm the offset was right (`win()` triggered, printed the placeholder `FLAG_NOT_SET`), then ran it against the real remote service.

<img width="1279" height="379" alt="image" src="https://github.com/user-attachments/assets/b97a37ce-e61d-40f3-be0c-7ec2bca519d9" />

---

### Result

**Flag:**
`BYTE{Buff3r_OverFl0w_k3_N45he}`

---

### Reflection

This was my first time going from "read the disassembly" to "write and run a working remote exploit" rather than following a guided walkthrough. The concept (overflow a buffer to control the return address) made sense quickly from a DFIR angle — I already think about memory/stack layout from a forensics lens — but translating that understanding into working exploit code is a gap I want to close by actually learning pwntools properly rather than leaning on AI for it next time.

---

## Overall Takeaways

- Known-plaintext / crib-based thinking is a genuinely useful crypto technique, not just a "cheat"
- File-format-level forensics (chunk structure, headers, checksums) transfers surprisingly well into stego
- I can read and reason about a binary vulnerability competently; I need to build independent scripting fluency so I'm not relying on AI assistance for exploit code
- "Corrupted" doesn't always mean complex — two of three tasks here came down to a file lying about its own structure

---

## Tools & Platforms Used

- CyberChef (Base64 decoding, Vigenère decode)
- Hex editor (HxD) / `pngcheck`
- Python (short patch/CRC scripts for Task 2; pwntools for Task 3)
- Ghidra / objdump (disassembly for Task 3)
- Netcat / pwntools `remote()` for the live service
- Claude, specifically for help writing the Task 3 exploit script and as a guide for stego tooling/workflow, since I have limited prior experience in both areas

---

## What I'll Improve Before the Next CTF

- Build real pwntools/scripting fluency instead of leaning on AI for exploit code
- Get more deliberate practice with classical/layered ciphers so crypto stops being my weak point
- Keep leaning into file-format-level forensics — it's clearly a strength

---

## Closing Note

Three very different domains, three very different ways of getting stuck — and in each case, the unlock was questioning an assumption the challenge wanted me to make (that the cipher had to be guessed blind, that the image was broken rather than lying, that exploitation required more scripting skill than I currently have rather than just understanding the primitive). Write-ups like this are part of how I track that.
