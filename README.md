# CRC32_API

New and better alternative for [x86 block_api.asm](https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm) and [x64 block_api.asm](https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/block/block_api.asm) files. By changing the Windows API name hashing method it is possible to trim 1 byte for every x86 Windows shellcode and 4 byte from all x64 Windows shellcode. Because most of the security products are searching for well known ROR13 hashes of Windows API function names, changing the Windows API name hashing method will decreases the detection rate of Metasploit Windows shellcodes. Also new method in this proposal have much less colision rate compared to ROR13. 

## Prior Work & References 
Following DEFCON 25 talk mentions about AV products detecting the metasploit shellcodes by searching for well known ROR13 hashes of Windows API function names.

* https://www.youtube.com/watch?v=jk1VAuPH4-w
* https://github.com/secretsquirrel/fido/blob/master/Defcon_25_2017.pdf 

## New Hashing Method
I have taken advantage of [CRC32](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf#page=327&zoom=100,61,88) instruction for calculating the  CRC32 (polynomial
11EDC6F41H) value of the Windows `[MODULE_NAME+NULL+FUNCTION_NAME]` (same as old block_api.asm). By simply changing the ROR13 hashes with CRC32 values crc32_api.asm will find the desired function address with exact same way that old `block_api.asm` uses. No additional registers are changed. I have tested both of the crc32_api.asm for all existing Windows shellcode inside Metasploit and it works without any error. [crc32_hash.py](https://github.com/EgeBalci/CRC32_API/crc32_hash.py) file can be used to calculate a CRC32 value of given input same as [hash.py](https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/hash.py).

![image](https://user-images.githubusercontent.com/17179401/85612965-0e3ab480-b662-11ea-8ac5-94148127e932.png)

## BUT ! Here's the catch.
`CRC32` instruction is a fairly new instruction. It is added with [SSE4](https://en.wikipedia.org/wiki/SSE4) so it may cause problems in older CPUs. Any model manufactured after 2006 seems to be working fine but I don't know what happens when you run a unsupported instruction on a old CPU, simply couldn't find old enough hardware for testing ¯\_(ツ)_/¯ 
