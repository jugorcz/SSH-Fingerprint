# SSH-Fingerprint
What is fingerprint? https://en.wikipedia.org/wiki/Public_key_fingerprint
This asm code converts public key fingerpirint into ASCII-art.
To run this in DOSBox using masm (https://winworldpc.com/product/macro-assembler/5x):

    > mount c c:\
    > c:
    > cd c:\Users\...  <- place where is masm and your asembler project
    > masm project.asm
    > link project.obj
    > project.exe 1 d5293e9a8d90265d6b6bfb8abba5da23
   
Expected result:https://drive.google.com/file/d/0BxBVs4D0FSe1TERPUTB6ZHJlblE/view

    > project.exe 2 d5293e9a8d90265d6b6bfb8abba5da23

Expected result: https://drive.google.com/file/d/0BxBVs4D0FSe1ZHlma21VYy1LUjg/view?usp=sharing
Secound option makes modyfication. On each pair of bytes is made xor and the result goes to the new table. By the end, last and first byte is used do xor. In further operations program uses this new byte table.
