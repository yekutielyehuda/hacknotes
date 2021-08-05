# Debuggers & Decompilers

## Wasm decompiler / Wat compiler

Software:

{% embed url="https://github.com/wwwg/wasmdec" %}

## DNSpy Debugging

[DNSpy ](https://github.com/dnSpy/dnSpy)is a debugger and .NET assembly editor. You can use it to edit and debug assemblies even if you don't have any source code available. 

## Java decompiler

​If you need to decompile a Java program, you can do so with these tools:

{% embed url="https://github.com/java-decompiler/jd-gui" %}

{% embed url="https://github.com/skylot/jadx" %}

## Debugging DLLs

### Using IDA

* **Load rundll32** \(64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe\)
* Select **Windbg** debugger
* Select "**Suspend on library load/unload**".

### Using x64dbg/x32dbg

* **Load rundll32** \(64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe\)
* **Change the Command Line** \( _File --&gt; Change Command Line_ \) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\14.ridii\_2.dll",DLLMain
* Change _Options --&gt; Settings_ and select "**DLL Entry**".
* Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

## ARM & MIPS

arm\_now is a qemu powered tool that allows instant setup of virtual machines on arm cpu, mips, powerpc, nios2, x86 and more, for reverse, exploit, fuzzing and programming purpose. arm\_now is a qemu powered tool that allows instant setup of virtual machines on arm cpu, mips, powerpc, nios2, x86 and more, for reverse, exploit, fuzzing and programming purpose.

{% embed url="https://github.com/nongiach/arm\_now" %}

## Shellcodes

### Debugging a shellcode with blobrunner

​[**Blobrunner**](https://github.com/OALabs/BlobRunner) will **allocate** the **shellcode** inside a space of memory, will **indicate** you the **memory address** were the shellcode was allocated and will **stop** the execution. Then, you need to **attach a debugger** \(Ida or x64dbg\) to the process and put a **breakpoint the indicated memory address** and **resume** the execution. This way you will be debugging the shellcode.

### Debugging a shellcode with jmp2it

**​**[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) is very similar to blobrunner. It will **allocate** the **shellcode** inside a space of memory, and start an **eternal loop**. You then need to **attach the debugger** to the process, **play start wait 2-5 secs and press stop** and you will find yourself inside the **eternal loop**. Jump to the next instruction of the eternal loop as it will be a call to the shellcode, and finally you will find yourself executing the shellcode.

### Debugging shellcode using Cutter

**​**[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is the GUI of radare. Using cutter you can emulate the shellcode and inspect it dynamically.

### Deobfuscating shellcode and getting executed functions

You should try [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152). It will tell you things like **which functions** is the shellcode using and if the shellcode is **decoding** itself in memory.

```text
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)​

This ofuscator change all the instructions for `mov`. It also uses interruptions to change executions flows. 

If you are lucky [demovfuscator](https://github.com/kirschju/demovfuscator) will deofuscate the binary. It has several dependencies

```text
apt-get install libcapstone-dev
apt-get install libz3-dev
```

And [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) \(`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`\)

If you are playing a **CTF, this workaround to find the flag** could be very useful: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Delphi

For Delphi compiled binaries you can use [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

## **References**

**HackTricks:**

{% embed url="https://book.hacktricks.xyz/" %}

​

