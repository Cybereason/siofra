# Summary

Siofra is a tool designed to identify and exploit DLL hijacking vulnerabilities 
in Windows programs. It is able to simulate the Windows loader in order to give 
visibility into all of the dependencies (and corresponding vulnerabilities) of 
a PE on disk, or alternatively an image file in memory corresponding to an active 
process. More significantly, the tool has the ability to easily generate DLLs to 
exploit these types of vulnerabilities via PE infection with dynamic shellcode creation. 
These infected DLLs retain the code (DllMain, exported functions) as well as the 
resources of a DLL to seamlessly preserve the functionality of the application loading 
them, while at the same time allowing the researcher to specify an executable payload 
to be either run as a separate process or loaded into the target as a module. Additionally, 
the tool contains automated methods of combining UAC auto-elevation criteria with 
the aforementioned functionality in order to scan for UAC bypass vulnerabilities.

# Vulnerabilities

At present, there is a very large number of vulnerabilities which this tool exposes. 
While testing this tool I encountered only several applications which were not vulnerable 
out of hundreds which I tested against. Note that these vulnerabilities can be exploited 
despite SafeDllSearchMode. A common misconception results from confusing the "current 
directory" (fixed with SafeDllSearchMode) with the "application directory" (the 
folder containing the .exe itself). The vast majority of DLL hijacking vulnerabilities 
currently present in Windows programs stem from the application directory (which 
comes first in the Windows search order). Several highlights are listed below in 
the output produced by the scanner in the tool. The last time these vulnerabilities 
were tested was in mid-July 2017.

* Application name: Internet Explorer
* Tested on OS: Windows 10 x64 Home/Pro
* Command/output: 

Siofra64.exe --mode file-scan -f "c:\Program Files\Internet Explorer\iexplore.exe" 
--enum-dependency --dll-hijack

======== c:\Program Files\Internet Explorer\iexplore.exe [64-bit PE] ========
iexplore.exe
    USER32.dll [KnownDLL]
        win32u.dll [Base]
        api-ms-win-core-privateprofile-l1-1-1.dll [API set]
            kernel32.dll [KnownDLL]
        GDI32.dll [KnownDLL]
            api-ms-win-gdi-internal-uap-l1-1-0.dll [API set]
                gdi32full.dll [Base]
                    msvcp_win.dll [Base]
                        api-ms-win-crt-string-l1-1-0.dll [API set]
                            ucrtbase.dll [Base]
    msvcrt.dll [KnownDLL]
    api-ms-win-downlevel-shell32-l1-1-0.dll [API set]
        shcore.dll [KnownDLL]
            RPCRT4.dll [KnownDLL]
            combase.dll [KnownDLL]
                bcryptPrimitives.dll [Base]
    ADVAPI32.dll [KnownDLL]
        api-ms-win-eventing-controller-l1-1-0.dll [API set]
            sechost.dll [KnownDLL]
    iertutil.dll [!]

[!] Module iertutil.dll vulnerable at c:\Program Files\Internet Explorer\iertutil.dll 
(real path: C:\WINDOWS\system32\iertutil.dll)

* Application name: Windows Defender
* Tested on OS: Windows 10 x64 Home/Pro
* Command/output: 

Siofra64.exe --mode file-scan -f "c:\Program Files\Windows Defender\MpCmdRun.exe" 
--enum-dependency --dll-hijack

======== c:\Program Files\Windows Defender\MpCmdRun.exe [64-bit PE] ========
MpCmdRun.exe
    msvcrt.dll [KnownDLL]
    KERNEL32.dll [KnownDLL]
    OLEAUT32.dll [KnownDLL]
        msvcp_win.dll [Base]
            api-ms-win-crt-string-l1-1-0.dll [API set]
                ucrtbase.dll [Base]
        combase.dll [KnownDLL]
            RPCRT4.dll [KnownDLL]
            bcryptPrimitives.dll [Base]
    ADVAPI32.dll [KnownDLL]
        api-ms-win-eventing-controller-l1-1-0.dll [API set]
            sechost.dll [KnownDLL]
    OLE32.dll [KnownDLL]
        GDI32.dll [KnownDLL]
            api-ms-win-gdi-internal-uap-l1-1-0.dll [API set]
                gdi32full.dll [Base]
                    USER32.dll [KnownDLL]
                        win32u.dll [Base]
    SspiCli.dll [!]
    mpclient.dll [!]
        CRYPT32.dll [Base]
            MSASN1.dll [Base]
    WINTRUST.dll [Base]

[!] Module SspiCli.dll vulnerable at c:\Program Files\Windows Defender\SspiCli.dll 
(real path: C:\WINDOWS\system32\SspiCli.dll)

* Application name: WMI
* Tested on OS: Windows 10 x64 Home/Pro
* Command/output: 

Siofra64.exe --mode file-scan -f "c:\WINDOWS\System32\wbem\wmiprvse.exe" --enum-dependency 
--dll-hijack

======== c:\WINDOWS\System32\wbem\wmiprvse.exe [64-bit PE] ========
wmiprvse.exe
    msvcrt.dll [KnownDLL]
    FastProx.dll [!]
        wbemcomn.dll [!]
            bcrypt.dll [!]
            WS2_32.dll [KnownDLL]
                api-ms-win-eventing-obsolete-l1-1-0.dll [API set]
                    sechost.dll [KnownDLL]
                        RPCRT4.dll [KnownDLL]
                        api-ms-win-core-heap-obsolete-l1-1-0.dll [API set]
                            kernel32.dll [KnownDLL]
    NCObjAPI.DLL [!]

[!] Module wbemcomn.dll vulnerable at c:\WINDOWS\System32\wbem\wbemcomn.dll (real 
path: C:\WINDOWS\system32\wbemcomn.dll)
[!] Module bcrypt.dll vulnerable at c:\WINDOWS\System32\wbem\bcrypt.dll (real path: 
C:\WINDOWS\system32\bcrypt.dll)
[!] Module NCObjAPI.DLL vulnerable at c:\WINDOWS\System32\wbem\NCObjAPI.DLL (real 
path: C:\WINDOWS\system32\NCObjAPI.DLL)

* Application name: Windows Search Indexer/Search Protocol Host
* Tested on OS: Windows 10 x64 Home/Pro
* Command/output: 

Siofra64.exe --mode file-scan -f "c:\WINDOWS\System32\SearchProtocolHost.exe" --enum-dependency 
--dll-hijack --explicit-loadlibrary

======== c:\WINDOWS\System32\SearchProtocolHost.exe [64-bit PE] ========
SearchProtocolHost.exe
    msvcrt.dll [KnownDLL]
    TQUERY.DLL [!]
        OLEAUT32.dll [KnownDLL]
            msvcp_win.dll [Base]
                api-ms-win-crt-string-l1-1-0.dll [API set]
                    ucrtbase.dll [Base]
            combase.dll [KnownDLL]
                RPCRT4.dll [KnownDLL]
                api-ms-win-core-heap-obsolete-l1-1-0.dll [API set]
                    kernel32.dll [KnownDLL]
                bcryptPrimitives.dll [Base]
        cryptdll.dll [!]
    api-ms-win-security-lsalookup-l2-1-1.dll [API set]
        advapi32.dll [KnownDLL]
            api-ms-win-eventing-controller-l1-1-0.dll [API set]
                sechost.dll [KnownDLL]
    api-ms-win-shell-namespace-l1-1-0.dll [API set]
        windows.storage.dll [Base]
            api-ms-win-shlwapi-winrt-storage-l1-1-1.dll [API set]
                shlwapi.dll [KnownDLL]
                    GDI32.dll [KnownDLL]
                        api-ms-win-gdi-internal-uap-l1-1-0.dll [API set]
                            gdi32full.dll [Base]
                                USER32.dll [KnownDLL]
                                    win32u.dll [Base]
            api-ms-win-appmodel-state-l1-2-0.dll [API set]
                kernel.appcore.dll [Base]
            api-ms-win-shcore-path-l1-1-0.dll [API set]
                shcore.dll [KnownDLL]
            api-ms-win-power-base-l1-1-0.dll [API set]
                powrprof.dll [Base]
            profapi.dll [Base]
    msfte.dll [Potential explicit Unicode] [!]
    msTracer.dll [Potential explicit Unicode] [!]
    Msidle.dll [Potential explicit Unicode] [!]
    winhttp.dll [Potential explicit Unicode] [!]

[!] Module msfte.dll vulnerable at C:\WINDOWS\system32\msfte.dll (real path: Unknown)
[!] Module msTracer.dll vulnerable at C:\WINDOWS\system32\msTracer.dll (real path: 
Unknown)

# Capabilities

The capabilities of this tool can be split into 3 separate categories, each corresponding 
to one of the execution modes of this tool.

  ## Infection mode
  
  When in infection mode, the tool is capable of generating infected copies of both 
  32 and 64-bit DLL files. These infected files are able to hijack the execution flow 
  of a target application when they are loaded during process initialization, causing 
  either a payload DLL to be loaded or a payload executable to be launched prior to 
  the execution of the target application entry point.
  
  ## File scanning mode
  
  When in file scanning mode, the tool may be given either an executable file path 
  or a folder (which will be searched for executable files, optionally with recursion) 
  which will recursively have its PE imports, delay load imports, API sets, assembly 
  dependencies, and explicitly loaded libraries enumerated and processed to determine 
  the path at which each will be loaded during runtime process initialization. With 
  this information, the tool is able to identify modules which are vulnerable to hijacking. 
  During PE processing and loader simulation, the tool is capable of handling:
    1. Modules imported using the primary PE imports section.
    2. Modules imported via delay load.
    3. WinSxS assembly dependency resolution (the PE manifest resource is parsed, assembly 
       dependency IDs are extracted, and the WinSxS module path is identified using
       a custom implementation).
    4. Explicitly loaded modules, imported via LoadLibrary at runtime.
    5. API set resolution of all of the above import types. This is achieved via a 
       custom implementation of a parser for the undocumented data structures found in 
       ApiSetSchema.dll (note that only versions 2, 4 and 6 have been tested).
    6. Searching for specific imported modules by name.
    7. Identifying Windows components which can be leveraged for UAC bypass attacks 
       (the UAC auto-elevation criteria are applied to a specified target PE in an
       automated way, then used in conjunction with a hijacking attack if one is present).
    8. Automatically detect and filter module dependencies which are not
       vulnerable on the basis of:
         * KnownDLLs
         * Exempt ("Base") DLL status. Kernelbase.dll, ntdll.dll, etc.
         * Manifest override security mechanism (used by Microsoft in sysprep.exe)
  
  ## Memory scanning mode
  
  When in memory scanning mode, the tool can either enumerate local process names/IDs 
  or it can be given a process ID to scan. Rather than parsing the image file corresponding 
  to the given PID on disk, the tool will enumerate the modules currently loaded into 
  the process and identify which of them may be vulnerable to hijacking. This is useful 
  in instances where an executable on disk is packed/obfuscated and its imports cannot 
  be identified through parsing the PE header.

# Usage

In order to display the tool usage information, simply run it with no parameters 
(output shown below). It is very important to use the appropriate compilation of 
the tool (32 or 64-bit) for the desired target depending upon whether it is a 32-bit PE 
or 64-bit PE file. Similarly, the 32-bit version of the tool can only enumerate and/or 
target 32-bit processes (Wow64 on an x64 OS) and the 64-bit version can only enumerate 
and/or target 64-bit processes. This principle applies both to scanning (Siofra64.exe 
will skip 32-bit PE and Siofra32.exe will skip 64-bit PE) and to PE infection. Siofra32.exe 
should be used to infect 32-bit DLLs and Siofra64.exe should be used to infect 64-bit 
DLLs.

When the 32-bit version of the tool is run on x64 systems Wow64 path redirection 
is explicitly disabled by the tool, which means that if you were to target \Windows\System32\notepad.exe 
it would be a 64-bit PE (and therefore \Windows\Syswow64\notepad.exe should be used instead). 
Similarly if you were to target \Program Files\Common Files\microsoft shared\MSInfo\msinfo32.exe 
it would be a 64-bit PE, and therefore \Program Files (x86)\Common Files\microsoft shared\MSInfo\msinfo32.exe 
should be used instead.

Siofra version 1.13 usage: Siofra32.exe --mode [Supported modes: "file-scan", "mem-scan" 
and "infect"] -v [Optional. Output verbosity level]
    Verbosity levels:
        0 - No output
        1 - Only critical success/failure status (default)
        2 - Additional status details for success/failure status, including discarded PEs
        3 - Everything
    File scan mode:
        -f [File or directory to scan]
        -r [Optional. Recursive scan]
        --signed [Optional. Process only signed binaries]
        --delayload [Optional. Include delayload imports in dependency list]
        --explicit-loadlibrary [Optional. Include potentially explicit imports in 
dependency list (these are *.dll strings which may have been called via LoadLibrary(Ex)A/W]
        --auto-elevate [Optional. Scan only auto-elevate binaries]
    Memory scan mode:
        --pid [Target process ID to scan. When not specified, a list of either 32 
or 64-bit process names/PIDs will be enumerated (corresponding to either the 32 
or 64-bit version of this tool)]
    Any scan mode:
        --enum-dependency [Enumerate dependencies]
        --show-unmapped-apiset [Optional. Include API sets which failed to map to 
a module from output (ignored by default)]
        --dll-hijack [Enumerate DLL hijacking vulns]
        --find-module [Optional. Scan dependencies for a specific module. Note that 
this excludes KnownDLLs]
    Infect mode:
        -f [DLL file to infect]
        -o [Output file]
        --payload-path [Path of DLL to be loaded into infected DLL at runtime, 
or path of executable to be launched at runtime]
        --payload-type [The type of payload specified in the parasite payload path. 
This can be "process" (generally indicating a exe) or "library" (generally indicating 
a DLL)]

  ## Examples
  
  1. Scanning the entire home drive for 32-bit programs vulnerable to DLL hijacking 
     using either standard or delay load imports through their PE headers.
  
     Siofra32.exe --mode file-scan -f "C:/" -r --enum-dependency --dll-hijack --delayload
  
  2. Scanning the Windows Defender application folder on an x64 version of Windows 
     for vulnerable modules loaded through the standard import table in their PE header.
  
     Siofra64.exe --mode file-scan -f "C:\Program Files\Windows Defender" -r --enum-dependency 
     --dll-hijack
  
  3. Scanning the 32-bit Java Update Scheduler program on an x64 version of Windows 
     for vulnerable modules loaded through any known channel (standard or delayload imports, 
     WinSxS, LoadLibrary).
  
     Siofra32.exe --mode file-scan -f "C:\Program Files (x86)\Common Files\Java\Java 
     Update\jusched.exe" --enum-dependency --dll-hijack --delayload --explicit-loadlibrary
  
  4. Scanning the Windows folder (and all its subfolders) for vulnerable modules 
     (imported via the standard imports table in the PE header) in 64-bit programs which 
     could be used for a UAC bypass attack (signed by Microsoft with an auto-elevate 
     manifest).
  
     Siofra64.exe --mode file-scan -f "C:\Windows" -r --enum-dependency --dll-hijack 
     --auto-elevate --signed
  
  5. Infecting a 32-bit copy of WININET.dll (copied from \Windows\SysWOW64\WININET.dll 
     to .\WININET_original.dll) with an implant which will launch a new notepad process 
     when loaded during process initialization by a vulnerable program. It's important 
     to note that simply loading an infected copy of this DLL (via LoadLibrary for example) 
     will not trigger the payload. Infected DLLs are only meant to work in the context 
     of a vulnerable module loaded via the standard imports section of its host process.
  
     Siofra32.exe --mode infect -f WININET_original.dll -o WININET.dll --payload-type 
     process --payload-path c:\windows\system32\notepad.exe
  
  6. Infecting a 64-bit copy of USERENV.dll (copied from \Windows\System32\USERENV.dll 
     to .\USERENV_original.dll) with an implant which will load a hypothetical payload 
     DLL stored at C:\Payload.dll. It's important to note that all DLLs loaded by a 64-bit 
     process must be 64-bit DLLs, and all DLLs loaded by a 32-bit process must be 32-bit 
     DLLs. Therefore in this hypothetical scenario, Payload.dll would need to be a 64-bit PE 
     file for it to be loaded successfully by the implant in USERENV.dll.
  
     Siofra64.exe --mode infect -f USERENV_original.dll -o USERENV.dll --payload-type 
     library --payload-path "C:\Payload.dll"
 
# Future improvements

* 32 and 64-bit versions of the tool to be combined into a single executable.
* Capability to perform PE infections which can successfully load DLL/executable 
  payloads within infected DLL files loaded explicitly via LoadLibrary or through 
  delayed imports.
* Support for all API set versions.
  
# Source code

I've decided to make some of this tool open source to help other security 
researchers understand the technical details of this project. Specifically I've 
provided assembler source code for one of the 64-bit implant shellcodes (for 64-bit PE 
DLL infection when specifying a "process" payload type).

Details surrounding other technical aspects of the tool and OS details related
to the Windows loader/search order, UAC, WinSxS etc. can be found within the
PDF for this project.

# License

Siofra is licensed under the GPL 3 license. See LICENSE.MD for details.

# Contact

Forrest Williams - forrest-RE@protonmail.com / forrest.williams@cybereason.com
