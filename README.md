# Goals
My goal of this project is simply to help automate matching any input cve to any cwe. For now we won't do any tree traversal to try to find one that lands in view 699.

# How to use
I have either provided the finished/compiled exe seperately or they are located in the bin folder

## Use
- Run the executable in a command line (recomended).
- Paste in the Cve full cve id such as `CVE-2007-2723` (or pass the id as a command line argument).
- Choose search keywords (numbers delimated by spaces)
- select closest matching Cwe (visible numbers)
- result updates `cve_mapping.json`


## Compilation
The program is in the `.nim` file which is compiled with the [nim programming langage](nim-lang.org). 
I simply used the latest devel version.

Some additional packages/dependencies may be needed, they can simply be added via `nimble install cligen print flatty`

The command to compile is `nim c -d:release file_name.nim` and will produce `file_name.exe`.
To build `manual_reverse`:
- compile `build_cache.nim`
- put 1000.xml next to `build_cache.exe` in the bin folder
- run `build_cache.exe`
- move `1000.cache` next to `reverse_utils.nim`
- compile manual_reverse.nim

## Uploaded files
The exe is the final executable which is what I was working on, the zip file has the github repo that has the source code and (almost) everything needed to compile the program.
