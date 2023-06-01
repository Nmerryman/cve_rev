# Goals
My goal of this project is simply to help automate matching any input cve to any cwe. For now we won't do any tree traversal to try to find one that lands in view 699.

# How to use
## Compilation
The program is in the `.nim` file which is compiled with the [nim programming langage](nim-lang.org). 
I simply used the latest stable version.

The command to compile is `nim c -d:ssl -d:release .\cve_rev.nim` and will produce `cve_rev.exe`.

## Use
- Run the executable in a command line.
- Paste in the Cve full cve id such as `CVE-2007-2723`.
- Choose search keywords
- select closest matching Cwe
