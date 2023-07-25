import cligen
import reverse_utils
import std/[os, exitprocs, json]

var output_file: string

proc contains(d: DataCollection, id: string): bool =
    for a in d.data:
        if id == a.cve.id:
            return true
    return false

proc save_file() =
    var new_data: DataCollection
    if fileExists("cve_mapping.json"):
        new_data = to(parseFile("cve_mapping.json"), DataCollection)
    
    removeFile("cve_mapping.json")
    
    var old_data: DataCollection
    if fileExists(output_file):
        old_data = to(parseFile(output_file), DataCollection)
    
    var out_data: DataCollection
    for a in new_data.data:
        if not (a.cve.id in out_data):
            out_data.data.add(a)
    for a in old_data.data:
        if not (a.cve.id in out_data):
            out_data.data.add(a)
    
    writeFile(output_file, pretty(%*(out_data)))
    echo "Saved to file"
    

proc manual_wrapper(start_cve: string, count=1, file="cve_mapping.json") =
    output_file = file
    # addExitProc(save_file)
    var cur_cve = parse_raw_cve(start_cve)
    var acc = 0
    while acc < count:
        discard execShellCmd("manual_reverse.exe " & cur_cve.format_raw_cve)
        cur_cve.num += 1
        acc += 1
        save_file()
    echo "Done wrapping"

dispatch manual_wrapper
