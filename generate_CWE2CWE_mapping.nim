import std/[json, tables, random, sequtils, strutils, times]
import reverse_utils

type 
    CweId = string
    Score = int
    Dict = Table
    DistCollection = Dict[CweId, Score]
    Data = Dict[CweId, DistCollection]

proc main =
    let cache = load_cwe_words("")
    var data: Data
    var count = 0
    var start = cpuTime()
    for a, b in cache:
        if count mod 25 == 0:
            echo "(", cpuTime() - start, ") ", count, ": ", a
        count += 1
        var temp: DistCollection
        let query = [b.name, b.description].join(" ")
        for c, d in cache:
            if a != c:
                temp[c] = score(query, d)
        data[a] = temp
        # echo a, ": ", b
    
    writeFile("mapping_out.json", pretty(%*(data)))   
    echo "Done in ", cpuTime() - start, "s."

if isMainModule:
    main()