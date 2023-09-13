import spacy_interface, reverse_utils
import std/[tables, json, strutils, sugar, algorithm]


type Collection = Table[string, int]

proc myCmp(a, b: (string, int)): int =
    result = cmp(a[1], b[1])
    if result == 0:
        result = cmp(a[0], b[0])

proc main =
    let cache = load_cwe_words("")
    var counter: Collection
    for _, cwe in cache:
        let temp = [cwe.name, cwe.description, cwe.extended_description, cwe.con_scope.join(" "), cwe.con_impacts.join(" "), cwe.con_note, cwe.alt_desc.join(" "), cwe.alt_term.join(" ")].join(" ")
        for a in temp.split:
            if a.len > 0:
                counter.mgetOrPut(a, 0) += 1
    
    var s = collect:
        for k, v in counter:
            (k, v)
    
    s.sort(myCmp, order=Descending)

    var o: OrderedTable[string, int]
    for (a, b) in s:
        o[a] = b
    
    # let t = %*(counter)
    writeFile("word_counter.json", pretty(%*(o)))


if isMainModule:
    main()

