import parseutils
import reverse_utils
import flatty
import std/[json]

proc insert(d: var DataCollection, v: Cve, w: Cwe) =
    for a in d.data.mitems:
        if a.cve.id == v.id:
            # We may want to check to make sure that no duplicates are put in
            a.cwe.add(w)
            return
    
    # If we're here, we didn't find it in the current list
    d.data.add(Cve2Cwe(cve: v, cwe: @[w]))

proc main = 
    let data = to(parseJson(readFile("site_mappings.json")), DataCollection)
    var fixed: DataCollection
    for a in data.data:
        fixed.insert(a.cve, a.cwe[0])

    writeFile("fixed_site_mappings.json", pretty(%*(fixed)))
    


if isMainModule:
    main()
