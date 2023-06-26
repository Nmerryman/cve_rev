import flatty
import cwe_parse, reverse_utils
import std/[tables]

proc main =
    # Generate the data 
    let file_name = "1000.xml"
    let cache_name = "1000.cache"
    let catalog = parse_catalog(file_name)
    var cache_data: Cache
    for a in catalog.weaknesses:
        var temp_weakness = CachedWeakness(id: a.id, name: a.name, description: a.description, extended_description: a.extended_description)
        for b in a.related_weaknesses:
            # We are only checking for current view weaknesses (1000)
            if b.view_id == "1000" and b.nature == "ChildOf":
                temp_weakness.child_of.add(b.cwe_id)
        for b in a.consequenses:
            for c in b.impact:
                temp_weakness.con_impacts.add(c)
            for c in b.scope:
                temp_weakness.con_scope.add(c)
            if b.note != "":
                temp_weakness.con_note = b.note
        for b in a.alternative_terms:
            if b.term != "":
                temp_weakness.alt_term.add(b.term)
            if b.description != "":
                temp_weakness.alt_desc.add(b.description)
        cache_data[a.id] = temp_weakness
    let flat = toFlatty(cache_data)
    writeFile(cache_name, flat)

main()
