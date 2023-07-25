import flatty
import cwe_parse, reverse_utils, spacy_interface
import std/[tables, strutils, json]

let lang = load()

proc clean(text: string): string =
    for a in lang.parse(text):
        if a.tag in ["DT", "IN"]:
            continue
        elif a.pos == "PRON":
            continue
        result &= " " & a.lemma.toLowerAscii

proc main =
    # Generate the data 
    let file_name = "cwec_v4.12.xml"
    let cache_name = "cwec.cache"
    let catalog = parse_catalog(file_name)
    var cache_data: Cache
    for a in catalog.weaknesses:
        var temp_weakness = CachedWeakness(id: a.id, name: a.name, description: a.description.clean, extended_description: a.extended_description.clean)
        for b in a.related_weaknesses:
            # We are only checking for current view weaknesses (1000)
            if b.view_id == "1000" and b.nature == "ChildOf":
                temp_weakness.child_of.add(b.cwe_id)
        for b in a.consequenses:
            for c in b.impact:
                temp_weakness.con_impacts.add(c.clean)
            for c in b.scope:
                temp_weakness.con_scope.add(c.clean)
            if b.note != "":
                temp_weakness.con_note = b.note.clean
        for b in a.alternative_terms:
            if b.term != "":
                temp_weakness.alt_term.add(b.term.clean)
            if b.description != "":
                temp_weakness.alt_desc.add(b.description.clean)
        cache_data[a.id] = temp_weakness
    let flat = toFlatty(cache_data)
    writeFile(cache_name, flat)

    # Also extract mappings
    var mapping = extract_mapping(catalog)
    writeFile("site_mappings.json", pretty(%*(mapping)))


main()
