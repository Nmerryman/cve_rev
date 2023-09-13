import std/[xmlparser, xmltree, json]
import Scoring/scoring_types

type
    Capec* = object
        id*, name*, description*: string
    Catalog* = object
        entries*: seq[Capec]


proc parse(file: string): Catalog =
    let thing = loadXml(file)
    var parts = thing.findAll("Attack_Patterns")[0]
    for a in parts.findAll("Attack_Pattern"):
        var capec = Capec(id: a.attr("ID"), name: a.attr("Name"))
        capec.description = a.findAll("Description")[0].innerText
        result.entries.add(capec)

proc main =
    let cache = parse("capec_v3.9.xml")
    save("capec_cache.json", cache)
    var input_file: InputFile[Capec]
    for a in cache.entries:
        input_file.data.add(Input[Capec](name: a.id, value: a))
    save("inputfile[Capec].json", input_file)



if isMainModule:
    main()
