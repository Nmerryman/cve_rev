{.experimental: "codeReordering".}
import std/[xmltree, xmlparser, strtabs, sugar]
import print

type
    Catalog* = object
        weaknesses*: seq[Weakness]
        views*: seq[View]
    Weakness* = object
        id*: string
        name*: string
        abstraction*: string
        description*: string
        extended_description*: string
        related_weaknesses*: seq[Related_weakness]
        consequenses*: seq[Consequence]
        mitigations*: seq[Mitigation]
        observed_examples*: seq[Observed_Example]
        alternative_terms*: seq[Alterantive_Term]
    Related_weakness* = object
        cwe_id*, view_id*: string
    Consequence* = object
        scope*, impact*: seq[string]
        note*: string
    Mitigation* = object
        phase*: seq[string]
        description*: string
    Observed_Example* = object
        reference*, description*, link*: string
    Alterantive_Term* = object
        term*, description*: string
    View* = object
        id*, name*, objective*: string
        members*: seq[Related_weakness]

export Catalog

proc parse_catalog(file_path: string): Catalog =
    let thing = loadXml(file_path)
    let tview = thing.findAll("Views")[0].findAll("View")[0]
    let tvobjective = tview.findAll("Objective")[0]
    let tvmembers = tview.findAll("Members")[0].findAll("Has_Member")

    # We assume there is only one view in the catalog right now
    result.views.add(View(id: tview.attr("ID"), name: tview.attr("Name"), objective: tvobjective.innerText))
    result.views[0].members = collect:
        for a in tvmembers:
            Related_weakness(cwe_id: a.attr("CWE_ID"), view_id: a.attr("View_ID"))

    var weaknesses: seq[Weakness]
    for a in thing.findAll("Weaknesses")[0].findAll("Weakness"):
        var temp = Weakness(id: a.attr("ID"), name: a.attr("Name"), abstraction: a.attr("Abstraction"))
        temp.description = a.findAll("Description")[0].innerText
        if a.findAll("Extended_Description").len > 0:
            temp.extended_description = a.findAll("Extended_Description")[0].innerText

        temp.related_weaknesses = collect:
            for b in a.findAll("Related_Weaknesses"):
                for c in b.findAll("Related_Weakness"):
                    Related_weakness(cwe_id: c.attr("CWE_ID"), view_id: c.attr("View_ID"))

        temp.consequenses = collect:
            for b in a.findAll("Common_Consequences"):
                for c in b.findAll("Consequence"):
                    var temp_con: Consequence
                    temp_con.scope = collect:
                        for d in c.findAll("Scope"):
                            d.innerText
                    temp_con.impact = collect:
                        for d in c.findAll("Impact"):
                            d.innerText
                    let con_note = c.findAll("Note")
                    if con_note.len > 0:
                        temp_con.note = con_note[0].innerText
                    temp_con
        
        temp.mitigations = collect:
            for b in a.findAll("Potential_Mitigations"):
                for c in b.findAll("Mitigation"):
                    var temp_mit: Mitigation
                    temp_mit.phase = collect:
                        for d in c.findAll("Phase"):
                            d.innerText
                    temp_mit.description = c.findAll("Description")[0].innerText
                    temp_mit
        
        temp.observed_examples = collect:
            for b in a.findAll("Observed_Examples"):
                for c in b.findAll("Observed_Example"):
                    var temp_obv: Observed_Example
                    temp_obv.reference = c.findAll("Reference")[0].innerText
                    temp_obv.description = c.findAll("Description")[0].innerText
                    temp_obv.link = c.findAll("Link")[0].innerText
                    temp_obv
        
        temp.alternative_terms = collect:
            for b in a.findAll("Alternate_Terms"):
                for c in b.findAll("Alternate_Term"):
                    var temp_term: Alterantive_Term
                    temp_term.term = c.findAll("Term")[0].innerText
                    if c.findAll("Description").len > 0:
                        temp_term.description = c.findAll("Description")[0].innerText
                    temp_term

        weaknesses.add(temp)

    result.weaknesses = weaknesses

proc find(c: Catalog, id: string): Weakness =
    for a in c.weaknesses:
        if id == a.id:
            return a

proc find(c: Catalog, id: int): Weakness =
    find(c, $id)

proc main =
    let cat = parse_catalog("src/1000.xml")
    print(cat.find(1004))

if isMainModule:
    main()

