import scoring_types


proc gen_from_site =
    let data = parse[DataCollection]("fixed_site_mappings.json")
    var res: InputFile[Cve]
    for a in data.data:
        res.data.add(Input[Cve](name: a.cve.id, value: a.cve))
    save("CVE_inputs.json", res)


proc main =
    gen_from_site()

if isMainModule:
    main()
