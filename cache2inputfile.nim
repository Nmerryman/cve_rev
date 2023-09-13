import Scoring/scoring_types
import std/[tables, json]


proc main = 
    let cache = load_cache("")
    var data: InputFile[CachedWeakness]
    for k, v in cache:
        data.data.add(Input[CachedWeakness](name: k, value: v))
    save("inputfile[CachedWeakness].json", data)


if isMainModule:
    main()
