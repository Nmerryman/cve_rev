import run_score
import scoring_types
import ../sbert_interface

var model = load()


proc matcher(a, b: CachedWeakness): float =
    var a_en = model.encode(a.name & " " & a.description)
    var b_en = model.encode(b.name & " " & b.description)

    fsim(a_en, b_en)
   


proc main =
    let a = parse[InputFile[CachedWeakness]]("inputfile[CachedWeakness].json")
    let b = parse[InputFile[CachedWeakness]]("inputfile[CachedWeakness].json")
   
    let r = input2input[CachedWeakness, CachedWeakness](a, b, matcher)

    save[Output]("cwe2cwe[sbert].json", r)

if isMainModule:
    main()
