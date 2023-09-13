import run_score
import scoring_types



proc extract(a: Capec): string =
    a.name & " " & a.description

proc extract(a: Cve): string =
    a.description

proc extract(a: CachedWeakness): string = 
    a.name & " " & a.description

proc test[T, V](a: T, b: V, name: string) =
    echo "Doing: ", name
    save[Output](name, input2input_bert(a, b, extract, extract))

proc gauntlet =
    let a = parse[InputFile[Cve]]("inputfile[CVE].json")
    let b = parse[InputFile[CachedWeakness]]("inputfile[CachedWeakness].json")
    let c = parse[InputFile[Capec]]("inputfile[Capec].json")

    test(a, b, "score_test(cve2cwe[sbert].json")
    test(a, c, "score_test(cve2capec[sbert].json")
    test(a, a, "score_test(cve2cve[sbert].json")
    test(b, c, "score_test(cwe2capec[sbert].json")



proc main =
    let a = parse[InputFile[Cve]]("inputfile[CVE].json")
    let b = parse[InputFile[CachedWeakness]]("inputfile[CachedWeakness].json")
    let c = parse[InputFile[Capec]]("inputfile[Capec].json")

    var r = input2input_bert(a, b, extract, extract)
    save[Output]("capec2capec.json", r)



if isMainModule:
    gauntlet()
