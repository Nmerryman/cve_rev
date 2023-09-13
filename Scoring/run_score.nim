import scoring_types
import ../spacy_interface
import ../sbert_interface
import std/[tables, sugar, strutils, json, sequtils, strutils]

const show_progress = true

proc `+=`(a: var float, b: int) = a += float(b)

proc esplit(text: string): seq[string] =
    result = collect:
        for x in text.splitWhitespace:
            x

proc basic_matching(a, b: seq[string]): float =
    for w in a:
        if w in b:
            result += 1

proc basic_matching(a, b: Cve): float =
    var temp_a = collect:
        for x in a.description.split:
            if x.len > 0:
                x
    var temp_b = collect:
        for y in b.description.split:
            if y.len > 0:
                y
    basic_matching(temp_a, temp_b)

proc basic_matching(a: Cve, b: CachedWeakness): float =
    var temp_a = collect:
        for x in a.description.split:
            if x.len > 0:
                x
    
    var temp_b: seq[string]
    for x in b.name.split:
        if x.len > 0:
            temp_b.add(x)
    for x in b.description.split:
        if x.len > 0:
            temp_b.add(x)

    basic_matching(temp_a, temp_b)

proc basic_matching(a: CachedWeakness, b: Capec): float =
    var temp_a: seq[string]
    for x in a.name.splitWhitespace:
        temp_a.add(x)
    for x in a.description.splitWhitespace:
        temp_a.add(x)
    
    var temp_b: seq[string]
    for x in b.name.splitWhitespace:
        temp_b.add(x)

    for x in b.description.splitWhitespace:
        temp_b.add(x)
    
    basic_matching(temp_a, temp_b)

proc basic_matching(a: Cve, b: Capec): float =
    var temp_a: seq[string]
    for x in a.description.splitWhitespace:
        temp_a.add(x)
    
    var temp_b: seq[string]
    for x in b.name.splitWhitespace:
        temp_b.add(x)
    for x in b.description.splitWhitespace:
        temp_b.add(x)
    
    basic_matching(temp_a, temp_b)


proc weighted(text: seq[string], match: CachedWeakness): float =
    ## Basic matching/scoring function that tries to find number of usefull matches.
    ## I should probably move the .toLowerAscii calls to the cache storage instead
    ## 
    # This puts all the words in one sequence
    var prep: seq[string] = collect:
        for b in text:
            let temp = b.replace('-', ' ').replace('_', ' ')
            for c in temp.splitWhitespace:
                c.toLowerAscii

    # I NEED TO LEMMA THE PREP WORDS

    # Scoring impact
    let name_s = 15
    let description_s = 4
    let extended_desc_s = 2
    let con_scope_s = 1
    let con_impact_s = 1
    let con_note_s = 1
    let alt_term_s = 2
    let alt_desc_s = 2
    for a in prep:
        if a in match.name.toLowerAscii:
            # if match.id == "451":
            #     echo a
            result += name_s
        elif a in match.description.toLowerAscii:
            result += description_s
        elif a in match.extended_description.toLowerAscii:
            result += extended_desc_s
        elif a in match.con_scope.join.toLowerAscii:
            result += con_scope_s
        elif a in match.con_impacts.join.toLowerAscii:
            result += con_impact_s
        elif a in match.con_note.toLowerAscii:
            result += con_note_s
        elif a in match.alt_term.join.toLowerAscii:
            result += alt_term_s
        elif a in match.alt_desc.join.toLowerAscii:
            result += alt_desc_s

proc weighted(a, b: CachedWeakness): float =
    var temp: seq[string]
    temp.add(esplit(a.name))
    temp.add(esplit(a.description))
    temp.add(esplit(a.extended_description))
    temp.add(esplit(a.alt_term.join(" ")))
    temp.add(esplit(a.alt_desc.join(" ")))

    weighted(temp, b)



proc input2input*[T, U](a: InputFile[T], b: InputFile[U], matcher: proc(a:T, b: U): float): Output =
    var p_count = 0
    echo "starting"

    for x in a.data:
        var temp: Table[string, float]
        for y in b.data:
            temp[y.name] = matcher(x.value, y.value)
        result[x.name] = temp

        if show_progress:
            p_count += 1
            if p_count mod 20 == 0:
                echo "(", p_count, "): ", x.name

proc input2cache[T](a: InputFile[T], cache_name: string, matcher: proc(a: T, b: CachedWeakness): float): Output =
    let cache = load_cache(cache_name)

    var p_count = 0

    for x in a.data:
        var temp: Table[string, float]
        for n, c in cache:
            temp[n] = matcher(x.value, c)
        result[x.name] = temp
    
        if show_progress:
            p_count += 1
            if p_count mod 20 == 0:
                echo "(", p_count, "): ", x.name

proc cache2input[T](a: InputFile[T], cache_name: string, matcher: proc(a: CachedWeakness, b: T): float): Output =
    let cache = load_cache(cache_name)

    var p_count = 0

    for n, c in cache:
        var temp: Table[string, float]
        for x in a.data:
            temp[x.name] = matcher(c, x.value)
        result[n] = temp
    
        if show_progress:
            p_count += 1
            if p_count mod 20 == 0:
                echo "(", p_count, "): ", n


proc input2input_bert*[T, U](a: InputFile[T], b: InputFile[U], e1: proc(a: T): string, e2: proc(a: U): string): Output =
    var prep_a: seq[string]
    for i in a.data:
        prep_a.add(e1(i.value))

    var prep_b: seq[string]
    for i in b.data:
        prep_b.add(e2(i.value))
    echo "Done with prep"

    var model = sbert_interface.load()
    echo "Loaded"
    var em_a = encode(model, prep_a)
    echo "A encoded"
    var em_b = encode(model, prep_b)
    echo "B encodod"
    var res = fsim(em_a, em_b)
    echo "fsim done"

    for (ad, r) in zip(a.data, res):
        var temp: Table[string, float]
        for (bd, s) in zip(b.data, r):
            temp[bd.name] = s
        result[ad.name] = temp

proc main =
    let cve = parse[InputFile[Cve]]("inputfile[CVE].json")
    let capec = parse[InputFile[Capec]]("inputfile[Capec].json")
    let cwe = parse[InputFile[CachedWeakness]]("inputfile[CachedWeakness].json")

    let c = input2input[Cve, Capec](cve, capec, basic_matching)
    # let c = cache2input[Capec](capec, "cwec.cache", basic_matching)

    save[Output]("score_test(cve2capec[basic]).json", c)


if isMainModule:
    main()
