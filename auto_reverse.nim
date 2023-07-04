import reverse_utils
import std/[strutils, tables, algorithm]
import cligen
import print

let CACHE = load_cwe_words("1000.cache")

proc smart_query(vals: ExtractedWords): string =
    let high_imp = @["Uhh temp"]
    let med_imp  = @["buffer overflow", "long string"]
    let low_imp  = @["gain privleges"]
    let word_lists = [high_imp, med_imp, low_imp]
    var desperation = 1
    
    var passed: seq[string]
    for a in vals:
        let test = a.join(" ").toLowerAscii
        for b in 0 .. desperation:
            for c in word_lists[b]:
                let loc = test.find(c)
                if loc != -1:
                    passed.add(test)
    return passed.join


proc echo_tree(nodes: seq[CweNode], query: string, offset: int = 0) =
    for a in nodes:
        var score = score(query, CACHE[a.id])
        var score_spacing = "  "
        if score >= 100:
            score_spacing = ""
        elif score < 100 and score >= 10:
            score_spacing = " "
        echo "[s=", score_spacing, score, "] ", "|".repeat(offset), " {", a.id, "}: ", CACHE[a.id].name
        echo_tree a.children, query, offset + 1

proc select_similar_score(scores: seq[(string, int)]): seq[string] =
    const sys = "discrete"
    
    var temp_max = 0
    for a in scores:
        if a[1] > temp_max:
            temp_max = a[1]
    
    if sys == "discrete":
        
        const within = 3  # 2 points
        
        for a in scores:
            if a[1] > temp_max - within:
                result.add(a[0])
    
    elif sys == "percent":

        const within = 0.1  # 10%

        for a in scores:
            if a[1].float > temp_max.float * (1 - within):
                result.add(a[0])

proc echo_scores(data: seq[(string, int)]) =
    for (i, s) in data:
        var spacing = ""
        if i.len < 3:
            spacing = " "
        echo "{", spacing, i, "} [s=", s, "]: ", CACHE[i].name

proc suggest_top*(query: string): seq[(string, int)] =
    ## We should probably do something smarter for when we have multiple final parents after gettin to roots of tree
    ## (id, score)

    var scores = score_top_matches(query, CACHE, 10).reversed()
    echo_scores scores
    
    # We basically have a guarentee that it's already order from large to small
    var top_options = select_similar_score(scores)

    # First we build the tree

    var score_collections: seq[CweNode]
    for a in top_options:
        score_collections.add(build_cwe_node(a, CACHE))
    var merged = merge_cwe_nodes(score_collections)

    echo_tree merged, query

    #  Find best scoring node
    var current_best: CweNode
    for a in merged:
        if a.contains(top_options[0]):
            current_best = a.get(top_options[0])
            break
    # var current_best = merged[0].get(top_options[0])
    var best_seq: seq[string]


    print "considering", top_options
    # print(current_best.id)

    # Add current best to list, check if all top are contained if not go to parent
    while true:
        best_seq.add(current_best.id)
        if current_best.parents.len == 0:
            break

        var working: bool
        for a in top_options:
            working = false
            if a notin current_best:
                current_best = current_best.parents[0]  # I'm assuming first parent will be best
                break
            working = true
        if working:
            break        

    for a in best_seq.reversed():
        result.add((a, score(query, CACHE[a])))

proc test =
    let test_cve = "CVE-2007-2759"
    let query = extract_keywords_spacy(get_cve_info(test_cve))
    echo query
    echo_scores suggest_top("SQL")


test()
