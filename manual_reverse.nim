import reverse_utils
import auto_reverse
import std/[strutils, tables, algorithm]
import cligen

let CACHE = load_cwe_words("1000.cache")

proc gen_query_manual(data: ExtractedWords, query_opts: string): string =
    ## Turn input + keyword data into a human query
    
    var parts = query_opts.split()
    for num_a, a in parts:
        # Directly store anything following the 'c' as verbetim
        if a == "c":
            result &= parts[num_a + 1 .. parts.high].join(" ")
            break
        result &= data[parseInt(a)].join(" ") & " "
    
    # Delete a trailing space if it exists
    if result[^1] == ' ':
        result.setLen(result.len - 1)

    return result

proc perform_cache_search(query: string): seq[(string, int)] =
    score_top_matches(query, CACHE, 6).reversed()

proc echo(nodes: seq[CweNode], offset: int = 0) =
    for a in nodes:
        echo "|".repeat(offset), " {", a.id, "}: ", CACHE[a.id].name
        echo a.children, offset + 1

proc echo_tree(nodes: seq[CweNode], query: string, stored: Table[string,int], offset: int = 0) =
    for a in nodes:
        var spacing = ""
        if stored[a.id] < 10:
            spacing = " "
        var score = score(query, CACHE[a.id])
        var score_spacing = "  "
        if score >= 100:
            score_spacing = ""
        elif score < 100 and score >= 10:
            score_spacing = " "
        echo "(", spacing, stored[a.id], ") ", "[s=", score_spacing, score, "] ", "|".repeat(offset), " {", a.id, "}: ", CACHE[a.id].name
        echo_tree a.children, query, stored, offset + 1

proc build_cwe_options(scores: seq[(string, int)]): seq[(int, string, int)] = # (choice_num, id, tabs)
    # First we build the tree

    # (id, choice_num)
    var stored: Table[string, int]

    let within = 2

    var top_score = 0
    for a in scores:
        top_score = max(top_score, a[1])
    
    var score_collections: seq[CweNode]
    for a in scores:
        if top_score - a[1] <= within:
            score_collections.add(build_cwe_node(a[0], CACHE))
    var merged = merge_cwe_nodes(score_collections)

    # echo score_collections
    # echo " -> -> -> "
    echo merged
    var merged_copy = merged
    var temp: seq[CweNode]
    while merged_copy.len > 0:
        for a in merged_copy:
            if a.id notin stored:
                stored[a.id] = stored.len
                temp.add(a.children)
        merged_copy = temp
        temp.setLen(0)
    echo stored


proc print_cwe_options_old(query: string) =
    var opts = perform_cache_search(query)
    discard build_cwe_options(opts)
    
    echo "Select one of the following, c to change query"
    for i in 0 .. opts.high:
        let weakness = CACHE[opts[i][0]]
        echo i, " [s=", opts[i][1], "]: {", weakness.id, "} ",  weakness.name
        echo "   ", weakness.description

proc print_cwe_options(query: string): Table[string, int] =

    var scores = perform_cache_search(query)
    
    # First we build the tree

    # (id, choice_num)
    var stored: Table[string, int]

    let within = 3

    var top_score = 0
    for a in scores:
        top_score = max(top_score, a[1])
    
    var score_collections: seq[CweNode]
    for a in scores:
        if top_score - a[1] <= within:
            score_collections.add(build_cwe_node(a[0], CACHE))
    var merged = merge_cwe_nodes(score_collections)

    # echo score_collections
    # echo " -> -> -> "
    # echo_tree merged, query
    var merged_copy = merged
    var temp: seq[CweNode]
    while merged_copy.len > 0:
        for a in merged_copy:
            if a.id notin stored:
                stored[a.id] = stored.len
                temp.add(a.children)
        merged_copy = temp
        temp.setLen(0)
    echo "(chose), [score], {cwe id}: Title"
    echo_tree merged, query, stored
    # echo stored
    for a in scores:
        if a[0] notin stored:
            stored[a[0]] = stored.len
            var num_spacing = ""
            if stored[a[0]] < 10:
                num_spacing = " "
            var score_spacing = "  "
            if a[1] > 100:
                score_spacing = ""
            elif a[1] >= 9 and a[1] < 100:
                score_spacing = " "

            echo "(", num_spacing, stored[a[0]], ") ", "[s=", score_spacing, a[1], "] {", a[0], "}: ", CACHE[a[0]].name
    
    echo "---"
    echo "Recomended by algorithm (top is best)"
    for id, s in suggest_top(query).items:
        var score_spacing = "  "
        if s > 100:
            score_spacing = ""
        elif s >= 9 and s < 100:
            score_spacing = " "
        echo "(", stored[id], ") ", "[s=", score_spacing, s, "] {", id, "} : ", CACHE[id].name

    return stored

proc new_select_cwe(query: string): Cwe =
    var opts = print_cwe_options(query)
    echo "Choose option:"
    var input = stdin.readLine()
    # By using an exception here we can catch easily catch it outside of this function
    if input == "c":
        raise ChangeQuery()
    
    var val = input.parseInt()
    for k, v in opts:
        if val == v:
            return CACHE[k].to_cwe
        
    # return CACHE[opts[input.parseInt()][0]].to_cwe
            

proc select_cwe(opts: seq[(string, int)]): Cwe =
    ## Display the sequence of Cwe objects and let the user select one of them

    # discard print_cwe_options(opts)
    var input = stdin.readLine()
    # By using an exception here we can catch easily catch it outside of this function
    if input == "c":
        raise ChangeQuery()
    return CACHE[opts[input.parseInt()][0]].to_cwe

proc test =
    var cache = load_cwe_words("1000.xml")
    let cve_text = "CVE-2007-2759"
    var cve = get_cve_info(cve_text)
    var chosen = "multiple target over injection vulnerabilities"
    echo  new_select_cwe(chosen)

proc manual_reverse(c: seq[string]) =
    var cve: Cve
    if c.len == 0:
        var raw = request_cve_id()
        cve = get_cve_info(raw.format_raw_cve)
    else:
        cve = get_cve_info(c[0])
    var parts = extract_keywords(cve)
    
    var chosen: Cwe
    while true:
        for i in 0 .. parts.high:
            echo i, ": ", parts[i].join(" ")
        echo "Select query options, f for full descrition."
        var query_ops: string
        while true:
            query_ops = stdin.readLine()
            if query_ops == "f":
                echo cve.description
            else:
                break

        let query_prep = gen_query_manual(parts, query_ops)
        var search_res = perform_cache_search(query_prep)
        try:
            chosen = new_select_cwe(query_prep)
            break
        except ChangeQuery:
            discard
    update_data(cve, chosen)
    echo "Saved Cve (", cve.id, ") -> Cwe mapping"

dispatch manual_reverse
# test()
