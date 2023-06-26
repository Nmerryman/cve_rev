import reverse_utils
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
    score_top_matches(ExtractedWords(@[@[query]]), CACHE, 6).reversed()

proc echo(nodes: seq[CweNode], offset: int = 0) =
    for a in nodes:
        echo ">".repeat(offset), " {", a.id, "}: ", CACHE[a.id].name
        echo a.children, offset + 1

proc print_cwe_options(opts: seq[(string, int)]) =

    # let within = 2

    # var top_score = 0
    # for a in opts:
    #     top_score = max(top_score, a[1])
    
    # var score_collections: seq[CweNode]
    # for a in opts:
    #     if top_score - a[1] <= within:
    #         score_collections.add(build_cwe_node(a[0], CACHE))
    # var merged = merge_cwe_nodes(score_collections)

    # echo score_collections
    # echo " -> -> -> "
    # echo merged
    
    echo "Select one of the following, c to change query"
    for i in 0 .. opts.high:
        let weakness = CACHE[opts[i][0]]
        echo i, " [s=", opts[i][1], "]: {", weakness.id, "} ",  weakness.name
        echo "   ", weakness.description

proc select_cwe(opts: seq[(string, int)]): Cwe =
    ## Display the sequence of Cwe objects and let the user select one of them

    print_cwe_options(opts)
    var input = stdin.readLine()
    # By using an exception here we can catch easily catch it outside of this function
    if input == "c":
        raise ChangeQuery()
    return CACHE[opts[input.parseInt()][0]].to_cwe

proc test =
    var cache = load_cwe_words("1000.xml")
    let cve_text = "CVE-2007-2759"
    var cve = get_cve_info(cve_text)
    var chosen = "multiple sql injection vulnerabilities"
    print_cwe_options(perform_cache_search(chosen))

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

        # var cache = load_cwe_words("1000.xml")
        let query_prep = gen_query_manual(parts, query_ops)
        var search_res = perform_cache_search(query_prep)
        try:
            chosen = select_cwe(search_res)
            break
        except ChangeQuery:
            discard
    update_data(cve, chosen)
    echo "Saved Cve (", cve.id, ") -> Cwe mapping"

dispatch manual_reverse
# test()
