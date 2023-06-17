import reverse_utils
import std/[strutils, tables, algorithm]

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

proc perform_cache_search(query: string, cache: Table[string, CachedWeakness]): seq[(string, int)] =
    score_top_matches(ExtractedWords(@[@[query]]), cache, 6).reversed()

proc select_cwe(opts: seq[(string, int)], cache: Table[string, CachedWeakness]): Cwe =
    ## Display the sequence of Cwe objects and let the user select one of them

    echo "Select one of the following, c to change query"
    for i in 0 .. opts.high:
        let weakness = cache[opts[i][0]]
        echo i, " {s=", opts[i][1], "}: ", weakness.name
        echo "   ", weakness.description
    var input = stdin.readLine()
    # By using an exception here we can catch easily catch it outside of this function
    if input == "c":
        raise ChangeQuery()
    return cache[opts[input.parseInt()][0]].to_cwe

proc main =
    # DEBUG = true
    var raw = request_cve_id()
    var cve = get_cve_info(raw.format_raw_cve)
    # var cve = get_cve_info("CVE-2010-3257")
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

        var cache = load_cwe_words("1000.xml")
        let query_prep = gen_query_manual(parts, query_ops)
        var search_res = perform_cache_search(query_prep, cache)
        try:
            chosen = select_cwe(search_res, cache)
            break
        except ChangeQuery:
            discard
    update_data(cve, chosen)
    echo "Saved Cve (", cve.id, ") -> Cwe mapping"


main()
