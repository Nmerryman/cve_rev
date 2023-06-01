import std/[httpclient, strutils, json, sets, re, sequtils, strscans, os]

type
    Cve = object
        id: string
        description: string
    Cwe = object
        id: string
        name: string
        description: string
        link: string
    Cve_to_Cwe = object
        cve: Cve
        cwe: Cwe
    Data_collection = object
        data: seq[Cve_to_Cwe]
    ChangeQuery = ref CatchableError


proc get_cve_info(cve_val: string): Cve =
    let client = newHttpClient()
    let response = client.getContent("https://cveawg.mitre.org/api/cve/" & cve_val)

    let json_obj = parseJson(response)
    return Cve(id: cve_val, description: json_obj["containers"]["cna"]["descriptions"][0]["value"].getStr())

proc extract_keywords(text: Cve): seq[seq[string]] =
    let blacklist_common = toHashSet(["a", "and", "as", "in", "to", "or", "of", "via", "used", "before",
    "after", "cause", "allows", "do", "when", "the", "has", "been", "which", "that", "from", "an"])
    let remove_chars = {'(', ')', '"', ',', '.'}
    var temp: seq[string]
    var i = 0
    var s_start = true
    var vals = text.description.split(" ").toSeq
    while i < vals.len:
        while i < vals.len:
            # if first char is upper case (not start of sentence)
            if vals[i][0].isUpperAscii and not s_start:
                break

            # will next word be a start
            s_start = false
            if vals[i][^1] == '.':
                s_start = true

            # remove surrounding special chars
            if vals[i][0] in remove_chars:
                vals[i] = vals[i][1..vals[i].high]
            if vals[i][^1] in remove_chars:
                vals[i] = vals[i][0..vals[i].high - 1]

            # is ver num
            if match(vals[i], re"^[0-9](\.[0-9]*|x)*$") or match(vals[i], re"\d{2,}"):
                break

            # is common word
            if vals[i] in blacklist_common:
                break

            temp.add(vals[i])
            i += 1

        i += 1
        if temp.len > 0:
            result.add(temp)
            temp.setLen(0)

proc gen_query(data: seq[seq[string]], query_opts: string): string =
    ## Turn cl input into a human query
    var parts = query_opts.split()
    for num_a, a in parts:
        if a == "c":
            result &= parts[num_a + 1 .. parts.high].join(" ")
            break
        result &= data[parseInt(a)].join(" ") & " "
    
    if result[^1] == ' ':
        result.setLen(result.len - 1)

proc perform_search(query: string): seq[Cwe] =
    # This base request simply needs to be updated when the token expires
    var base_request = "https://cse.google.com/cse/element/v1?rsz=filtered_cse&num=10&hl=en&source=gcsc&gss=.com&cselibv=8e77c7877b8339e2&cx=012899561505164599335%3Atb0er0xsk_o&q=test_asdf&safe=off&cse_tok=AFW0emw-cDjP0r_IoYBy22b-oq-s%3A1685565480543&exp=csqr%2Ccc%2Cbf&oq=test_asdf&gs_l=partner-generic.3...856269.858334.4.858558.0.0.0.0.0.0.0.0..0.0.csems%2Cnrl%3D10...0....1.34.partner-generic..0.0.0.&callback=google.search.cse.api6724"
    var query_prepared = query.replace(' ', '+')
    var raw_request = base_request.replace("test_asdf", query_prepared)
    var client = newHttpClient()
    var response = client.getContent(raw_request)

    var start = 0
    var stop = 1
    while response[start] != '{':
        start += 1
    while response[^stop] != '}':
        stop += 1
    var parsed = parseJson(response[start .. ^stop])

    for a in parsed["results"]:
        try:
            var tid, ttitle: string
            if scanf(a["title"].getStr(), "CWE-$+: $+", tid, ttitle):
                var temp: Cwe
                temp.name = ttitle
                temp.id = tid
                temp.description = a["contentNoFormatting"].getStr()
                temp.link = a["unescapedUrl"].getStr()
                result.add(temp)
        except:
            raise getCurrentException()

proc select_cwe(opts: seq[Cwe]): Cwe =
    echo "Select one of the following, c to change query"
    for i in 0 .. opts.high:
        echo i, ": ", opts[i].name
    var input = stdin.readLine()
    if input == "c":
        raise ChangeQuery()
    return opts[input.parseInt()]

proc update_data(cve: Cve, cwe: Cwe) =
    var data: Data_collection
    if fileExists("mapping.json"): 
       data = to(parseFile("mapping.json"), Data_collection)
    
    data.data.add(Cve_to_Cwe(cve: cve, cwe: cwe))
    var temp_out: string
    # Use toUgly in the future for speed
    temp_out = pretty(%*(data))
    writeFile("mapping.json", temp_out )

proc test =
    # Test the system with no user input
    var cve = "CVE-2010-3257"
    var desc = get_cve_info(cve)
    echo desc
    var parts = desc.extract_keywords
    for i in 0..parts.high:
        echo i, ": ", parts[i].join(" ")
    var genned = gen_query(parts, "0")
    echo genned
    var search_res = perform_search(genned)
    for a in search_res:
        echo a
    
    # Selecting cwe
    var chosen_cve = search_res[0]
    echo "Chosen CWE-", chosen_cve.id, ", saving now."
    update_data(desc, chosen_cve)
    

proc main() =
    while true:
        try:
            echo "What is the CVE number"
            var cid_raw = stdin.readLine()
            var cve = get_cve_info(cid_raw)
            var parts = extract_keywords(cve)
            for i in 0..parts.high:
                echo i, ": ", parts[i].join(" ")
            echo "Number to craft query, c for custom"
            var query_opts = stdin.readLine()
            var query_prep = gen_query(parts, query_opts)
            echo "Trying: ", query_prep
            var search_res = perform_search(query_prep)
            var chosen = select_cwe(search_res)
            update_data(cve, chosen)
            echo "Saved Cve -> Cwe mapping"
            break
        except ChangeQuery:
            continue


if isMainModule:
    # main()
    test()
