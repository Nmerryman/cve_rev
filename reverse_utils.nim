{.experimental: "codeReordering".}
import std/[httpclient, strutils, json, sets, re, sequtils, strscans, os, parseutils, tables, sugar, algorithm]
import cwe_parse
import flatty

# Types needed for collecting data
type
    CliCve* = object
        base*: string
        num*: int
    Cve* = object
        id*: string
        description*: string
    Cwe* = object
        id*: string
        name*: string
        description*: string
        link*: string
    Cve2Cwe* = object
        cve*: Cve
        cwe*: Cwe
    DataCollection* = object
        data*: seq[Cve2Cwe]
    ChangeQuery* = ref CatchableError
    CachedWeakness* = object
        id*, name*, description*, extended_description*: string
        con_scope*, con_impacts*: seq[string]
        con_note*: string
        alt_term*, alt_desc*: seq[string]
    ExtractedWords* = seq[seq[string]]

# Globals
var DEBUG* = false
var OUTPUT_FILE = "cve_mapping.json"
var SMART = false
var DEBUG_STATE: seq[string]

proc get_cve_info*(cve_val: string): Cve =
    ## Get basic CVE info based on the id
    
    # Load api response
    let client = newHttpClient()
    let response = client.getContent("https://cveawg.mitre.org/api/cve/" & cve_val)
    # debug
    if DEBUG:
        writeFile("cve.html", response)

    # Parse and generate Cve storage object
    let json_obj = parseJson(response)
    return Cve(id: cve_val, description: json_obj["containers"]["cna"]["descriptions"][0]["value"].getStr())

proc extract_keywords*(text: Cve): ExtractedWords =
    ## Remove rarely important words and nouns that usually have nothing to do with the weakness itself
    ## Organized so that runs of big words are kept together
    ## Basically this is a first round of preprocessing
    
    # Some (growing) criteria to check words against
    let blacklist_common = toHashSet(["a", "and", "as", "in", "to", "or", "of", "via", "used", "before",
    "after", "cause", "allows", "do", "when", "the", "has", "been", "which", "that", "from", "an"])
    let whitelist_names = toHashSet(["SQL", "PHP"])
    let remove_chars = {'(', ')', '"', ',', '.'}

    var temp: seq[string]
    var i = 0
    var s_start = true
    var vals = text.description.split(" ").toSeq
    # Double loop so we can nest sequences
    while i < vals.len:
        while i < vals.len:
            # if first char is upper case, (not start of sentence), it's probably a nown we don't want
            if vals[i].len < 1 or vals[i][0].isUpperAscii and not s_start and vals[i] notin whitelist_names:
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

            # Part of running sequence
            temp.add(vals[i])
            i += 1

        i += 1
        if temp.len > 0:
            result.add(temp)
            temp.setLen(0)
    
    return result

proc to_cwe*(cwe: CachedWeakness): Cwe =
    Cwe(id: cwe.id, name: cwe.name, description: cwe.description, link: "https://cwe.mitre.org/data/definitions/" & $cwe.id & ".html")

proc update_data*(cve: Cve, cwe: Cwe) =
    ## Store the decision in a local file but try to be context aware

    # Get global value
    let out_file = OUTPUT_FILE
    if DEBUG:
        echo "OUTPUT_FILE IS -> ", out_file

    # Create file if it doesn't already exist
    var data: DataCollection
    if fileExists(out_file): 
       data = to(parseFile(out_file), DataCollection)
    
    # Add run to collection
    data.data.add(Cve2Cwe(cve: cve, cwe: cwe))
    var temp_out: string

    # Store the data again
    # Use toUgly in the future for speed
    temp_out = pretty(%*(data))
    writeFile(out_file, temp_out )

# proc test_sys =
#     ## Test the system with no user input
#     var cve = "CVE-2010-3257"
#     var desc = get_cve_info(cve)
#     echo desc
#     var parts = desc.extract_keywords
#     for i in 0..parts.high:
#         echo i, ": ", parts[i].join(" ")
#     var genned = gen_query_manual(parts, "0")
#     echo genned
#     var search_res = perform_google_search(genned)
#     for a in search_res:
#         echo a
    
#     # Selecting cwe
#     var chosen_cve = search_res[0]
#     echo "Chosen CWE-", chosen_cve.id, ", saving now."
#     update_data(desc, chosen_cve)
    
proc request_cve_id*(): CliCve =
    echo "What is the CVE number"
    var cid_raw = stdin.readLine()
    return parse_raw_cve(cid_raw)

proc parse_raw_cve*(val: string): CliCve =
    let parts = val.split("-")
    result.base = parts[0..^2].join("-")
    result.num = parseint(parts[^1])

proc format_raw_cve*(val: CliCve): string =
    return val.base & "-" & $val.num    

# proc do_cve(raw_cve: CliCve) =
#     while true:
#         try:
#             var cve = get_cve_info(raw_cve.format_raw_cve)
#             var parts = extract_keywords(cve)

#             var query_prep: string
#             if SMART:
#                 query_prep = smart_query(parts)
#                 echo "Trying: ", query_prep
#             else:
#                 for i in 0..parts.high:
#                     echo i, ": ", parts[i].join(" ")
#                 echo "Number to craft query (space delimited for multiple), c for custom, f to print full description"
#                 var query_opts = stdin.readLine()
#                 if query_opts == "f":
#                     echo cve.description
#                     continue
#                 query_prep = gen_query_manual(parts, query_opts)
#                 echo "Trying: ", query_prep
#             var search_res = perform_google_search(query_prep)

#             var chosen: Cwe
#             if SMART:
#                 chosen = search_res[0]
#             else:
#                 chosen = select_cwe(search_res)

#             update_data(cve, chosen)
#             echo "Saved Cve (", cve.id, ") -> Cwe mapping"
#             break
#         except ChangeQuery as e:
#             echo "debug changing: ", e.msg
#             continue
#         except Exception as e:
#             raise e

proc load_cwe_words*(file_name: string, cache_file="1000.cache"): Table[string, CachedWeakness] =
    ## Load the data for use (takes advantage of caching because parsing the original is a bit slow)
    if not fileExists(cache_file):
        # Generate the data 
        let catalog = parse_catalog(file_name)
        for a in catalog.weaknesses:
            var temp_weakness = CachedWeakness(id: a.id, name: a.name, description: a.description, extended_description: a.extended_description)
            for b in a.consequenses:
                for c in b.impact:
                    temp_weakness.con_impacts.add(c)
                for c in b.scope:
                    temp_weakness.con_scope.add(c)
                if b.note != "":
                    temp_weakness.con_note = b.note
            for b in a.alternative_terms:
                if b.term != "":
                    temp_weakness.alt_term.add(b.term)
                if b.description != "":
                    temp_weakness.alt_desc.add(b.description)
            result[a.id] = temp_weakness
        let flat = toFlatty(result)
        writeFile(cache_file, flat)
    else:
        result = fromFlatty(readFile(cache_file), result.typeof)

proc score*(text: ExtractedWords, match: CachedWeakness): int =
    # This puts all the words in one sequence
    var prep: seq[string] = collect:
        for a in text:
            for b in a:
                let temp = b.replace('-', ' ').replace('_', ' ')
                for c in temp.split(' '):
                    c
    if DEBUG and ("score temp" notin DEBUG_STATE):
        echo prep
        DEBUG_STATE.add("score temp")


    # Scoring impact
    let name_s = 3
    let description_s = 2
    let extended_desc_s = 1
    let con_scope_s = 1
    let con_impact_s = 1
    let con_note_s = 1
    let alt_term_s = 1
    let alt_desc_s = 1
    for a in prep:
        if a in match.name:
            result += name_s
        elif a in match.description:
            result += description_s
        elif a in match.extended_description:
            result += extended_desc_s

proc score_matches*(words: ExtractedWords, cache: Table[string, CachedWeakness]): Table[string, int] =
    for k, v in cache:
        result[k] = score(words, v)

proc score_top_matches*(words: ExtractedWords, cache: Table[string, CachedWeakness], limit=3): seq[(string, int)] =
    result.setLen(limit)
    var vals = score_matches(words, cache)
    for k, v in vals:
        block result_iter:
            for a in result.mitems:
                if v > a[1]:
                    a = (k, v)
                    break result_iter
    
    result = result.sortedByIt(it[1])

proc testing_main() =
    var cache = load_cwe_words("1000.xml")
    var raw_cve = request_cve_id()
    var cve = get_cve_info(raw_cve.format_raw_cve)
    var extracted = extract_keywords(cve)
    for a in score_top_matches(extracted, cache):
        echo "[", a[0], "->", a[1], "]: ", cache[a[0]].name


# proc cve_rev(test=false, debug=false, iterations=1, cve="", autoincrement=false, output="mapping.json", smart=false) =
#     ## test = Perform test run
#     ## debug = Print out debug info and save http results
#     ## iterations = How often to run program. -1 for forever
#     ## cve = Choose cve from cli
#     ## autoincrement = Auto increment the cve value and bypass asking for next
    
#     DEBUG = debug
#     OUTPUT_FILE = output
#     SMART = smart
#     if test:
#         test_sys()
#     else:
#         # Set initial cve
#         var chosen_cve: CliCve
#         if cve == "":
#             chosen_cve = request_cve_id()
#         else:
#             chosen_cve = parse_raw_cve(cve)
#         if iterations == -1:  # Loop forever
#             while true:
#                 do_cve(chosen_cve)
#                 if autoincrement:
#                     chosen_cve.num += 1
#                 else:
#                     chosen_cve = request_cve_id()
#         else:
#             for a in 0 ..< iterations:
#                 do_cve(chosen_cve)
#                 if autoincrement:
#                     chosen_cve.num += 1
#                 else:
#                     chosen_cve = request_cve_id()

# import cligen

# testing_main()

# dispatch cve_rev
