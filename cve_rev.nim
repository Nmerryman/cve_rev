{.experimental: "codeReordering".}
import std/[httpclient, strutils, json, sets, re, sequtils, strscans, os, parseutils, tables, sugar]
import cwe_parse
import flatty

# Types needed for collecting data
type
    Cli_Cve = object
        base: string
        num: int
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
    Cached_weakness = object
        name, description, extended_description: string
        con_scope, con_impacts: seq[string]
        con_note: string
        alt_term, alt_desc: seq[string]


# Globals
var DEBUG = false
var OUTPUT_FILE = "mapping.json"
var SMART = false

proc get_cve_info(cve_val: string): Cve =
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

proc extract_keywords(text: Cve): seq[seq[string]] =
    ## Remove rarely important words and nouns that usually have nothing to do with the weakness itself
    ## Organized so that runs of big words are kept together
    
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

proc gen_query(data: seq[seq[string]], query_opts: string): string =
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

proc perform_search(query: string): seq[Cwe] =
    ## Use the Google search engine on the CWE site to search for our key words

    # This base request simply needs to be updated when the token expires
    # Maybe add a way to set this dynamically from the command line?
    # Maybe I should add headers?
    var base_request = "https://cse.google.com/cse/element/v1?rsz=filtered_cse&num=10&hl=en&source=gcsc&gss=.com&cselibv=ffd60a64b75d4cdb&cx=012899561505164599335%3Atb0er0xsk_o&q=test_asdf&safe=off&cse_tok=AFW0emzSnF4ibAKkW1ENH81HuIh1%3A1686115077002&exp=csqr%2Ccc%2Cbf&oq=test_asdf&gs_l=partner-generic.12...0.0.1.7403.0.0.0.0.0.0.0.0..0.0.csems%2Cnrl%3D10...0.....34.partner-generic..0.0.0.&callback=google.search.cse.api3242"
    var query_prepared = query.replace(' ', '+')
    var raw_request = base_request.replace("test_asdf", query_prepared)
    var client = newHttpClient()
    var response = client.getContent(raw_request)
    # debug
    if DEBUG:
        writeFile("google_response.html", response)

    # Remove all js function calls until we only have a json object
    var start = 0
    var stop = 1
    while response[start] != '{':
        start += 1
    while response[^stop] != '}':
        stop += 1
    var parsed = parseJson(response[start .. ^stop])

    # Iterate the results and store interestin Cwe info
    for a in parsed["results"]:
        var tid, ttitle: string
        if scanf(a["title"].getStr(), "CWE-$+: $+", tid, ttitle):
            var temp: Cwe
            ttitle.removeSuffix(" - CWE")
            ttitle.removeSuffix(" (4.11)")
            temp.name = ttitle
            temp.id = tid
            temp.description = a["contentNoFormatting"].getStr()
            temp.link = a["unescapedUrl"].getStr()
            result.add(temp)
    
    return result

proc select_cwe(opts: seq[Cwe]): Cwe =
    ## Display the sequence of Cwe objects and let the user select one of them

    echo "Select one of the following, c to change query"
    for i in 0 .. opts.high:
        echo i, ": ", opts[i].name
        echo "\t", opts[i].description
    var input = stdin.readLine()
    # By using an exception here we can catch easily catch it outside of this function
    if input == "c":
        raise ChangeQuery()
    return opts[input.parseInt()]

proc update_data(cve: Cve, cwe: Cwe) =
    ## Store the decision in a local file but try to be context aware

    # Get global value
    let out_file = OUTPUT_FILE
    if DEBUG:
        echo "OUTPUT_FILE IS -> ", out_file

    # Create file if it doesn't already exist
    var data: Data_collection
    if fileExists(out_file): 
       data = to(parseFile(out_file), Data_collection)
    
    # Add run to collection
    data.data.add(Cve_to_Cwe(cve: cve, cwe: cwe))
    var temp_out: string

    # Store the data again
    # Use toUgly in the future for speed
    temp_out = pretty(%*(data))
    writeFile(out_file, temp_out )

proc test_sys =
    ## Test the system with no user input
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
    
proc request_cve_id(): Cli_Cve =
    echo "What is the CVE number"
    var cid_raw = stdin.readLine()
    return parse_raw_cve(cid_raw)

proc parse_raw_cve(val: string): Cli_Cve =
    let parts = val.split("-")
    result.base = parts[0..^2].join("-")
    result.num = parseint(parts[^1])

proc format_raw_cve(val: Cli_Cve): string =
    return val.base & "-" & $val.num    

proc next_raw_cve(val: var Cli_Cve): var Cli_Cve =
    result = val
    val.num += 1

proc smart_query(vals: seq[seq[string]]): string =
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
    return passed.join(" ")



proc do_cve(raw_cve: Cli_Cve) =
    while true:
        try:
            var cve = get_cve_info(raw_cve.format_raw_cve)
            var parts = extract_keywords(cve)

            var query_prep: string
            if SMART:
                query_prep = smart_query(parts)
                echo "Trying: ", query_prep
            else:
                for i in 0..parts.high:
                    echo i, ": ", parts[i].join(" ")
                echo "Number to craft query (space delimited for multiple), c for custom, f to print full description"
                var query_opts = stdin.readLine()
                if query_opts == "f":
                    echo cve.description
                    continue
                query_prep = gen_query(parts, query_opts)
                echo "Trying: ", query_prep
            var search_res = perform_search(query_prep)

            var chosen: Cwe
            if SMART:
                chosen = search_res[0]
            else:
                chosen = select_cwe(search_res)

            update_data(cve, chosen)
            echo "Saved Cve (", cve.id, ") -> Cwe mapping"
            break
        except ChangeQuery as e:
            echo "debug changing: ", e.msg
            continue
        except Exception as e:
            raise e

proc load_cwe_words(file_name: string, cache_file="1000.cache"): Table[string, Cached_weakness] =
    # Load the data for use (takes advantage of caching because parsing the original is a bit slow)
    if not fileExists(cache_file):
        # Generate the data 
        let catalog = parse_catalog(file_name)
        for a in catalog.weaknesses:
            var temp_weakness = Cached_weakness(name: a.name, description: a.description, extended_description: a.extended_description)
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


proc score(text: seq[seq[string]], match: Cached_weakness): int =
    # This puts all the words in one sequence
    var prep: seq[string] = collect:
        for a in text:
            for b in a:
                let temp = b.replace('-', ' ').replace('_', ' ')
                for c in temp.split(' '):
                    c

    # Scoring impact
    let name_s = 1
    let description_s = 1
    let extended_desc_s = 1
    let con_scope_s = 1
    let con_impact_s = 1
    let con_note_s = 1
    let alt_term_s = 1
    let alt_desc_s = 1



proc testing_main() =
    discard load_cwe_words("1000.xml")

proc cve_rev(test=false, debug=false, iterations=1, cve="", autoincrement=false, output="mapping.json", smart=false) =
    ## test = Perform test run
    ## debug = Print out debug info and save http results
    ## iterations = How often to run program. -1 for forever
    ## cve = Choose cve from cli
    ## autoincrement = Auto increment the cve value and bypass asking for next
    
    DEBUG = debug
    OUTPUT_FILE = output
    SMART = smart
    if test:
        test_sys()
    else:
        # Set initial cve
        var chosen_cve: Cli_Cve
        if cve == "":
            chosen_cve = request_cve_id()
        else:
            chosen_cve = parse_raw_cve(cve)
        if iterations == -1:  # Loop forever
            while true:
                do_cve(chosen_cve)
                if autoincrement:
                    chosen_cve.num += 1
                else:
                    chosen_cve = request_cve_id()
        else:
            for a in 0 ..< iterations:
                do_cve(chosen_cve)
                if autoincrement:
                    chosen_cve.num += 1
                else:
                    chosen_cve = request_cve_id()

import cligen

testing_main()

# dispatch cve_rev
