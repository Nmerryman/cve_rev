{.experimental: "codeReordering".}
import std/[httpclient, strutils, json, sets, re, sequtils, strscans, os, parseutils, tables, sugar, algorithm]
import cwe_parse, spacy_interface
import flatty
import print

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
        child_of*: seq[string]
        con_scope*, con_impacts*: seq[string]
        con_note*: string
        alt_term*, alt_desc*: seq[string]
    ExtractedWords* = seq[seq[string]]
    Cache* = Table[string, CachedWeakness]
    CweNode* = ref object
        id*: string
        parents*, children*: seq[CweNode]

# Globals
var OUTPUT_FILE* = "cve_mapping.json"
var DEBUG* = false
var DEBUG_STATE: seq[string]

var spacy_lang: Language
var GENERATED_SPACY_LANG = false

proc get_lang: Language =
    if not GENERATED_SPACY_LANG:
        spacy_lang = load()
    spacy_lang

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

proc extract_keywords_spacy*(text: Cve): string =
    var temp: seq[string]
    let parts = get_lang().parse(text.description)
    var last_is_punct = true
    for a in parts:
        if a.pos == "PUNCT":
            last_is_punct = true
            if DEBUG:
                echo "Removed via PUNCT:   ", a.text
            continue
        if a.pos == "PRON" or a.tag == "DT":
            if DEBUG:
                echo "Removed via PRON:    ", a.text
            continue
        if a.shape == "x" or a.shape == "xx" or "d" in a.shape:
            if DEBUG:
                echo "Removed via shape x: ", a.text
            continue
        if a.shape.len > 2 and (a.shape[0..1] == "Xx"):
            if not last_is_punct:
                if DEBUG:
                    echo "Removed via caps:     ", a.text
                continue

        temp.add(a.lemma.toLowerAscii)
        last_is_punct = false
        echo a
    
    join(temp.deduplicate, " ")

proc extract_keywords*(text: Cve): ExtractedWords =
    ## Remove rarely important words and nouns that usually have nothing to do with the weakness itself
    ## Organized so that runs of big words are kept together
    ## Basically this is a first round of preprocessing

    # Some (growing) criteria to check words against
    let blacklist_common = toHashSet(["a", "and", "as", "in", "to", "or", "of", "via", "used", "before",
    "after", "cause", "allows", "do", "when", "the", "has", "been", "which", "that", "from", "an"])
    let whitelist_names = toHashSet(["SQL", "PHP", "HTTP", "HTTPS"])
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
            temp.add(vals[i].toLowerAscii)
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

proc load_cwe_words*(file_name: string): Table[string, CachedWeakness] =
    ## Load the data for use (takes advantage of caching because parsing the original is a bit slow)
    const cache_file = staticRead("1000.cache")
    result = fromFlatty(cache_file, result.typeof)

proc build_cwe_node*(id: string, cache: Cache, child: CweNode = nil): CweNode =
    result = CweNode(id: id)
    if child != nil:
        result.children.add(child)
    # print(result)
    for a in cache[id].child_of:
        result.parents.add(build_cwe_node(a, cache, result))
    # print result        

proc id_exists(nodes: seq[CweNode], id: string): bool =
    for a in nodes:
        if a.id == id:
            return true

proc contains*(node: CweNode, id: string): bool =
    if node.id == id:
        return true
    for a in node.children:
        if a.contains(id):
            return true
    return false

proc contains_many*(node: CweNode, ids: seq[string]): bool =
    result = true
    for a in ids:
        if a notin node:
            result = false

proc get_contains_many*(node: CweNode, ids: seq[string]): CweNode =
    var amount = 0
    for a in node.children:
        if contains_many(a, ids):
            amount += 1
            result = get_contains_many(a, ids)
    if amount != 1:
        return node

proc get*(node: CweNode, id: string): CweNode =
    if node.id == id:
        return node
    for a in node.children:
        if a.contains(id):
            return a.get(id)
    return nil

proc update_if_possible(root: CweNode, other: CweNode): void =

    # Only need to merge childen
    if root.parents.id_exists(other.id):
        root.children.add(other.children)
    else:
        for a in root.children:
            update_if_possible(a, other)

proc merge_cwe_nodes*(nodes: seq[CweNode]): seq[CweNode] =
    ## Take a sequence of input nodes and fill out the parents and merge into a single tree ending with selected nodes
    # flattens all known nodes
    var flat: seq[CweNode]
    var remaining: seq[CweNode] = nodes
    while remaining.len > 0:
        var temp = remaining.pop()
        remaining.add(temp.parents)
        flat.add(temp)
    # Debug echos
    # echo flat.len
    # for a in flat:
    #     print a.id

    var thing: Table[string, CweNode]
    for a in flat:
        var temp = thing.getOrDefault(a.id)
        # Update temp object
        if temp == nil:
            temp = CweNode(id: a.id)
            thing[a.id] = temp  # We may need to transfer parent/child info
        # Update temp parents and chilren if we have already stored them
        for b in a.parents:
            if not id_exists(temp.parents, b.id) and thing.contains(b.id):
                temp.parents.add(thing[b.id])
                for c in temp.parents:
                    if not id_exists(c.children, temp.id):
                        c.children.add(temp)
        for b in a.children:
            if not id_exists(temp.children, b.id) and thing.contains(b.id):
                temp.children.add(thing[b.id])
                for c in temp.children:
                    if not id_exists(c.parents, temp.id):
                        c.parents.add(temp)
            
    for k, v in thing.pairs:
        if v.parents.len == 0:
            result.add(v)
            

proc score*(text: string, match: CachedWeakness): int =
    score(@[@[text]], match)

proc score*(text: ExtractedWords, match: CachedWeakness): int =
    ## Basic matching/scoring function that tries to find number of usefull matches.
    ## I should probably move the .toLowerAscii calls to the cache storage instead
    ## 
    # This puts all the words in one sequence
    var prep: seq[string] = collect:
        for a in text:
            for b in a:
                let temp = b.replace('-', ' ').replace('_', ' ')
                for c in temp.split(' '):
                    c.toLowerAscii
    if DEBUG and ("score temp" notin DEBUG_STATE):
        echo prep
        DEBUG_STATE.add("score temp")

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

proc score_matches*(words: ExtractedWords, cache: Cache): Table[string, int] =
    for k, v in cache:
        result[k] = score(words, v)

proc score_top_matches*(words: string, cache: Cache, limit=3): seq[(string, int)] =
    score_top_matches(@[@[words]], cache, limit)

proc score_top_matches*(words: ExtractedWords, cache: Cache, limit=3): seq[(string, int)] =
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
    # var cache = load_cwe_words("1000.xml")
    # # var raw_cve = request_cve_id()
    # # var cve = get_cve_info(raw_cve.format_raw_cve)
    # # var extracted = extract_keywords(cve)
    # # for a in score_top_matches(extracted, cache):
    # #     echo "[", a[0], "->", a[1], "]: ", cache[a[0]].name
    # var val = build_cwe_node("360", cache)
    # # print val
    # var temp = @[val, build_cwe_node("354", cache)]
    # for a in merge_cwe_nodes(temp):
    #     print a
    echo extract_keywords_spacy(get_cve_info("CVE-2007-2758"))


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

if isMainModule:
    testing_main()

# dispatch cve_rev
