import std/[json, tables]
import flatty

type 
    Name = string
    Score = float
    Input*[T] = object
        name*: Name
        value*: T
    InputFile*[T] = object
        data*: seq[Input[T]]

    Output* = Table[Name, Table[Name, Score]]

    
        
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
        cwe*: seq[Cwe]
    DataCollection* = object
        data*: seq[Cve2Cwe]

    
    CachedWeakness* = object
        id*, name*, description*, extended_description*: string
        child_of*: seq[string]
        con_scope*, con_impacts*: seq[string]
        con_note*: string
        alt_term*, alt_desc*: seq[string]
    Cache* = Table[string, CachedWeakness]

    Capec* = object
        id*, name*, description*: string


proc parse*[T](name: string): T =
    to(parseJson(readFile(name)), T)

proc save*[T](name: string, data: T) =
    writeFile(name, pretty(%*(data)))

proc load_cache*(file_name: string): Table[string, CachedWeakness] =
    ## Load the data for use (takes advantage of caching because parsing the original is a bit slow)
    ## FIXME this is hardcoded which is probably quite bad lol
    let cache_file = readFile("cwec.cache")
    result = fromFlatty(cache_file, result.typeof)
