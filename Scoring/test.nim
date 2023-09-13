import std/[tables, json]


type
    Output* = Table[string, Table[string, int]]


proc save*[T](name: string, data: T) =
    writeFile(name, pretty(%*(data)))



var c: Output
save[Output]("score_test.json", c)

