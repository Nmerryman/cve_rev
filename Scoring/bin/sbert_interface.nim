import nimpy

type
    Model = PyObject
    Embeding = PyObject
    EmbedingMulti = PyObject

let ST = pyImport("sentence_transformers")

proc load*: Model =
    ST.SentenceTransformer.callObject("all-MiniLM-L6-v2")

proc encode*(m: Model, text: string): Embeding =
    m.callMethod("encode", text)

proc fsim*(a, b: Embeding): float =
    let sim = ST.util.cos_sim(a, b)
    return sim[0][0].item().to(float)

proc encode*(m: Model, text: seq[string]): EmbedingMulti =
    m.callMethod("encode", text)
   
proc fsim*(a: EmbedingMulti): seq[seq[float]] =
    let sim = ST.util.cos_sim(a, a).tolist()
    return sim.to(seq[seq[float]])
