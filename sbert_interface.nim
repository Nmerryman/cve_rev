import nimpy

type
    Model = PyObject
    Embeding = PyObject
    EmbedingMulti = distinct PyObject

let ST = pyImport("sentence_transformers")

proc load*: Model =
    ST.SentenceTransformer.callObject("all-MiniLM-L6-v2")

proc encode*(m: Model, text: string): Embeding =
    m.callMethod("encode", text)

proc fsim*(a, b: Embeding): float =
    let sim = ST.util.cos_sim(a, b)
    return sim[0][0].item().to(float)

proc encode*(m: Model, text: seq[string]): EmbedingMulti =
    EmbedingMulti(m.callMethod("encode", text))

proc fsim*(a, b: EmbedingMulti): seq[seq[float]] =
    let ta = PyObject(a)
    let tb = PyObject(b)
    let sim = ST.util.cos_sim(ta, tb).tolist()
    return sim.to(seq[seq[float]])

proc fsim*(a: EmbedingMulti): seq[seq[float]] =
    let ta = PyObject(a)
    let sim = ST.util.cos_sim(ta, ta).tolist()
    return sim.to(seq[seq[float]])
