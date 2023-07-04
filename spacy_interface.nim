import nimpy

type
    Language* = PyObject
    Token* = object
        text*, lemma*, shape*, pos*, tag*: string 
        alpha*, stop*: bool

proc load*: Language =
    let spacy = pyImport("spacy")
    spacy.load("en_core_web_sm")

proc parse*(L: Language, text: string): seq[Token] =
    for a in L.callObject(text):
        result.add(Token(text: a.getAttr("text").to(string), lemma: a.getAttr("lemma_").to(string), shape: a.getAttr("shape_").to(string), pos: a.getAttr("pos_").to(string),
            tag: a.getAttr("tag_").to(string), alpha: a.getAttr("is_alpha").to(bool), stop: a.getAttr("is_stop").to(bool)))

