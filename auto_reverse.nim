

proc smart_query(vals: ExtractedWords): string =
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
    return passed.join
