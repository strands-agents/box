from textstats import describe, word_counts


def test_word_counts() -> None:
    counts = word_counts("The cat saw the dog. The end!")
    assert counts["the"] == 3
    assert counts["end"] == 1


def test_describe() -> None:
    assert describe("") == "empty text"
    assert describe("two words") == "text of 2 words"
    assert describe([1, 2, 3]) == "list of 3 items"
    assert describe(4) == "something else"
