from collections import Counter


def word_counts(text: str) -> Counter[str]:
    return Counter(word.strip(".,!?;:").lower() for word in text.split() if word.strip(".,!?;:"))


def describe(value: object) -> str:
    match value:
        case str() if not value:
            return "empty text"
        case str():
            return f"text of {len(value.split())} words"
        case [*items]:
            return f"list of {len(items)} items"
        case _:
            return "something else"
