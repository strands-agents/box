import json


def slugify(text, sep="-"):
    words = [w for w in text.lower().split() if w.isalnum()]
    return sep.join(words)


def chunk(items, size):
    if size <= 0:
        raise ValueError("size must be positive")
    return [items[i:i + size] for i in range(0, len(items), size)]


def load_config(path, defaults=None):
    with open(path) as f:
        data = json.load(f)
    merged = dict(defaults or {})
    merged.update(data)
    return merged


def mean(values):
    if not values:
        return None
    return sum(values) / len(values)
