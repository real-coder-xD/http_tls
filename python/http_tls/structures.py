"""Data structures compatible with requests.structures."""

class CaseInsensitiveDict(dict):
    """A case-insensitive dictionary, identical to requests.structures.CaseInsensitiveDict."""

    def __init__(self, data=None, **kwargs):
        super().__init__()
        if data is not None:
            self.update(data)
        if kwargs:
            self.update(kwargs)

    def __setitem__(self, key, value):
        super().__setitem__(str(key).lower(), (key, value))

    def __getitem__(self, key):
        return super().__getitem__(str(key).lower())[1]

    def __delitem__(self, key):
        super().__delitem__(str(key).lower())

    def __contains__(self, key):
        return super().__contains__(str(key).lower())

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def update(self, *args, **kwargs):
        for k, v in dict(*args, **kwargs).items():
            self[k] = v

    def copy(self):
        return CaseInsensitiveDict(dict(self.items()))

    def items(self):
        return ((orig_key, val) for orig_key, val in super().values())

    def keys(self):
        return (orig_key for orig_key, _ in super().values())

    def values(self):
        return (val for _, val in super().values())

    def __repr__(self):
        return str(dict(self.items()))
