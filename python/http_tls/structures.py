"""Data structures compatible with requests.structures."""

from typing import Any


class CaseInsensitiveDict(dict):
    """A case-insensitive dictionary, identical to requests.structures.CaseInsensitiveDict."""

    def __init__(self, data: Any = None, **kwargs: Any) -> None:
        super().__init__()
        if data is not None:
            self.update(data)
        if kwargs:
            self.update(kwargs)

    def __setitem__(self, key: Any, value: Any) -> None:
        super().__setitem__(str(key).lower(), (key, value))

    def __getitem__(self, key: Any) -> Any:
        return super().__getitem__(str(key).lower())[1]

    def __delitem__(self, key: Any) -> None:
        super().__delitem__(str(key).lower())

    def __contains__(self, key: Any) -> bool:
        return super().__contains__(str(key).lower())

    def get(self, key: Any, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def update(self, *args: Any, **kwargs: Any) -> None:
        for k, v in dict(*args, **kwargs).items():
            self[k] = v

    def copy(self) -> "CaseInsensitiveDict":
        return CaseInsensitiveDict(dict(self.items()))

    def items(self):
        return {orig_key: val for orig_key, val in super().values()}.items()

    def keys(self):
        return {orig_key: val for orig_key, val in super().values()}.keys()

    def values(self):
        return {orig_key: val for orig_key, val in super().values()}.values()

    def __repr__(self) -> str:
        return str(dict(self.items()))
