from __future__ import annotations

import base64
import hashlib
import inspect
import struct
from pathlib import Path
from typing import Any

import numpy as np
from pydantic import BaseModel


class EntityHash(BaseModel):
    hash: int

    @staticmethod
    def FromHex(hexstr: str) -> EntityHash:
        return EntityHash(hash=int(hexstr, 16))

    @staticmethod
    def FromBase64(base64str: str) -> EntityHash:
        return EntityHash.FromBytes(data=base64.b64decode(base64str))

    @staticmethod
    def FromInt(value: int) -> EntityHash:
        return EntityHash(hash=value)

    @staticmethod
    def FromHashlib(hashlib: hashlib) -> EntityHash:
        return EntityHash.FromBytes(data=hashlib.digest())

    @staticmethod
    def FromDiskFile(file_path: Path, hash_algorithm: str) -> EntityHash:
        with open(file_path, "rb") as file:
            # noinspection PyTypeChecker
            digest = hashlib.file_digest(file, hash_algorithm)
        return EntityHash.FromBytes(digest.digest())

    @staticmethod
    def FromBytes(data: bytes) -> EntityHash:
        return EntityHash(hash=int.from_bytes(data, byteorder="big"))

    @property
    def as_hex(self) -> str:
        return hex(self.hash)[2:]

    @property
    def as_base64(self) -> str:
        return base64.b64encode(self.as_bytes).decode("utf-8")

    @property
    def as_int(self) -> int:
        return self.hash

    @property
    def as_bytes(self) -> bytes:
        return self.hash.to_bytes(32, byteorder="big")

    def __str__(self) -> str:
        return self.as_hex


def combine_hashes(hashes: list[EntityHash]) -> EntityHash:
    sha256 = hashlib.sha256()
    for hash in hashes:
        sha256.update(hash.as_bytes)
    return EntityHash.FromBytes(sha256.digest())


def calc_hash(value: Any) -> EntityHash:
    sha256 = hashlib.sha256()
    add_thing_to_hash(sha256, value)
    return EntityHash.FromBytes(sha256.digest())


def calc_inthash(value: Any) -> int:
    sha256 = hashlib.sha256()
    add_thing_to_hash(sha256, value)
    return int.from_bytes(sha256.digest(), byteorder="big")


def add_thing_to_hash(sha256, value: Any):
    if isinstance(value, str):
        sha256.update(value.encode())
    elif isinstance(value, dict):
        key_list = list(value.keys())
        key_list.sort()
        for key in key_list:
            add_thing_to_hash(sha256, key)
            add_thing_to_hash(sha256, value[key])
    elif isinstance(value, set):
        for item in sorted(list(value)):
            add_thing_to_hash(sha256, item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            add_thing_to_hash(sha256, item)
    elif isinstance(value, np.ndarray):
        add_thing_to_hash(sha256, value.tolist())
    elif isinstance(value, float):
        sha256.update(struct.pack("d", value))
    elif isinstance(value, int):
        sha256.update(struct.pack("q", value))
    elif isinstance(value, bytes):
        sha256.update(value)
    elif (
        inspect.ismodule(value)
        or inspect.isclass(value)
        or inspect.ismethod(value)
        or inspect.isfunction(value)
        or inspect.iscode(value)
    ):
        if value.__module__ == "builtins":
            sha256.update(value.__name__.encode())
        else:
            sha256.update(inspect.getsource(value).encode())
    else:
        try:
            sha256.update(value)
        except Exception as e:
            raise ValueError(f"Cannot hash value {value} of type {type(value)}") from e


def make_dict_serializable_in_place(d: dict) -> dict:
    """Turns all numpy arrays in the dictionary into lists"""
    for key in d:
        if isinstance(d[key], dict):
            d[key] = make_dict_serializable_in_place(d[key])
        elif isinstance(d[key], np.ndarray):
            d[key] = d[key].tolist()
    return d


def create_dict_serializable_copy(d: dict) -> dict:
    """Turns all numpy arrays in the dictionary into lists"""
    ans = {}
    for key in d:
        if isinstance(d[key], dict):
            ans[key] = create_dict_serializable_copy(d[key])
        elif isinstance(d[key], np.ndarray):
            ans[key] = d[key].tolist()
        elif isinstance(d[key], list):
            ans[key] = [create_dict_serializable_copy(item) for item in d[key]]
        elif isinstance(d[key], (float, int)):
            ans[key] = d[key]
        else:
            raise ValueError(f"Cannot serialize value {d[key]} of type {type(d[key])}")
    return ans
