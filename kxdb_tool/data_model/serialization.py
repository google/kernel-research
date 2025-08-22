from pydantic import TypeAdapter
from typing import TypeVar, Type

T = TypeVar('T')

def to_json(obj: T, indent=None, type_: Type[T] = None) -> str:
  return TypeAdapter(type_ or type(obj)).dump_json(obj, indent=indent, exclude_none=True).decode('utf-8')

def from_json(type_: Type[T], json_str: str) -> T:
  return TypeAdapter(type_).validate_json(json_str)
