import json
from rop_chain import *

class RopChainSerializer:
  @staticmethod
  def serialize(rop_chain: RopChain) -> list:
    def serialize_item(item: RopChainItem):
      if isinstance(item, RopChainConstant):
        return {"type": "constant", "value": item.value}
      elif isinstance(item, RopChainOffset):
        return {"type": "offset", "kernel_offset": item.kernel_offset}
      elif isinstance(item, RopChainArgument):
        return {"type": "argument", "argument_index": item.argument_index}

    return list(map(serialize_item, rop_chain.items))

  @staticmethod
  def deserialize(items: list) -> RopChain:
    def deserialize_item(item: dict):
      if item["type"] == "constant":
        return RopChainConstant(item["value"])
      elif item["type"] == "offset":
        return RopChainOffset(item["kernel_offset"])
      elif item["type"] == "argument":
        return RopChainArgument(item["argument_index"])

    return RopChain(list(map(deserialize_item, items)))

class RopActionSerializer:
  @staticmethod
  def serialize(rop_actions: dict) -> str:
    json_obj = {type_id: RopChainSerializer.serialize(rop_chain)
                for (type_id, rop_chain) in rop_actions.items()}
    return json.dumps(json_obj)

  @staticmethod
  def deserialize(json_str: str) -> dict:
    json_obj = json.loads(json_str)
    return {int(type_id): RopChainSerializer.deserialize(items)
            for (type_id, items) in json_obj.items()}
