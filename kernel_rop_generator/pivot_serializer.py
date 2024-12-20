import json
from pivots import *

class PivotSerializer:
    class_mapping = {
        "one_gadgets": OneGadgetPivot,
        "push_indirects": PushIndirectPivot,
        "pop_rsps": PopRspPivot
    }

    class JSONEncoder(json.JSONEncoder):
        def default(self, obj):
            return obj.__dict__

    @staticmethod
    def serialize(pivots, indent=None):
        return json.dumps(pivots, cls=PivotSerializer.JSONEncoder, indent=indent)

    @staticmethod
    def deserialize(json_str):
        root = json.loads(json_str)
        pivots = {}
        for (key, cls) in PivotSerializer.class_mapping.items():
            pivots[key] = [cls(**fields) for fields in root[key]]
        return Pivots(**pivots)
