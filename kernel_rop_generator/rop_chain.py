class RopChainItem:

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"


class RopChainConstant(RopChainItem):

    def __init__(self, value) -> None:
        self.value = value

    def __repr__(self) -> str:
        return f"RopChainConstant(value={self.value})"


class RopChainOffset(RopChainItem):

    def __init__(self, kernel_offset) -> None:
        self.kernel_offset = kernel_offset

    def __repr__(self) -> str:
        return f"RopChainOffset(kernel_offset={hex(self.kernel_offset)})"


class RopChainArgument(RopChainItem):

    def __init__(self, argument_index) -> None:
        self.argument_index = argument_index

    def __repr__(self) -> str:
        return f"RopChainArgument(argument_index={self.argument_index})"


class RopChain:

    def __init__(self, items) -> None:
        self.items = items

    def __repr__(self) -> str:
        items_str = ", ".join(repr(item) for item in self.items)
        return f"RopChain(items=[{items_str}])"


