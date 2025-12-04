class PluginBase:
    """
    Base class for plugins.
    """
    def __init__(self):
        pass

    def name(self) -> str:
        raise NotImplementedError

    def execute(self, *args, **kwargs):
        raise NotImplementedError
