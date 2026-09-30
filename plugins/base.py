class Plugin:
    name = "base"
    def analyze(self, ctx, report):
        raise NotImplementedError
