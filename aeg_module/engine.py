from angr.engines import *


# The default execution engine
# You may remove unused mixins from this default engine to speed up execution
class SmallEngine(
        SimEngineFailure,
        SimEngineSyscall,
        HooksMixin,
        SimEngineUnicorn,
        SuperFastpathMixin,
        TrackActionsMixin,
        SimInspectMixin,
        HeavyResilienceMixin,
        # SootMixin,
        # HeavyVEXMixin
):
    pass


try:
    from .pcode import HeavyPcodeMixin

    class UberEnginePcode(SimEngineFailure, SimEngineSyscall, HooksMixin, HeavyPcodeMixin):  # pylint:disable=abstract-method
        pass
except ImportError:
    pass
