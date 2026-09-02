// AA4: factory entry point. Consumers do:
//     var engine = AntiStealerEngineFactory.Create(new EngineOptions { ... });
// and never have to type-name DefaultEngine directly, so we can swap the
// implementation (multi-process sandbox harness, REST shim, …) without
// breaking the public API surface.

namespace AntiStealer.Engine
{
    public static class AntiStealerEngineFactory
    {
        public static IAntiStealerEngine Create(EngineOptions? options = null)
            => new DefaultEngine(options ?? new EngineOptions());
    }
}
