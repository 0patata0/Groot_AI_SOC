"""Conservative launch budget for explicitly reviewed Thor/Spark UMA and cgroups."""
from pathlib import Path


def cgroup_headroom(root=Path('/sys/fs/cgroup')):
    # Docker uses a private cgroup v2 namespace: the container limit is at root.
    maximum, current = root / 'memory.max', root / 'memory.current'
    if not maximum.exists() or not current.exists():
        return None
    text = maximum.read_text().strip()
    return None if text == 'max' else max(0, int(text) - int(current.read_text())) / 2**30


def budget(system_available, cuda_free, cuda_total, platform, capability, cgroup_available=None):
    thor_uma = platform == 'aarch64' and list(capability) == [11, 0]
    spark_uma = platform == 'aarch64' and list(capability) == [12, 1]
    # cudaMemGetInfo on Tegra excludes reclaimable CPU page cache. MemAvailable
    # includes the kernel's reclaim estimate; never equate it to a peak guarantee.
    # NVIDIA Spark UMA guidance: cudaMemGetInfo excludes reclaimable page cache.
    # No swap is added; the host reserve guard and hard cgroup limit still apply.
    # https://nvidia.custhelp.com/app/answers/detail/a_id/5728/
    available = min(system_available, cuda_total if (thor_uma or spark_uma) else cuda_free)
    if cgroup_available is not None:
        available = min(available, cgroup_available)
    return {'available_memory_gib': round(available, 2),
            'system_available_gib':round(system_available, 2),
            'cuda_free_gib':round(cuda_free, 2),
            'cgroup_headroom_gib':None if cgroup_available is None else round(cgroup_available, 2),
            'memory_budget_basis':'thor_uma_memavailable_cgroup' if thor_uma else
                'spark_uma_memavailable_cgroup' if spark_uma else 'minimum_system_cuda_cgroup'}
